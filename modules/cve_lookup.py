from core.worker import BaseWorker
"""
modules/cve_lookup.py — CVE lookup and exploit matching for discovered services.
Queries NVD API (no key required) and integrates with searchsploit.
"""
import json
import shutil
import subprocess
import time
from datetime import datetime
from typing import Optional



# ── NVD API endpoint ──────────────────────────────────────────────────────────
_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_RESULTS = 20
_HTTP_TIMEOUT = 10


class _LookupWorker(BaseWorker):
    """Background worker for CVE lookups."""

    def __init__(self, service: str, version: str,
                 on_result=None, on_progress=None, on_error=None):
        super().__init__()
        self._service     = service
        self._version     = version
        self._on_result   = on_result
        self._on_progress = on_progress
        self._on_error    = on_error

    def _safe_emit(self, sig, *a):
        _cb = {
            "result_ready":    self._on_result,
            "lookup_progress": self._on_progress,
            "lookup_error":    self._on_error,
        }.get(sig)
        self._call(_cb, *a)

    def run(self):
        try:
            query = f"{self._service} {self._version}".strip()
            self._safe_emit("lookup_progress", f"[NVD] Querying: {query}")

            nvd_results = self._fetch_nvd(query)
            self._safe_emit("lookup_progress", f"[NVD] Found {len(nvd_results)} CVE(s)")

            ss_results = self._run_searchsploit(query)
            if ss_results:
                self._safe_emit("lookup_progress", 
                    f"[searchsploit] Found {len(ss_results)} exploit(s)"
                )

            combined = nvd_results + ss_results
            self._safe_emit("result_ready", combined)

        except Exception as exc:
            self._safe_emit("lookup_error", f"Lookup failed: {exc}")

    # ── Internal helpers ──────────────────────────────────────────────────

    def _fetch_nvd(self, query: str) -> list:
        """HTTP GET against NVD API; handles 429 rate-limit with one retry."""
        try:
            import urllib.request
            import urllib.parse

            params = urllib.parse.urlencode({
                "keywordSearch": query,
                "resultsPerPage": _NVD_RESULTS,
            })
            url = f"{_NVD_BASE}?{params}"

            req = urllib.request.Request(
                url,
                headers={"User-Agent": "DarkCrackerOPS/2.0"},
            )

            def _do_get():
                with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                    return json.loads(resp.read().decode())

            try:
                data = _do_get()
            except Exception as e:
                # Check for rate limit (HTTP 429)
                if "429" in str(e):
                    self._safe_emit("lookup_progress", "[NVD] Rate-limited, waiting 6s…")
                    time.sleep(6)
                    data = _do_get()
                else:
                    raise

            return self._parse_nvd(data)

        except Exception as exc:
            self._safe_emit("lookup_error", f"NVD API error: {exc}")
            return []

    def _parse_nvd(self, data: dict) -> list:
        """Extract CVE entries from NVD JSON response."""
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")

            # Description — prefer English
            descs = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descs if d.get("lang") == "en"),
                descs[0]["value"] if descs else "No description"
            )

            # CVSS v3 score
            score = 0.0
            severity = "INFO"
            metrics = cve.get("metrics", {})
            cvss3_list = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
            if cvss3_list:
                cvss_data = cvss3_list[0].get("cvssData", {})
                score = float(cvss_data.get("baseScore", 0.0))
                severity = score_to_severity(score)

            # Published date
            published = cve.get("published", "")
            if published:
                try:
                    published = datetime.fromisoformat(
                        published.replace("Z", "+00:00")
                    ).strftime("%Y-%m-%d")
                except ValueError:
                    pass

            # References
            references = [
                ref.get("url", "")
                for ref in cve.get("references", [])[:5]
                if ref.get("url")
            ]

            results.append({
                "source":      "NVD",
                "cve_id":      cve_id,
                "description": description,
                "score":       score,
                "severity":    severity,
                "published":   published,
                "references":  references,
            })

        return results

    def _run_searchsploit(self, query: str) -> list:
        """Run searchsploit if available; parse JSON output for exploits."""
        if not shutil.which("searchsploit"):
            return []
        try:
            proc = subprocess.run(
                ["searchsploit", "--json", query],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if proc.returncode != 0 or not proc.stdout.strip():
                return []
            data = json.loads(proc.stdout)
            results = []
            for entry in data.get("RESULTS_EXPLOIT", []) + data.get("RESULTS_SHELLCODE", []):
                title = entry.get("Title", "Unknown")
                path  = entry.get("Path", "")
                etype = entry.get("Type", "exploit")
                results.append({
                    "source":      "searchsploit",
                    "cve_id":      "N/A",
                    "description": title,
                    "score":       0.0,
                    "severity":    "INFO",
                    "published":   "",
                    "path":        path,
                    "type":        etype,
                    "references":  [],
                })
            return results
        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
            return []


class CVELookup:
    """
    CVE lookup and exploit matching for discovered services.

    Callbacks:
        on_result(list)    — list of CVE/exploit dicts
        on_progress(str)   — status messages during lookup
        on_error(str)      — error messages
    """

    def __init__(self, on_result=None, on_progress=None, on_error=None):
        self._worker: Optional[_LookupWorker] = None
        self._on_result   = on_result
        self._on_progress = on_progress
        self._on_error    = on_error

    # ── Public API ────────────────────────────────────────────────────────────

    def lookup_service(self, service: str, version: str):
        """Look up CVEs for a service + version combo (background thread)."""
        if self._worker and self._worker.is_alive():
            self._worker.stop()
            self._worker.join(2.0)

        self._worker = _LookupWorker(
            service, version,
            on_result=self._on_result,
            on_progress=self._on_progress,
            on_error=self._on_error,
        )
        self._worker.start()

    def lookup_port(self, port: int, service: str):
        """
        Look up CVEs by port number and service name.
        Delegates to lookup_service with port as version context.
        """
        self._safe_emit("lookup_progress", f"[CVE] Looking up port {port}/{service}")
        self.lookup_service(service, str(port))

    def get_metasploit_modules(self, service: str) -> list:
        """
        Query msfconsole for modules related to a service.
        Returns list of module path strings. Timeout: 10s.
        """
        if not shutil.which("msfconsole"):
            return []
        try:
            proc = subprocess.run(
                ["msfconsole", "-q", "-x", f"search {service}; exit"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            modules = []
            for line in proc.stdout.splitlines():
                line = line.strip()
                # Module paths contain '/' and look like: exploit/multi/...
                if "/" in line and any(
                    line.startswith(p)
                    for p in ("exploit/", "auxiliary/", "post/", "payload/", "encoder/")
                ):
                    parts = line.split()
                    if parts:
                        modules.append(parts[0])
            return modules
        except (subprocess.TimeoutExpired, Exception):
            return []

    # ── Internal helpers (exposed for direct calls) ───────────────────────────

    def _fetch_nvd(self, query: str) -> list:
        """HTTP GET against NVD API with 10s timeout."""
        worker = _LookupWorker(query, "")
        return worker._fetch_nvd(query)

    def _run_searchsploit(self, query: str) -> list:
        """Run searchsploit; handles missing tool gracefully."""
        worker = _LookupWorker(query, "")
        return worker._run_searchsploit(query)


# ── Module-level helpers ──────────────────────────────────────────────────────

def score_to_severity(score: float) -> str:
    """
    Map CVSS v3 base score to severity label.

    Thresholds:
        9.0+   → CRITICAL
        7.0+   → HIGH
        4.0+   → MEDIUM
        0.1+   → LOW
        0.0    → INFO
    """
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def score_host(ports: list) -> dict:
    """
    Compute a composite risk score for a host based on its open ports.

    Args:
        ports: list of dicts, each with keys: port, service, version, risk.
               risk is one of CRITICAL / HIGH / MEDIUM / LOW / INFO.

    Returns:
        dict with keys: score(0-100), critical, high, medium, low, grade(A-F).
    """
    _WEIGHTS = {
        "CRITICAL": 25,
        "HIGH":     15,
        "MEDIUM":    7,
        "LOW":       2,
        "INFO":      0,
    }

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    raw = 0
    for p in ports:
        risk = str(p.get("risk", "INFO")).upper()
        raw += _WEIGHTS.get(risk, 0)
        key = risk.lower()
        if key in counts:
            counts[key] += 1

    # Cap at 100
    score = min(raw, 100)

    # Grade buckets
    if score <= 20:
        grade = "A"
    elif score <= 40:
        grade = "B"
    elif score <= 60:
        grade = "C"
    elif score <= 80:
        grade = "D"
    else:
        grade = "F"

    return {
        "score":    score,
        "critical": counts["critical"],
        "high":     counts["high"],
        "medium":   counts["medium"],
        "low":      counts["low"],
        "grade":    grade,
    }
