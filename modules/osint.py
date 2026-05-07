from core.worker import BaseWorker
"""
modules/osint.py — Passive OSINT reconnaissance.
DNS enumeration, WHOIS, certificate transparency, IP geolocation.
"""
import json
import socket
import subprocess
import urllib.request
import urllib.parse
from typing import Optional



# ── Common subdomains to probe ────────────────────────────────────────────────
_COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "vpn", "admin", "api", "dev",
    "staging", "test", "remote", "ssh", "rdp", "smtp",
    "pop", "imap", "ns1", "ns2", "cdn", "app", "portal",
]

_HTTP_TIMEOUT = 10
_GEO_TIMEOUT  = 5


class _OSINTWorker(BaseWorker):
    """Background worker that runs all OSINT sub-scans sequentially."""

    def __init__(self, target: str, scan_type: str = "full",
                 on_result=None, on_progress=None, on_complete=None, on_error=None):
        super().__init__()
        self._target      = target
        self._scan_type   = scan_type
        self._on_result   = on_result
        self._on_progress = on_progress
        self._on_complete = on_complete
        self._on_error    = on_error

    def run(self):
        target = self._target.strip()
        if not target:
            self._call(self._on_error, "No target specified")
            return

        # Determine if target is IP or domain
        is_ip = self._is_ip(target)
        domain = None if is_ip else target
        ip     = target if is_ip else None

        # Resolve domain → IP if needed
        if domain and not ip:
            try:
                ip = socket.gethostbyname(domain)
                self._call(self._on_progress, f"[DNS] Resolved {domain} → {ip}")
            except socket.gaierror:
                self._call(self._on_progress, f"[WARN] Could not resolve {domain}")

        full_result = {}

        # ── DNS enumeration ───────────────────────────────────────────────
        if self._scan_type in ("full", "dns") and domain:
            self._call(self._on_progress, "[DNS] Enumerating DNS records…")
            dns_data = self._dns_enum(domain)
            full_result["dns"] = dns_data
            self._call(self._on_result, "dns", dns_data)

        # ── WHOIS ─────────────────────────────────────────────────────────
        if self._scan_type in ("full", "whois"):
            self._call(self._on_progress, "[WHOIS] Running whois lookup…")
            whois_data = self._whois_lookup(target)
            full_result["whois"] = whois_data
            self._call(self._on_result, "whois", whois_data)

        # ── Certificate transparency ──────────────────────────────────────
        if self._scan_type in ("full", "cert") and domain:
            self._call(self._on_progress, "[CERT] Querying crt.sh certificate transparency…")
            subdomains = self._cert_transparency(domain)
            full_result["subdomains"] = subdomains
            self._call(self._on_result, "subdomains", {"subdomains": subdomains})

        # ── GeoIP ─────────────────────────────────────────────────────────
        if self._scan_type in ("full", "geoip") and ip:
            self._call(self._on_progress, f"[GEO] Geolocating {ip}…")
            geo_data = self._geoip(ip)
            full_result["geoip"] = geo_data
            self._call(self._on_result, "geoip", geo_data)

        # ── Reverse DNS ───────────────────────────────────────────────────
        if ip:
            rev = self._reverse_dns(ip)
            full_result["reverse_dns"] = rev
            if rev:
                self._call(self._on_progress, f"[RDNS] {ip} → {rev}")

        self._call(self._on_progress, "[OSINT] Scan complete")
        self._call(self._on_complete, full_result)

    # ── Sub-scan methods ──────────────────────────────────────────────────────

    def _dns_enum(self, domain: str) -> dict:
        """
        Resolve A, AAAA, MX, TXT, NS, CNAME, SOA records.
        Also brute-forces common subdomains via socket.
        """
        records = {
            "A": [], "AAAA": [], "MX": [], "TXT": [],
            "NS": [], "CNAME": [], "SOA": [],
            "subdomains_dns": [],
        }

        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]

        for rtype in record_types:
            try:
                proc = subprocess.run(
                    ["dig", "+short", domain, rtype],
                    capture_output=True, text=True, timeout=8,
                )
                if proc.returncode == 0:
                    vals = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
                    records[rtype] = vals
            except (subprocess.TimeoutExpired, FileNotFoundError):
                # Fallback: socket for A record
                if rtype == "A":
                    try:
                        info = socket.getaddrinfo(domain, None, socket.AF_INET)
                        records["A"] = list({i[4][0] for i in info})
                    except socket.gaierror:
                        pass
                elif rtype == "AAAA":
                    try:
                        info = socket.getaddrinfo(domain, None, socket.AF_INET6)
                        records["AAAA"] = list({i[4][0] for i in info})
                    except socket.gaierror:
                        pass

        # Subdomain brute force (up to 20)
        found_subs = []
        for sub in _COMMON_SUBDOMAINS[:20]:
            fqdn = f"{sub}.{domain}"
            try:
                socket.setdefaulttimeout(2)
                socket.gethostbyname(fqdn)
                found_subs.append(fqdn)
            except (socket.gaierror, socket.timeout):
                pass
        socket.setdefaulttimeout(None)
        records["subdomains_dns"] = found_subs

        return records

    def _whois_lookup(self, target: str) -> dict:
        """
        Run whois(1) on the target and parse key fields.
        Falls back to raw output if structured parsing fails.
        """
        result = {
            "registrar":      "",
            "creation_date":  "",
            "expiry_date":    "",
            "name_servers":   [],
            "registrant_org": "",
            "raw":            "",
        }

        try:
            proc = subprocess.run(
                ["whois", target],
                capture_output=True, text=True, timeout=10,
            )
            raw = proc.stdout
            result["raw"] = raw

            for line in raw.splitlines():
                low = line.lower()
                val = line.split(":", 1)[-1].strip() if ":" in line else ""

                if not result["registrar"] and "registrar:" in low:
                    result["registrar"] = val
                elif not result["creation_date"] and any(
                    k in low for k in ("creation date:", "created:", "registered:")
                ):
                    result["creation_date"] = val
                elif not result["expiry_date"] and any(
                    k in low for k in ("expiry date:", "expires:", "expiration date:")
                ):
                    result["expiry_date"] = val
                elif "name server:" in low or "nserver:" in low:
                    if val and val not in result["name_servers"]:
                        result["name_servers"].append(val)
                elif not result["registrant_org"] and any(
                    k in low for k in ("registrant organization:", "org:", "organisation:")
                ):
                    result["registrant_org"] = val

        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            result["raw"] = f"whois unavailable: {exc}"

        return result

    def _cert_transparency(self, domain: str) -> list:
        """
        Query crt.sh for certificate transparency logs.
        Returns a sorted list of unique subdomains.
        """
        url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "DarkCrackerOPS/2.0"},
            )
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                data = json.loads(resp.read().decode())

            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                # name_value may contain newlines with multiple names
                for n in name.splitlines():
                    n = n.strip().lstrip("*.")
                    if n and domain in n:
                        subdomains.add(n.lower())

            return sorted(subdomains)

        except Exception as exc:
            self._call(self._on_progress, f"[CERT] crt.sh error: {exc}")
            return []

    def _geoip(self, ip: str) -> dict:
        """
        Geolocate an IP via ip-api.com (free, no key required).
        Returns country, city, ISP, org, ASN.
        """
        url = (
            f"http://ip-api.com/json/{ip}"
            "?fields=status,country,city,regionName,isp,org,as"
        )
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "DarkCrackerOPS/2.0"},
            )
            with urllib.request.urlopen(req, timeout=_GEO_TIMEOUT) as resp:
                data = json.loads(resp.read().decode())

            if data.get("status") == "success":
                return {
                    "ip":      ip,
                    "country": data.get("country", ""),
                    "region":  data.get("regionName", ""),
                    "city":    data.get("city", ""),
                    "isp":     data.get("isp", ""),
                    "org":     data.get("org", ""),
                    "asn":     data.get("as", ""),
                }
            return {"ip": ip, "error": data.get("message", "API error")}

        except Exception as exc:
            return {"ip": ip, "error": str(exc)}

    def _reverse_dns(self, ip: str) -> str:
        """PTR lookup via socket.gethostbyaddr()."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return ""

    @staticmethod
    def _is_ip(target: str) -> bool:
        """Return True if target looks like an IPv4 or IPv6 address."""
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                socket.inet_pton(family, target)
                return True
            except (socket.error, OSError):
                pass
        return False


class OSINTScanner:
    """
    Passive OSINT reconnaissance module.

    Callbacks:
        on_result(category, data)   — called after each sub-scan
        on_progress(msg)            — status messages
        on_complete(dict)           — full result dict at end of scan
        on_error(msg)               — error messages
    """

    def __init__(self, on_result=None, on_progress=None, on_complete=None, on_error=None):
        self._worker: Optional[_OSINTWorker] = None
        self._on_result   = on_result
        self._on_progress = on_progress
        self._on_complete = on_complete
        self._on_error    = on_error

    def scan(self, target: str, scan_type: str = "full"):
        """
        Run a full (or partial) OSINT scan against target in a background thread.

        scan_type: 'full' | 'dns' | 'whois' | 'cert' | 'geoip'
        """
        self.stop()
        self._worker = _OSINTWorker(
            target, scan_type,
            on_result=self._on_result,
            on_progress=self._on_progress,
            on_complete=self._on_complete,
            on_error=self._on_error,
        )
        self._worker.start()

    def stop(self):
        """Request cancellation of the running scan."""
        if self._worker and self._worker.is_alive():
            self._worker.stop()
            self._worker = None
