"""
modules/port_scanner.py — Multi-host nmap port scanner with risk scoring.
DARK CRACKER OPS Generation 2
"""
import subprocess
import tempfile
import os
import re

try:
    import nmap as python_nmap
    HAS_PYTHON_NMAP = True
except ImportError:
    HAS_PYTHON_NMAP = False

from core.worker import BaseWorker
from core.config import get_risk_level

INTENSITY_ARGS: dict = {
    "Fast":   "-T4 --top-ports 100",
    "Normal": "-T4 -p 1-1000 -sV -sC",
    "Full":   "-T4 -p- -sV -sC -O",
}
RISK_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


class PortScanner(BaseWorker):
    """
    Runs nmap against one or more targets, parses results, risk-scores each host.

    Callbacks
    ---------
    on_port(dict)       — called for each open port found
    on_vuln(dict)       — called for each vulnerability detected
    on_log(tag, msg)    — log messages
    on_progress(pct)    — 0-100 progress
    on_finished(bool)   — True on clean completion
    """

    def __init__(
        self,
        targets=None,
        intensity: str = "Normal",
        os_detect: bool = True,
        on_port=None,
        on_vuln=None,
        on_log=None,
        on_progress=None,
        on_finished=None,
    ) -> None:
        super().__init__()
        self.targets     = targets or []
        self.intensity   = intensity if intensity in INTENSITY_ARGS else "Normal"
        self.os_detect   = os_detect
        self.on_port     = on_port     or (lambda p: None)
        self.on_vuln     = on_vuln     or (lambda v: None)
        self.on_log      = on_log      or (lambda t, m: None)
        self.on_progress = on_progress or (lambda pct: None)
        self.on_finished = on_finished or (lambda ok: None)
        # Public attributes — caller can set before start()
        self.target: str = ""
        self.ports: str  = ""

    def run(self) -> None:
        # Support both list-based and single-target modes
        targets = self.targets
        if not targets and self.target:
            targets = [self.target]

        total = len(targets)
        if total == 0:
            self._call(self.on_log, "SCAN", "No targets supplied")
            self._call(self.on_finished, True)
            return

        for idx, target in enumerate(targets):
            if self.is_stopped():
                break
            pct = int((idx / total) * 100)
            self._call(self.on_progress, pct)
            self._call(self.on_log, "SCAN", f"Scanning {target} ({idx + 1}/{total})")
            host_data = self._scan_target(target)
            # Emit per-port callbacks
            for p in host_data.get("ports", []):
                if p.get("state") == "open":
                    p["host"] = host_data.get("ip", target)
                    self._call(self.on_port, p)

        self._call(self.on_progress, 100)
        self._call(self.on_finished, True)

    def _scan_target(self, target: str) -> dict:
        host_data: dict = {
            "ip": target, "hostname": "", "os_guess": "",
            "ports": [], "risk_score": "LOW", "open_count": 0, "scan_args": "",
        }
        nmap_args = INTENSITY_ARGS[self.intensity]
        # Override with custom ports if set
        if self.ports:
            nmap_args = f"-T4 -p {self.ports} -sV"
        if self.os_detect and self.intensity != "Fast":
            nmap_args += " -O"
        host_data["scan_args"] = nmap_args

        if HAS_PYTHON_NMAP:
            host_data = self._scan_with_python_nmap(target, nmap_args, host_data)
        else:
            host_data = self._scan_with_subprocess(target, nmap_args, host_data)

        host_data["risk_score"] = self._score_host(host_data)
        host_data["open_count"] = len([p for p in host_data["ports"] if p["state"] == "open"])
        return host_data

    def _scan_with_python_nmap(self, target: str, args: str, host_data: dict) -> dict:
        try:
            nm = python_nmap.PortScanner()
            nm.scan(hosts=target, arguments=args)
            for host in nm.all_hosts():
                host_data["ip"]       = host
                host_data["hostname"] = nm[host].hostname() or host
                if nm[host].get("osmatch"):
                    best = max(nm[host]["osmatch"], key=lambda x: int(x.get("accuracy", 0)))
                    host_data["os_guess"] = f"{best.get('name','')} ({best.get('accuracy','?')}%)".strip()
                for proto in nm[host].all_protocols():
                    for port in sorted(nm[host][proto].keys()):
                        pi      = nm[host][proto][port]
                        state   = pi.get("state", "")
                        service = pi.get("name", "")
                        version = (
                            f"{pi.get('product','')} {pi.get('version','')} {pi.get('extrainfo','')}".strip()
                        )
                        risk = get_risk_level(port)
                        host_data["ports"].append({
                            "port": port, "protocol": proto, "state": state,
                            "service": service, "version": version,
                            "risk_level": risk, "scripts_output": pi.get("script", {}),
                        })
                        if state == "open":
                            self._call(self.on_log, "PORT",
                                       f"{host}:{port}/{proto}  {service}  {version}  [{risk}]")
        except Exception as exc:
            self._call(self.on_log, "ERR", f"python-nmap error for {target}: {exc}")
        return host_data

    def _scan_with_subprocess(self, target: str, args: str, host_data: dict) -> dict:
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name
        try:
            cmd    = ["nmap"] + args.split() + ["-oX", xml_path, target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode not in (0, 1):
                self._call(self.on_log, "ERR", f"nmap returned {result.returncode}")
                return host_data
            host_data = self._parse_nmap_xml(xml_path, host_data)
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            self._call(self.on_log, "ERR", f"nmap subprocess error: {exc}")
        finally:
            try:
                os.unlink(xml_path)
            except OSError:
                pass
        return host_data

    def _parse_nmap_xml(self, xml_path: str, host_data: dict) -> dict:
        try:
            with open(xml_path, "r", errors="replace") as fh:
                xml = fh.read()
        except OSError:
            return host_data

        m = re.search(r'<address addr="([^"]+)" addrtype="ipv4"', xml)
        if m:
            host_data["ip"] = m.group(1)
        m = re.search(r'<hostname name="([^"]+)"', xml)
        if m:
            host_data["hostname"] = m.group(1)
        m = re.search(r'<osmatch name="([^"]+)" accuracy="(\d+)"', xml)
        if m:
            host_data["os_guess"] = f"{m.group(1)} ({m.group(2)}%)"

        for port_block in re.finditer(
            r'<port protocol="([^"]+)" portid="(\d+)">(.*?)</port>', xml, re.DOTALL
        ):
            proto    = port_block.group(1)
            port_num = int(port_block.group(2))
            block    = port_block.group(3)

            state_m   = re.search(r'<state state="([^"]+)"',   block)
            service_m = re.search(r'<service name="([^"]+)"',  block)
            prod_m    = re.search(r'product="([^"]*)"',         block)
            ver_m     = re.search(r'version="([^"]*)"',         block)
            extra_m   = re.search(r'extrainfo="([^"]*)"',       block)

            state   = state_m.group(1)   if state_m   else ""
            service = service_m.group(1) if service_m else ""
            version = " ".join(filter(None, [
                prod_m.group(1)  if prod_m  else "",
                ver_m.group(1)   if ver_m   else "",
                extra_m.group(1) if extra_m else "",
            ])).strip()
            scripts = {}
            for sm in re.finditer(r'<script id="([^"]+)" output="([^"]*)"', block):
                scripts[sm.group(1)] = sm.group(2)

            risk = get_risk_level(port_num)
            host_data["ports"].append({
                "port": port_num, "protocol": proto, "state": state,
                "service": service, "version": version,
                "risk_level": risk, "scripts_output": scripts,
            })
            if state == "open":
                self._call(self.on_log, "PORT",
                           f"{host_data['ip']}:{port_num}/{proto}  {service}  {version}  [{risk}]")
        return host_data

    def _score_host(self, host_dict: dict) -> str:
        highest = "LOW"
        for port_info in host_dict.get("ports", []):
            if port_info.get("state") != "open":
                continue
            level = port_info.get("risk_level", "INFO")
            if RISK_ORDER.get(level, 0) > RISK_ORDER.get(highest, 0):
                highest = level
            if highest == "CRITICAL":
                break
        return highest
