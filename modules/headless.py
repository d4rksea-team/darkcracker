"""
modules/headless.py — Headless CLI mode for DARK CRACKER OPS.
Usage: sudo python3 main.py --headless --scan-wifi --iface wlan0
       sudo python3 main.py --headless --config engagement.json --report --format html
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path


# ── Argument parser ───────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    """Parse and return all DARK CRACKER OPS CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="darkcracker",
        description="DARK CRACKER OPS Generation 2 — Headless CLI Mode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 main.py --headless --scan-wifi --iface wlan0\n"
            "  sudo python3 main.py --headless --scan-network --target 192.168.1.0/24\n"
            "  sudo python3 main.py --headless --port-scan --hosts 192.168.1.1,192.168.1.2\n"
            "  sudo python3 main.py --headless --crack --cap capture.cap --wordlist rockyou.txt\n"
            "  sudo python3 main.py --headless --config engagement.json --report --format html\n"
        ),
    )

    # Mode flags
    parser.add_argument(
        "--headless",
        action="store_true",
        default=False,
        help="Run in headless CLI mode (no GUI)",
    )

    # Config
    parser.add_argument(
        "--config",
        metavar="PATH",
        default=None,
        help="Path to engagement JSON config file",
    )

    # WiFi scanning
    parser.add_argument(
        "--scan-wifi",
        action="store_true",
        default=False,
        help="Perform WiFi network scan (requires monitor-mode capable interface)",
    )
    parser.add_argument(
        "--iface",
        metavar="IFACE",
        default="wlan0",
        help="Wireless interface for WiFi operations (default: wlan0)",
    )
    parser.add_argument(
        "--channel",
        metavar="CH",
        type=int,
        default=None,
        help="Lock to a specific WiFi channel (1-14); omit for all-channel hop",
    )

    # Network scanning
    parser.add_argument(
        "--scan-network",
        action="store_true",
        default=False,
        help="Perform ARP network host discovery",
    )
    parser.add_argument(
        "--target",
        metavar="CIDR",
        default=None,
        help="Target CIDR range for network scan (e.g. 192.168.1.0/24)",
    )

    # Port scanning
    parser.add_argument(
        "--port-scan",
        action="store_true",
        default=False,
        help="Perform nmap port scan on specified hosts",
    )
    parser.add_argument(
        "--hosts",
        metavar="IPs",
        default=None,
        help="Comma-separated list of host IPs to port-scan",
    )
    parser.add_argument(
        "--ports",
        metavar="PORTSPEC",
        default="21,22,23,25,53,80,443,445,3306,3389,5900,8080,8443",
        help="Port specification for nmap (default: common ports)",
    )

    # Cracking
    parser.add_argument(
        "--crack",
        action="store_true",
        default=False,
        help="Run aircrack-ng password cracking against a capture file",
    )
    parser.add_argument(
        "--cap",
        metavar="FILE",
        default=None,
        help="Path to .cap / .pcapng capture file for cracking",
    )
    parser.add_argument(
        "--wordlist",
        metavar="FILE",
        default="/usr/share/wordlists/rockyou.txt",
        help="Wordlist file for cracking (default: rockyou.txt)",
    )

    # Reporting
    parser.add_argument(
        "--report",
        action="store_true",
        default=False,
        help="Generate a report after all operations complete",
    )
    parser.add_argument(
        "--format",
        metavar="FORMAT",
        choices=["html", "json", "txt", "pdf"],
        default="html",
        help="Report output format: html, json, txt, pdf (default: html)",
    )
    parser.add_argument(
        "--output",
        metavar="PATH",
        default=None,
        help="Output path for the generated report (default: ~/.darkcracker/reports/)",
    )

    # Integration
    parser.add_argument(
        "--webhook",
        metavar="URL",
        default=None,
        help="HTTP webhook URL to POST results as JSON on completion",
    )

    # Session
    parser.add_argument(
        "--session-name",
        metavar="NAME",
        default=f"headless-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        help="Name for this engagement session",
    )

    # General
    parser.add_argument(
        "--timeout",
        metavar="SECONDS",
        type=int,
        default=300,
        help="Global timeout in seconds for each operation (default: 300)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose / debug output",
    )

    return parser.parse_args()


# ── HeadlessRunner ────────────────────────────────────────────────────────────

class HeadlessRunner:
    """
    Orchestrates headless CLI execution of DARK CRACKER OPS operations.

    Lifecycle:
        runner = HeadlessRunner(args)
        sys.exit(runner.run())
    """

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self._results: dict = {
            "session": args.session_name,
            "started": datetime.now().isoformat(),
            "wifi": [],
            "network": [],
            "ports": [],
            "crack": {},
            "report_path": None,
        }

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self) -> int:
        """
        Execute all requested operations in sequence.
        Returns 0 on success, 1 if any operation encountered an error.
        """
        self._print_banner()
        self._log(f"Session: {self.args.session_name}")
        self._log(f"Timeout per operation: {self.args.timeout}s")

        error_flag = False

        # Load config overlay if provided
        if self.args.config:
            try:
                cfg = self._load_config(self.args.config)
                self._log(f"Loaded config: {self.args.config} ({len(cfg)} keys)")
            except Exception as exc:
                self._log(f"Failed to load config '{self.args.config}': {exc}", level="ERROR")
                error_flag = True

        # WiFi scan
        if self.args.scan_wifi:
            self._log(f"Starting WiFi scan on {self.args.iface} ...")
            try:
                results = self._run_wifi_scan()
                self._results["wifi"] = results
                self._log(f"WiFi scan complete. Found {len(results)} networks.")
                if self.args.verbose:
                    for net in results:
                        self._log(f"  SSID={net.get('ssid', '?')} BSSID={net.get('bssid', '?')} "
                                  f"CH={net.get('channel', '?')} ENC={net.get('encryption', '?')}")
            except Exception as exc:
                self._log(f"WiFi scan error: {exc}", level="ERROR")
                error_flag = True

        # Network scan
        if self.args.scan_network:
            target = self.args.target or "192.168.1.0/24"
            self._log(f"Starting ARP network scan on {target} ...")
            try:
                results = self._run_network_scan()
                self._results["network"] = results
                self._log(f"Network scan complete. Found {len(results)} hosts.")
                if self.args.verbose:
                    for host in results:
                        self._log(f"  IP={host.get('ip', '?')} MAC={host.get('mac', '?')} "
                                  f"VENDOR={host.get('vendor', '?')}")
            except Exception as exc:
                self._log(f"Network scan error: {exc}", level="ERROR")
                error_flag = True

        # Port scan
        if self.args.port_scan:
            if not self.args.hosts:
                self._log("--port-scan requires --hosts; skipping.", level="WARN")
            else:
                hosts = [h.strip() for h in self.args.hosts.split(",") if h.strip()]
                self._log(f"Starting port scan on {len(hosts)} host(s) ...")
                try:
                    results = self._run_port_scan(hosts)
                    self._results["ports"] = results
                    self._log(f"Port scan complete. {len(results)} result record(s).")
                except Exception as exc:
                    self._log(f"Port scan error: {exc}", level="ERROR")
                    error_flag = True

        # Crack
        if self.args.crack:
            if not self.args.cap:
                self._log("--crack requires --cap; skipping.", level="WARN")
            elif not Path(self.args.wordlist).exists():
                self._log(f"Wordlist not found: {self.args.wordlist}", level="WARN")
            else:
                self._log(f"Starting aircrack-ng on {self.args.cap} ...")
                try:
                    result = self._run_crack()
                    self._results["crack"] = result
                    found = result.get("password")
                    if found:
                        self._log(f"Password FOUND: {found}", level="SUCCESS")
                    else:
                        self._log("Password not found in wordlist.")
                except Exception as exc:
                    self._log(f"Crack error: {exc}", level="ERROR")
                    error_flag = True

        # Report
        if self.args.report:
            self._log(f"Generating {self.args.format.upper()} report ...")
            try:
                report_path = self._generate_report(self._results)
                self._results["report_path"] = report_path
                self._log(f"Report saved to: {report_path}")
            except Exception as exc:
                self._log(f"Report generation error: {exc}", level="ERROR")
                error_flag = True

        # Webhook
        if self.args.webhook:
            self._log(f"Posting results to webhook: {self.args.webhook}")
            try:
                self._send_webhook(self.args.webhook, self._results)
                self._log("Webhook POST complete.")
            except Exception as exc:
                self._log(f"Webhook error: {exc}", level="ERROR")
                error_flag = True

        self._results["finished"] = datetime.now().isoformat()
        status = "COMPLETED WITH ERRORS" if error_flag else "COMPLETED OK"
        self._log(f"Run {status}. Session: {self.args.session_name}")

        return 1 if error_flag else 0

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _print_banner(self):
        """Print the DARK CRACKER OPS ASCII logo and version info to stdout."""
        try:
            from assets.branding import ASCII_LOGO, TOOL_NAME, TOOL_VERSION, TEAM_NAME, LICENSE_TEXT
            print("\033[96m", end="")  # cyan
            for line in ASCII_LOGO:
                print(f"  {line}")
            print(f"\n  {TOOL_NAME} v{TOOL_VERSION} — {TEAM_NAME}")
            print(f"  {LICENSE_TEXT}")
            print("\033[0m")           # reset
        except Exception:
            print("=" * 60)
            print("  DARK CRACKER OPS Generation 2 — Headless Mode")
            print("=" * 60)
        print()

    def _log(self, msg: str, level: str = "INFO"):
        """Print a timestamped log line to stdout."""
        ts = datetime.now().strftime("%H:%M:%S")
        level_colors = {
            "INFO":    "\033[0m",
            "SUCCESS": "\033[92m",
            "WARN":    "\033[93m",
            "WARNING": "\033[93m",
            "ERROR":   "\033[91m",
            "DEBUG":   "\033[90m",
        }
        color = level_colors.get(level.upper(), "\033[0m")
        reset = "\033[0m"
        print(f"{color}[{ts}] [{level:7s}] {msg}{reset}")
        sys.stdout.flush()

    def _run_wifi_scan(self) -> list:
        """
        Run airodump-ng for --timeout seconds on self.args.iface and parse results.
        Returns list of dicts: {ssid, bssid, channel, encryption, signal, beacons}.
        """
        iface = self.args.iface
        timeout = min(self.args.timeout, 30)   # cap WiFi scan at 30s for headless

        # Build airodump-ng CSV command
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_prefix = os.path.join(tmpdir, "scan")
            cmd = [
                "airodump-ng",
                "--output-format", "csv",
                "--write", csv_prefix,
                "--write-interval", "5",
            ]
            if self.args.channel:
                cmd += ["--channel", str(self.args.channel)]
            cmd.append(iface)

            if self.args.verbose:
                self._log(f"CMD: {' '.join(cmd)}", level="DEBUG")

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                import time
                time.sleep(timeout)
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
            except FileNotFoundError:
                self._log("airodump-ng not found; returning empty WiFi results.", level="WARN")
                return []

            # Parse CSV output
            csv_file = csv_prefix + "-01.csv"
            return self._parse_airodump_csv(csv_file)

    def _parse_airodump_csv(self, csv_path: str) -> list:
        """Parse airodump-ng CSV output into a list of network dicts."""
        networks = []
        if not os.path.exists(csv_path):
            return networks
        try:
            with open(csv_path, "r", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            return networks

        in_ap_section = True
        for line in lines:
            line = line.strip()
            if not line:
                # The blank line separates AP section from client section
                in_ap_section = False
                continue
            if line.startswith("BSSID") or line.startswith("Station MAC"):
                continue
            if not in_ap_section:
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 14:
                continue
            bssid = parts[0]
            if not bssid or len(bssid) < 17:
                continue
            try:
                channel = int(parts[3]) if parts[3].lstrip("-").isdigit() else 0
                signal  = int(parts[8]) if parts[8].lstrip("-").isdigit() else 0
                beacons = int(parts[9]) if parts[9].isdigit() else 0
            except (ValueError, IndexError):
                channel, signal, beacons = 0, 0, 0
            enc   = parts[5] if len(parts) > 5 else "?"
            ssid  = parts[13] if len(parts) > 13 else ""
            networks.append({
                "bssid":      bssid,
                "ssid":       ssid,
                "channel":    channel,
                "signal":     signal,
                "encryption": enc,
                "beacons":    beacons,
            })
        return networks

    def _run_network_scan(self) -> list:
        """
        Run arp-scan on target CIDR and return list of host dicts.
        Dict keys: ip, mac, vendor.
        """
        target = self.args.target or "192.168.1.0/24"
        cmd = ["arp-scan", "--localnet", target]
        if self.args.verbose:
            self._log(f"CMD: {' '.join(cmd)}", level="DEBUG")

        hosts = []
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.args.timeout,
            )
        except FileNotFoundError:
            self._log("arp-scan not found; returning empty network results.", level="WARN")
            return hosts
        except subprocess.TimeoutExpired:
            self._log("arp-scan timed out.", level="WARN")
            return hosts

        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 3:
                ip     = parts[0].strip()
                mac    = parts[1].strip()
                vendor = parts[2].strip()
                # Validate IP-ish
                if ip.count(".") == 3:
                    hosts.append({"ip": ip, "mac": mac, "vendor": vendor})
        return hosts

    def _run_port_scan(self, hosts: list) -> list:
        """
        Run nmap on the provided host list.
        Returns list of dicts: {host, port, protocol, state, service, version}.
        """
        ports_arg = self.args.ports or "21,22,23,25,53,80,443,445,3306,3389,5900,8080,8443"
        cmd = [
            "nmap",
            "-sV", "-O", "--open", "-T4",
            "-p", ports_arg,
            "-oX", "-",   # XML output to stdout for parsing
        ] + hosts

        if self.args.verbose:
            self._log(f"CMD: {' '.join(cmd)}", level="DEBUG")

        results = []
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.args.timeout,
            )
            xml_output = proc.stdout
        except FileNotFoundError:
            self._log("nmap not found; returning empty port scan results.", level="WARN")
            return results
        except subprocess.TimeoutExpired:
            self._log("nmap timed out.", level="WARN")
            return results

        # Parse nmap XML
        results = self._parse_nmap_xml(xml_output)
        return results

    def _parse_nmap_xml(self, xml_text: str) -> list:
        """Parse nmap XML output into a list of port result dicts."""
        results = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_text)
        except Exception:
            return results

        for host_el in root.findall("host"):
            # Get address
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host_el.find("address")
            host_ip = addr_el.attrib.get("addr", "?") if addr_el is not None else "?"

            ports_el = host_el.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                state_el   = port_el.find("state")
                service_el = port_el.find("service")
                state   = state_el.attrib.get("state", "?") if state_el is not None else "?"
                if state != "open":
                    continue
                service = service_el.attrib.get("name", "?") if service_el is not None else "?"
                version = ""
                if service_el is not None:
                    version = " ".join(filter(None, [
                        service_el.attrib.get("product", ""),
                        service_el.attrib.get("version", ""),
                    ]))
                results.append({
                    "host":     host_ip,
                    "port":     int(port_el.attrib.get("portid", 0)),
                    "protocol": port_el.attrib.get("protocol", "tcp"),
                    "state":    state,
                    "service":  service,
                    "version":  version,
                })
        return results

    def _run_crack(self) -> dict:
        """
        Run aircrack-ng against self.args.cap with self.args.wordlist.
        Returns dict: {password, key_found, elapsed}.
        """
        import time
        cmd = [
            "aircrack-ng",
            "-w", self.args.wordlist,
            self.args.cap,
        ]
        if self.args.verbose:
            self._log(f"CMD: {' '.join(cmd)}", level="DEBUG")

        t_start = time.time()
        result  = {"password": None, "key_found": False, "elapsed": 0.0}
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.args.timeout,
            )
            elapsed = time.time() - t_start
            result["elapsed"] = round(elapsed, 2)
            output = proc.stdout + proc.stderr
            # Parse aircrack-ng output for "KEY FOUND! [ password ]"
            for line in output.splitlines():
                if "KEY FOUND" in line:
                    result["key_found"] = True
                    start = line.find("[")
                    end   = line.find("]", start)
                    if start != -1 and end != -1:
                        result["password"] = line[start + 1:end].strip()
                    break
        except FileNotFoundError:
            self._log("aircrack-ng not found.", level="WARN")
        except subprocess.TimeoutExpired:
            result["elapsed"] = float(self.args.timeout)
            self._log("aircrack-ng timed out.", level="WARN")
        return result

    def _generate_report(self, data: dict) -> str:
        """
        Import modules.report_generator.ReportGenerator and generate a report.
        Returns the path to the generated report file.
        """
        try:
            from modules.report_generator import ReportGenerator
        except ImportError as exc:
            self._log(f"ReportGenerator not available: {exc}", level="WARN")
            # Fallback: write raw JSON
            from core.config import REPORTS_DIR, ensure_dirs
            ensure_dirs()
            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = self.args.output or str(REPORTS_DIR / f"report_{ts}.json")
            with open(path, "w") as fh:
                json.dump(data, fh, indent=2, default=str)
            return path

        rg     = ReportGenerator()
        fmt    = self.args.format.lower()
        ts     = datetime.now().strftime("%Y%m%d_%H%M%S")

        from core.config import REPORTS_DIR, ensure_dirs
        ensure_dirs()
        ext_map = {"html": "html", "json": "json", "txt": "txt", "pdf": "pdf"}
        ext     = ext_map.get(fmt, "html")
        path    = self.args.output or str(REPORTS_DIR / f"report_{ts}.{ext}")

        try:
            rg.generate(data=data, fmt=fmt, output_path=path)
        except Exception as exc:
            # Try a generic generate call with positional args
            self._log(f"ReportGenerator.generate() error: {exc}", level="WARN")
            with open(path, "w") as fh:
                json.dump(data, fh, indent=2, default=str)
        return path

    def _send_webhook(self, url: str, data: dict):
        """HTTP POST results as JSON to the given webhook URL."""
        try:
            import requests
            resp = requests.post(
                url,
                json=data,
                timeout=15,
                headers={"Content-Type": "application/json", "User-Agent": "DarkCracker/2.0"},
            )
            if not resp.ok:
                self._log(f"Webhook returned HTTP {resp.status_code}", level="WARN")
        except ImportError:
            # Fall back to urllib
            import urllib.request
            payload = json.dumps(data, default=str).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                pass  # fire-and-forget

    def _load_config(self, path: str) -> dict:
        """Load an engagement JSON config file and return its contents as a dict."""
        with open(path, "r") as fh:
            cfg = json.load(fh)
        if not isinstance(cfg, dict):
            raise ValueError(f"Config file must contain a JSON object, got {type(cfg).__name__}")
        return cfg


# ── Public entry point ─────────────────────────────────────────────────────────

def run_headless(args: argparse.Namespace) -> int:
    """Create a HeadlessRunner and execute the full run cycle."""
    return HeadlessRunner(args).run()
