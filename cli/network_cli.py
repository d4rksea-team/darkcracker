"""
cli/network_cli.py — Post-connection network scanning: host discovery, port scan,
vuln scan, CVE lookup, web scan, SMB enum, default credentials.
"""
import threading
from typing import List, Optional

from cli.display import (
    print_section, print_menu, print_table,
    info, success_msg, warn_msg, error_msg, log as cli_log,
    get_input, ask_yn, wait_enter, get_choice, safe_print, print_progress
)
from cli.colors import cyan, green, red, yellow, dim, gray, bold

_RISK_COLOR = {
    "CRITICAL": red,
    "HIGH":     red,
    "MEDIUM":   yellow,
    "LOW":      green,
    "INFO":     dim,
}

# ── Shared state ───────────────────────────────────────────────────────────────
_hosts: List[dict] = []
_hosts_lock = threading.Lock()


# ── Host discovery ─────────────────────────────────────────────────────────────

def _host_discovery() -> None:
    print_section("HOST DISCOVERY")
    target = get_input("Target subnet (CIDR)", "192.168.1.0/24")
    if not target:
        return

    info(f"Discovering hosts on {cyan(target)}…")
    safe_print()

    stop_event = threading.Event()

    def _on_host(h: dict) -> None:
        with _hosts_lock:
            known = {x.get("ip") for x in _hosts}
            if h.get("ip") not in known:
                _hosts.append(h)
        risk = h.get("risk", "LOW")
        cfn  = _RISK_COLOR.get(risk, dim)
        safe_print(
            f"  {cyan('HOST')}  {h.get('ip','?'):<18}  "
            f"{h.get('mac',''):<20}  "
            f"{h.get('hostname',''):<30}  "
            f"{cfn(risk)}"
        )

    def _on_log(tag: str, msg: str) -> None:
        cli_log(tag, msg)

    def _on_finished(ok: bool) -> None:
        stop_event.set()

    try:
        from modules.network_discovery import NetworkDiscovery
        nd = NetworkDiscovery(
            on_host     = _on_host,
            on_log      = _on_log,
            on_finished = _on_finished,
        )
        nd.target = target
        nd.start()
        try:
            stop_event.wait(timeout=180)
        except KeyboardInterrupt:
            warn_msg("Discovery aborted.")
        nd.stop()
        nd.join(timeout=10)
    except Exception as e:
        error_msg(f"Discovery error: {e}")
        wait_enter()
        return

    safe_print()
    with _hosts_lock:
        count = len(_hosts)
    success_msg(f"Discovery complete — {count} host(s) found.")

    if count and ask_yn("Run port scan on all discovered hosts?"):
        ports = get_input("Ports", "21,22,23,25,53,80,443,445,3306,3389,5900,8080,8443")
        _run_portscan_batch(_hosts, ports)
    else:
        wait_enter()


# ── Port scanning ──────────────────────────────────────────────────────────────

def _port_scan_menu() -> None:
    print_section("PORT SCAN")

    with _hosts_lock:
        hosts = list(_hosts)

    target = ""
    if hosts:
        headers = ["#", "IP", "HOSTNAME", "VENDOR"]
        rows = [[str(i), h.get("ip",""), h.get("hostname",""), h.get("vendor","")] for i, h in enumerate(hosts, 1)]
        print_table(headers, rows)
        safe_print(f"  {cyan(f'[{len(hosts)+1}]')}  Enter IP manually")
        choice = get_choice(len(hosts) + 1, "Target host")
        if not choice or choice == 0:
            return
        if choice <= len(hosts):
            target = hosts[choice - 1].get("ip", "")
        else:
            target = get_input("Target IP or hostname", "")
    else:
        target = get_input("Target IP or hostname", "")

    if not target:
        return

    ports = get_input(
        "Ports",
        "21,22,23,25,53,80,110,139,143,443,445,993,995,1433,3306,3389,5432,5900,8080,8443"
    )
    _run_portscan_single(target, ports)


def _run_portscan_single(target: str, ports: str) -> None:
    info(f"Scanning {cyan(target)} — ports: {dim(ports[:60])}")
    safe_print()

    stop_event = threading.Event()

    def _on_port(p: dict) -> None:
        risk = p.get("risk_level", "INFO")
        cfn  = _RISK_COLOR.get(risk, dim)
        safe_print(
            f"  {cyan('PORT')}  {str(p.get('port','')):<8}  "
            f"{p.get('state',''):<10}  "
            f"{p.get('service',''):<15}  "
            f"{p.get('version',''):<30}  "
            f"{cfn(risk)}"
        )

    def _on_vuln(v: dict) -> None:
        sev = v.get("severity", "LOW")
        cfn = _RISK_COLOR.get(sev, dim)
        safe_print(
            f"  {red('VULN')}  {v.get('cve_id','N/A'):<20}  "
            f"{cfn(sev):<12}  "
            f"{v.get('description','')[:50]}"
        )

    def _on_log(tag: str, msg: str) -> None:
        cli_log(tag, msg)

    def _on_finished_inner() -> None:
        stop_event.set()

    try:
        from modules.port_scanner import PortScanner
        ps = PortScanner(
            on_port = _on_port,
            on_vuln = _on_vuln,
            on_log  = _on_log,
        )
        ps.target    = target
        ps.ports     = ports
        # Try to hook finished if supported
        if hasattr(ps, "on_finished"):
            ps.on_finished = lambda ok: stop_event.set()
        ps.start()
        try:
            stop_event.wait(timeout=600)
        except KeyboardInterrupt:
            warn_msg("Scan aborted.")
        ps.stop()
        ps.join(timeout=10)
    except Exception as e:
        error_msg(f"Port scan error: {e}")
    safe_print()
    success_msg(f"Port scan of {target} complete.")
    wait_enter()


def _run_portscan_batch(hosts: List[dict], ports: str) -> None:
    """Scan all hosts in the list sequentially."""
    ips = [h.get("ip", "") for h in hosts if h.get("ip")]
    info(f"Scanning {len(ips)} host(s)…")
    for ip in ips:
        _run_portscan_single(ip, ports)


def _scan_all_hosts() -> None:
    print_section("SCAN ALL HOSTS")
    with _hosts_lock:
        hosts = list(_hosts)
    if not hosts:
        warn_msg("No hosts in memory — run host discovery first.")
        wait_enter()
        return
    ports = get_input(
        "Ports",
        "21,22,23,25,53,80,443,445,3306,3389,5900,8080,8443"
    )
    _run_portscan_batch(hosts, ports)


# ── Vulnerability scanner ──────────────────────────────────────────────────────

def _vuln_scan() -> None:
    print_section("VULNERABILITY SCAN")
    target = get_input("Target IP", "")
    if not target:
        return
    ports = get_input("Ports to scan", "21,22,80,443,445,3306,3389")

    info(f"Running vulnerability scan on {cyan(target)}…")
    safe_print()

    stop_event = threading.Event()

    def _on_vuln(v: dict) -> None:
        sev = v.get("severity", "LOW")
        cfn = _RISK_COLOR.get(sev, dim)
        safe_print(
            f"  {cfn('●')}  {v.get('cve_id',''):<20}  "
            f"{cfn(sev):<12}  CVSS:{v.get('cvss_score','?')}  "
            f"{v.get('description','')[:50]}"
        )

    def _on_log(tag: str, msg: str) -> None:
        cli_log(tag, msg)

    def _on_progress(pct: int) -> None:
        print_progress(pct, "Vuln scan")

    def _on_finished(ok: bool) -> None:
        stop_event.set()

    try:
        from modules.post_exploit.vuln_scanner import VulnScanner
        vs = VulnScanner(
            on_vuln_found = _on_vuln,
            on_log        = _on_log,
            on_progress   = _on_progress,
            on_finished   = _on_finished,
        )
        vs.target = target
        vs.ports  = ports
        vs.start()
        try:
            stop_event.wait(timeout=300)
        except KeyboardInterrupt:
            warn_msg("Vuln scan aborted.")
        vs.stop()
        vs.join(timeout=10)
    except Exception as e:
        error_msg(f"Vuln scan error: {e}")
    safe_print()
    wait_enter()


# ── CVE Lookup ─────────────────────────────────────────────────────────────────

def _cve_lookup() -> None:
    print_section("CVE LOOKUP")
    query = get_input("CVE ID or keyword (e.g. 'apache 2.4', 'CVE-2021-44228')", "")
    if not query:
        return

    try:
        from modules.cve_lookup import CVELookup
        with __import__("cli.display", fromlist=["Spinner"]).Spinner(f"Querying CVE database…"):
            cl = CVELookup()
            results = cl.search(query)
    except Exception as e:
        error_msg(f"CVE lookup error: {e}")
        wait_enter()
        return

    if not results:
        warn_msg("No CVEs found.")
    else:
        headers = ["CVE ID", "CVSS", "SEVERITY", "DESCRIPTION"]
        rows = []
        for r in results[:20]:
            sev = r.get("severity", "N/A")
            cfn = _RISK_COLOR.get(sev.upper(), dim)
            rows.append([
                r.get("cve_id", ""),
                str(r.get("cvss_score", "")),
                cfn(sev),
                r.get("description", "")[:60],
            ])
        print_table(headers, rows)
        success_msg(f"{len(results)} result(s) found.")
    wait_enter()


# ── Web Scanner ────────────────────────────────────────────────────────────────

def _web_scan() -> None:
    print_section("WEB SCANNER")
    target = get_input("Target URL or IP (e.g. http://192.168.1.1)", "")
    if not target:
        return
    if not target.startswith("http"):
        target = f"http://{target}"

    info(f"Scanning: {cyan(target)}")
    safe_print()

    try:
        from modules.post_exploit.web_scanner import WebScanner

        def _on_result(r: dict) -> None:
            status = r.get("status_code", "")
            safe_print(
                f"  {cyan(str(status)):<8}  "
                f"{r.get('path',''):<40}  "
                f"{dim(r.get('title',''))}"
            )

        def _on_progress(pct: int) -> None:
            print_progress(pct, "Web scan")

        def _on_complete() -> None:
            pass

        def _on_error(e: str) -> None:
            error_msg(e)

        ws = WebScanner(
            on_result   = _on_result,
            on_progress = _on_progress,
            on_complete = _on_complete,
            on_error    = _on_error,
        )
        ws.scan(target)
    except Exception as e:
        error_msg(f"Web scan error: {e}")
    safe_print()
    wait_enter()


# ── SMB Enumeration ────────────────────────────────────────────────────────────

def _smb_enum() -> None:
    print_section("SMB ENUMERATION")
    target = get_input("Target IP", "")
    if not target:
        return
    user = get_input("Username (blank=anonymous)", "")
    pw   = get_input("Password (blank=anonymous)", "")

    info(f"SMB enum on {cyan(target)}…")
    safe_print()

    try:
        import subprocess
        cmd = ["smbclient", "-L", f"//{target}/", "-N"] if not user else \
              ["smbclient", "-L", f"//{target}/", "-U", f"{user}%{pw}"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr
        if output.strip():
            for line in output.splitlines():
                safe_print(f"  {line}")
        else:
            warn_msg("No SMB shares found or host unreachable.")
    except FileNotFoundError:
        warn_msg("smbclient not installed. Install: apt install samba-client")
    except Exception as e:
        error_msg(str(e))
    wait_enter()


# ── Default Credentials ────────────────────────────────────────────────────────

def _default_creds() -> None:
    print_section("DEFAULT CREDENTIALS TEST")
    target  = get_input("Target IP", "")
    service = get_input("Service (ssh/ftp/telnet/http)", "ssh")
    port    = get_input("Port", "22" if service == "ssh" else "21")

    # Common default credentials
    cred_pairs = [
        ("admin", "admin"), ("admin", "password"), ("admin", ""),
        ("root", "root"),   ("root", "toor"),      ("root", ""),
        ("admin", "1234"),  ("user",  "user"),      ("guest", "guest"),
        ("administrator", "administrator"), ("pi", "raspberry"),
    ]

    info(f"Testing {len(cred_pairs)} credential pair(s) on {cyan(target)}:{port} via {cyan(service)}…")
    safe_print()

    found = []

    if service.lower() == "ssh":
        try:
            import paramiko
            for user, pw in cred_pairs:
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(target, port=int(port), username=user, password=pw, timeout=5)
                    client.close()
                    found.append((user, pw))
                    success_msg(f"VALID: {cyan(user)}:{cyan(pw)}")
                except paramiko.AuthenticationException:
                    safe_print(f"  {dim(f'FAIL  {user}:{pw}')}")
                except Exception as e:
                    error_msg(f"Connection error: {e}")
                    break
        except ImportError:
            error_msg("paramiko not installed. Install: pip install paramiko")
    elif service.lower() == "ftp":
        try:
            import ftplib
            for user, pw in cred_pairs:
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(target, int(port), timeout=5)
                    ftp.login(user, pw)
                    ftp.quit()
                    found.append((user, pw))
                    success_msg(f"VALID: {cyan(user)}:{cyan(pw)}")
                except ftplib.error_perm:
                    safe_print(f"  {dim(f'FAIL  {user}:{pw}')}")
                except Exception as e:
                    error_msg(f"Connection error: {e}")
                    break
        except Exception as e:
            error_msg(str(e))
    else:
        warn_msg(f"Default cred test for '{service}' not implemented. Use hydra for other services.")

    safe_print()
    if found:
        success_msg(f"{len(found)} valid credential(s) found!")
    else:
        info("No default credentials accepted.")
    wait_enter()


# ── Top-level Network menu ─────────────────────────────────────────────────────

def network_menu() -> None:
    while True:
        print_menu("NETWORK", [
            "Host Discovery      — ARP/ICMP sweep subnet",
            "Port Scan           — scan specific host",
            "Scan All Hosts      — port scan all discovered hosts",
            "Vulnerability Scan  — NSE + CVE matching",
            "CVE Lookup          — NVD API + searchsploit",
            "Web Scanner         — nikto + gobuster + path probes",
            "SMB Enumeration     — list shares",
            "Default Credentials — test common creds (SSH/FTP)",
        ])
        choice = get_choice(8)
        if choice is None:
            continue
        if choice == 0:
            break
        elif choice == 1:
            _host_discovery()
        elif choice == 2:
            _port_scan_menu()
        elif choice == 3:
            _scan_all_hosts()
        elif choice == 4:
            _vuln_scan()
        elif choice == 5:
            _cve_lookup()
        elif choice == 6:
            _web_scan()
        elif choice == 7:
            _smb_enum()
        elif choice == 8:
            _default_creds()
