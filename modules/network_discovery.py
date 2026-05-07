"""
modules/network_discovery.py — Layer-2/3 host discovery for the local subnet.
DARK CRACKER OPS Generation 2

Uses arp-scan for fast ARP-based discovery, confirms with nmap ping sweep,
enriches results with hostname resolution and MAC vendor lookup.
"""
import re
import socket
import subprocess
from typing import Optional

from core.worker import BaseWorker

# ── Embedded OUI prefix → vendor table (top-50 most common) ──────────────────
OUI_PREFIXES: dict = {
    "00:50:56": "VMware",       "00:0c:29": "VMware",
    "00:1c:42": "Parallels",    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",     "00:16:3e": "Xen",
    "ac:de:48": "Apple",        "f8:ff:c2": "Apple",
    "00:1b:63": "Apple",        "3c:22:fb": "Apple",
    "a4:c3:f0": "Apple",
    "dc:a6:32": "Raspberry Pi Foundation",
    "b8:27:eb": "Raspberry Pi Foundation",
    "e4:5f:01": "Raspberry Pi Foundation",
    "00:1a:2b": "Cisco",        "00:0f:f7": "Cisco",
    "00:01:02": "Cisco",        "fc:fb:fb": "Cisco",
    "00:1e:13": "Netgear",      "20:4e:7f": "Netgear",
    "c0:3f:0e": "Netgear",      "00:22:6b": "Linksys",
    "00:14:bf": "Linksys",      "00:18:f8": "D-Link",
    "1c:7e:e5": "D-Link",       "00:90:4c": "Epigram (Broadcom)",
    "00:50:f2": "Microsoft",    "28:18:78": "Microsoft",
    "00:15:5d": "Microsoft Hyper-V",
    "00:1c:bf": "Samsung",      "84:25:db": "Samsung",
    "fc:a1:3e": "Samsung",      "40:b4:cd": "LG Electronics",
    "00:1e:c2": "Apple AirPort",
    "b4:fb:e4": "Dell",         "f0:1f:af": "Dell",
    "00:25:90": "Dell",         "00:1a:4b": "HP",
    "3c:d9:2b": "HP",           "00:17:08": "HP",
    "7c:e9:d3": "Intel",        "00:21:6b": "Intel",
    "f4:5c:89": "Intel",        "04:02:1f": "Ubiquiti",
    "44:d9:e7": "Ubiquiti",     "dc:9f:db": "Ubiquiti",
    "00:1b:17": "Huawei",       "48:46:fb": "Huawei",
    "f8:3d:ff": "ZTE",          "00:90:fb": "Fortinet",
}

VENDOR_DEVICE_HINTS: list = [
    (["Apple"],                             "Workstation / Mobile"),
    (["Raspberry Pi"],                      "Single-board Computer"),
    (["VMware", "VirtualBox", "QEMU", "Parallels", "Hyper-V", "Xen"], "Virtual Machine"),
    (["Cisco"],                             "Network Infrastructure"),
    (["Netgear", "Linksys", "D-Link", "Ubiquiti", "Fortinet"], "Router / AP"),
    (["HP"],                               "Printer / Workstation"),
    (["Dell", "Lenovo", "Acer", "Asus"],   "Workstation / Laptop"),
    (["Samsung", "LG", "Huawei", "ZTE"],   "Mobile / IoT"),
    (["Intel"],                             "Workstation / Laptop"),
    (["Microsoft"],                         "Workstation"),
]


def _vendor_from_mac(mac: str) -> str:
    prefix = mac[:8].upper().replace("-", ":") if mac else ""
    return OUI_PREFIXES.get(prefix, "")


def _device_type_from_vendor(vendor: str) -> str:
    for substrs, dtype in VENDOR_DEVICE_HINTS:
        if any(s.lower() in vendor.lower() for s in substrs):
            return dtype
    return "Unknown"


class NetworkDiscovery(BaseWorker):
    """
    Discovers live hosts on the local subnet using ARP and ICMP.

    Callbacks
    ---------
    on_host(dict)       — called for each live host discovered
    on_complete(list)   — full list of hosts at end of scan
    on_log(tag, msg)    — log messages
    on_finished(bool)   — True on clean completion
    on_connected()      — called when connected to a network (WiFi connect flow)
    """

    def __init__(
        self,
        iface: Optional[str] = None,
        ssid: Optional[str] = None,
        password: Optional[str] = None,
        on_host=None,
        on_log=None,
        on_complete=None,
        on_connected=None,
        on_finished=None,
    ) -> None:
        super().__init__()
        self.iface      = iface
        self.ssid       = ssid
        self.password   = password
        self.on_host    = on_host    or (lambda h: None)
        self.on_log     = on_log     or (lambda t, m: None)
        self.on_complete = on_complete or (lambda hosts: None)
        self.on_connected = on_connected or (lambda: None)
        self.on_finished  = on_finished  or (lambda ok: None)
        # Public attribute — caller can set before start()
        self.target: Optional[str] = None
        self.subnet: Optional[str] = None  # backwards compat alias

    def run(self) -> None:
        # If ssid/password given, connect first
        if self.ssid and self.password:
            self._connect_wifi()
            self._call(self.on_connected)

        subnet = self.target or self.subnet or self._detect_subnet()
        if not subnet:
            self._call(self.on_log, "NET", "Could not determine local subnet — aborting")
            self._call(self.on_finished, False)
            return

        self._call(self.on_log, "NET", f"Starting network discovery on {subnet}")

        arp_hosts  = self._arp_scan(subnet)
        self._call(self.on_log, "NET", f"ARP scan: {len(arp_hosts)} host(s)")

        nmap_hosts = self._nmap_ping_sweep(subnet)
        self._call(self.on_log, "NET", f"Nmap ping sweep: {len(nmap_hosts)} host(s)")

        merged = self._merge_hosts(arp_hosts, nmap_hosts)
        self._call(self.on_log, "NET", f"Total unique hosts: {len(merged)}")

        all_hosts: list = []
        for host in merged:
            if self.is_stopped():
                break
            enriched = self._enrich_host(host)
            all_hosts.append(enriched)
            self._call(self.on_host, enriched)

        self._call(self.on_complete, all_hosts)
        self._call(self.on_finished, True)

    def _connect_wifi(self) -> None:
        """Attempt to connect to Wi-Fi using nmcli."""
        try:
            self._call(self.on_log, "CONNECT", f"Connecting to {self.ssid}...")
            subprocess.run(
                ["nmcli", "dev", "wifi", "connect", self.ssid,
                 "password", self.password],
                capture_output=True, text=True, timeout=30,
            )
        except Exception as e:
            self._call(self.on_log, "CONNECT", f"Connect error: {e}")

    def _detect_subnet(self) -> Optional[str]:
        try:
            r = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5,
            )
            iface_match = re.search(r"dev\s+(\S+)", r.stdout)
            if not iface_match:
                return None
            iface = iface_match.group(1)

            r2 = subprocess.run(
                ["ip", "addr", "show", "dev", iface],
                capture_output=True, text=True, timeout=5,
            )
            cidr_match = re.search(
                r"inet\s+((?:192\.168|172\.1[6-9]|172\.2\d|172\.3[01]|10)\.\d+\.\d+/\d+)",
                r2.stdout,
            )
            if cidr_match:
                ip_cidr   = cidr_match.group(1)
                ip, prefix = ip_cidr.split("/")
                octets    = ip.split(".")
                prefix_len = int(prefix)
                ip_int    = sum(int(o) << (24 - 8 * i) for i, o in enumerate(octets))
                mask      = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
                net       = ip_int & mask
                net_str   = ".".join(str((net >> (24 - 8 * i)) & 0xFF) for i in range(4))
                return f"{net_str}/{prefix_len}"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        try:
            r3 = subprocess.run(["ip", "addr"], capture_output=True, text=True, timeout=5)
            m = re.search(
                r"inet\s+((?:192\.168|10|172\.1[6-9]|172\.2\d|172\.3[01])\.\d+\.\d+)/(\d+)",
                r3.stdout,
            )
            if m:
                return f"{m.group(1)}/{m.group(2)}"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return None

    def _arp_scan(self, subnet: str) -> list:
        hosts: list = []
        try:
            r = subprocess.run(
                ["arp-scan", "--localnet", "--retry=2", "--timeout=500"],
                capture_output=True, text=True, timeout=60,
            )
            raw = r.stdout
        except FileNotFoundError:
            try:
                r = subprocess.run(
                    ["arp-scan", subnet], capture_output=True, text=True, timeout=60,
                )
                raw = r.stdout
            except (FileNotFoundError, subprocess.TimeoutExpired):
                self._call(self.on_log, "NET", "arp-scan not available — falling back to nmap only")
                return hosts
        except subprocess.TimeoutExpired:
            return hosts

        for line in raw.splitlines():
            m = re.match(
                r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s*(.*)",
                line.strip(), re.IGNORECASE,
            )
            if not m:
                continue
            ip, mac, vendor = m.group(1), m.group(2).upper(), m.group(3).strip()
            hosts.append({
                "ip": ip, "mac": mac, "hostname": "",
                "vendor": vendor or _vendor_from_mac(mac),
                "device_type": "", "response_time_ms": 0, "status": "up",
            })
        return hosts

    def _nmap_ping_sweep(self, subnet: str) -> list:
        hosts: list = []
        try:
            r = subprocess.run(
                ["nmap", "-sn", "--open", "-T4", subnet],
                capture_output=True, text=True, timeout=120,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return hosts

        current_ip = ""
        for line in r.stdout.splitlines():
            line = line.strip()
            m_ip = re.search(
                r"Nmap scan report for (?:(\S+) \()?(\d{1,3}(?:\.\d{1,3}){3})\)?", line
            )
            if m_ip:
                current_ip = m_ip.group(2)
                continue
            m_lat = re.search(r"Host is up \((\d+\.?\d*)(\w+) latency\)", line)
            if m_lat and current_ip:
                raw_val = float(m_lat.group(1))
                unit    = m_lat.group(2)
                latency = raw_val * 1000 if unit == "s" else raw_val
                hosts.append({
                    "ip": current_ip, "mac": "", "hostname": "",
                    "vendor": "", "device_type": "",
                    "response_time_ms": round(latency, 2), "status": "up",
                })
                current_ip = ""
        return hosts

    def _merge_hosts(self, arp_hosts: list, nmap_hosts: list) -> list:
        merged: dict = {}
        for h in arp_hosts:
            merged[h["ip"]] = h
        for h in nmap_hosts:
            ip = h["ip"]
            if ip not in merged:
                merged[ip] = h
            else:
                if h["response_time_ms"] and not merged[ip]["response_time_ms"]:
                    merged[ip]["response_time_ms"] = h["response_time_ms"]
        return list(merged.values())

    def _enrich_host(self, host: dict) -> dict:
        ip, mac = host.get("ip", ""), host.get("mac", "")
        if not host.get("hostname"):
            try:
                host["hostname"] = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.gaierror, OSError):
                host["hostname"] = ip
        if not host.get("vendor") and mac:
            host["vendor"] = _vendor_from_mac(mac)
        if not host.get("device_type"):
            host["device_type"] = _device_type_from_vendor(host.get("vendor", ""))
        return host
