"""
core/utils.py — Shared utilities for DARK CRACKER OPS.
Covers: root check, subprocess wrappers, interface enumeration,
MAC/OUI lookup, signal/duration formatting, filename sanitization.
"""
import os
import re
import subprocess
import shutil
import time
import socket
import struct
from typing import Tuple, List, Optional, Dict

from core.logger import get_logger

log = get_logger("utils")

# ── Root check ────────────────────────────────────────────────────────────────

def is_root() -> bool:
    """Return True if the process is running as root (UID 0)."""
    return os.geteuid() == 0


def require_root() -> None:
    """Raise PermissionError if not running as root."""
    if not is_root():
        raise PermissionError("This operation requires root privileges (run with sudo).")


# ── Command execution ─────────────────────────────────────────────────────────

def run_command(
    cmd: List[str],
    timeout: int = 60,
    stdin: Optional[str] = None,
    env: Optional[Dict] = None,
) -> Tuple[bool, str, str]:
    """
    Run a command and wait for it to finish.

    Returns:
        (success: bool, stdout: str, stderr: str)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin,
            env=env,
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        log.warning("Command timed out after %ds: %s", timeout, " ".join(cmd))
        return False, "", "Timeout"
    except FileNotFoundError:
        return False, "", f"Tool not found: {cmd[0]}"
    except Exception as exc:
        log.error("run_command error: %s", exc)
        return False, "", str(exc)


def run_command_popen(
    cmd: List[str],
    env: Optional[Dict] = None,
) -> subprocess.Popen:
    """
    Launch a command as a background process.
    Caller is responsible for calling .wait() / .kill() / .communicate().
    """
    log.debug("Popen: %s", " ".join(cmd))
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )


def tool_exists(tool_name: str) -> bool:
    """Return True if *tool_name* is on PATH."""
    return shutil.which(tool_name) is not None


# ── Wireless interfaces ───────────────────────────────────────────────────────

def get_wifi_interfaces() -> List[str]:
    """
    Return a list of wireless interface names present on the system.
    Tries ``iw dev`` first, falls back to /sys/class/net inspection.
    """
    ifaces: List[str] = []
    try:
        ok, out, _ = run_command(["iw", "dev"], timeout=10)
        if ok:
            for line in out.splitlines():
                stripped = line.strip()
                if stripped.startswith("Interface "):
                    ifaces.append(stripped.split()[1])
        if not ifaces:
            net_dir = "/sys/class/net"
            for iface in os.listdir(net_dir):
                if os.path.exists(os.path.join(net_dir, iface, "wireless")):
                    ifaces.append(iface)
    except Exception as exc:
        log.error("get_wifi_interfaces error: %s", exc)
    return ifaces


def get_all_interfaces() -> List[str]:
    """Return all network interfaces (wired + wireless)."""
    try:
        return os.listdir("/sys/class/net")
    except Exception:
        return []


def get_interface_mac(iface: str) -> str:
    """Read the hardware MAC address for *iface* from sysfs."""
    path = f"/sys/class/net/{iface}/address"
    try:
        with open(path) as f:
            return f.read().strip().upper()
    except Exception:
        return ""


def set_monitor_mode(iface: str) -> Tuple[bool, str]:
    """
    Put *iface* into monitor mode using airmon-ng.
    Returns (success, monitor_interface_name).
    """
    ok, out, err = run_command(["airmon-ng", "start", iface], timeout=20)
    if not ok:
        return False, err
    # airmon-ng usually creates <iface>mon  e.g. wlan0mon
    mon = iface + "mon"
    if mon in get_wifi_interfaces():
        return True, mon
    # Some drivers rename differently; scan for any new monitor interface
    for candidate in get_wifi_interfaces():
        if candidate != iface and "mon" in candidate:
            return True, candidate
    return ok, iface  # assume same name on some drivers


def set_managed_mode(iface: str) -> bool:
    """Restore *iface* to managed mode using airmon-ng stop."""
    ok, _, _ = run_command(["airmon-ng", "stop", iface], timeout=20)
    return ok


# ── MAC / OUI vendor lookup ───────────────────────────────────────────────────

_OUI_DB: Dict[str, str] = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:1A:2B": "Cisco",
    "00:1E:BD": "Cisco",
    "00:1F:26": "Cisco",
    "00:1B:63": "Apple",
    "18:65:90": "Apple",
    "3C:07:54": "Apple",
    "DC:A9:04": "Apple",
    "A4:C3:F0": "Apple",
    "F0:18:98": "Apple",
    "00:50:F2": "Microsoft",
    "28:D2:44": "Microsoft",
    "00:1F:3C": "Intel",
    "00:23:14": "Intel",
    "8C:EC:4B": "Intel",
    "00:26:B9": "Dell",
    "14:18:77": "Dell",
    "00:14:22": "Dell",
    "1C:6F:65": "ASUS",
    "04:D4:C4": "ASUS",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "28:CD:C1": "Raspberry Pi",
    "00:09:BF": "TP-Link",
    "C0:4A:00": "TP-Link",
    "EC:08:6B": "TP-Link",
    "90:F6:52": "TP-Link",
    "54:A7:03": "TP-Link",
    "00:1D:7E": "Linksys",
    "C4:41:1E": "Linksys",
    "00:14:6C": "Netgear",
    "20:0C:C8": "Netgear",
    "C0:3F:0E": "Netgear",
    "30:46:9A": "Netgear",
    "00:17:DF": "Asus Router",
    "74:D4:35": "Samsung",
    "CC:F9:54": "Samsung",
    "00:16:32": "Samsung",
    "00:26:E8": "Huawei",
    "00:46:4B": "Huawei",
    "AC:CF:85": "Huawei",
    "00:18:E7": "D-Link",
    "1C:BD:B9": "D-Link",
    "14:D6:4D": "D-Link",
    "00:22:6B": "ZTE",
    "3C:46:D8": "ZTE",
    "28:2C:B2": "Xiaomi",
    "F4:F5:DB": "Xiaomi",
    "00:9A:CD": "Huawei Lite",
    "78:11:DC": "Ubiquiti",
    "04:18:D6": "Ubiquiti",
    "00:27:22": "Ubiquiti",
    "7C:DD:90": "MikroTik",
    "B8:69:F4": "MikroTik",
    "00:0D:B9": "PC Engines",
    "00:1C:BF": "Peplink",
}


def get_vendor(mac: str) -> str:
    """Return the vendor name for a MAC address, or 'Unknown'."""
    if not mac or len(mac) < 8:
        return "Unknown"
    # Normalise to XX:XX:XX format
    normalized = mac.upper().replace("-", ":").replace(".", ":")
    prefix = ":".join(normalized.split(":")[:3])
    return _OUI_DB.get(prefix, "Unknown")


def is_randomized_mac(mac: str) -> bool:
    """
    Return True if the MAC address has the locally-administered bit set,
    which typically indicates a randomized/privacy MAC.
    """
    if not mac or len(mac) < 2:
        return False
    try:
        first_byte = int(mac.split(":")[0].replace("-", ""), 16)
        return bool(first_byte & 0x02)
    except (ValueError, IndexError):
        return False


def is_broadcast_mac(mac: str) -> bool:
    """Return True if the MAC is the broadcast address FF:FF:FF:FF:FF:FF."""
    return mac.upper().replace("-", ":") == "FF:FF:FF:FF:FF:FF"


# ── IP / Network helpers ──────────────────────────────────────────────────────

def is_valid_ip(addr: str) -> bool:
    """Return True if *addr* is a valid IPv4 address."""
    try:
        socket.inet_pton(socket.AF_INET, addr)
        return True
    except (socket.error, OSError):
        return False


def is_valid_cidr(cidr: str) -> bool:
    """Return True if *cidr* is a valid IPv4 CIDR (e.g. 192.168.1.0/24)."""
    try:
        addr, prefix = cidr.split("/")
        if not is_valid_ip(addr):
            return False
        return 0 <= int(prefix) <= 32
    except Exception:
        return False


def ip_to_int(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(n: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", n))


def cidr_to_range(cidr: str) -> Tuple[str, str]:
    """Return (first_ip, last_ip) strings for a CIDR range."""
    addr, prefix = cidr.split("/")
    mask = (0xFFFFFFFF << (32 - int(prefix))) & 0xFFFFFFFF
    base = ip_to_int(addr) & mask
    return int_to_ip(base), int_to_ip(base | (~mask & 0xFFFFFFFF))


# ── Formatting helpers ────────────────────────────────────────────────────────

def fmt_duration(seconds: int) -> str:
    """Format an integer number of seconds as HH:MM:SS."""
    h, rem = divmod(int(seconds), 3600)
    m, s   = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def fmt_signal(dbm: int) -> str:
    """Return a human-readable signal quality label for a dBm value."""
    if dbm >= -50:
        return "Excellent"
    if dbm >= -65:
        return "Good"
    if dbm >= -75:
        return "Fair"
    return "Poor"


def fmt_bytes(n: int) -> str:
    """Format a byte count into a human-readable string (KB/MB/GB)."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def sanitize_filename(s: str) -> str:
    """Remove characters that are unsafe in file/directory names."""
    return re.sub(r"[^\w\-_\.]", "_", s)


def now_str() -> str:
    """Return current datetime as an ISO-formatted string."""
    from datetime import datetime
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def timestamp_filename() -> str:
    """Return a sortable timestamp string suitable for use in filenames."""
    from datetime import datetime
    return datetime.now().strftime("%Y%m%d_%H%M%S")


# ── Missing tools ─────────────────────────────────────────────────────────────

def missing_tools() -> List[str]:
    """Return the list of logical tool names whose executables are absent."""
    from core.config import TOOLS
    return [name for name, cmd in TOOLS.items() if not shutil.which(cmd)]


def check_tool(tool_cmd: str) -> bool:
    """Return True if *tool_cmd* is available on PATH."""
    return shutil.which(tool_cmd) is not None


# ── Channel helpers ───────────────────────────────────────────────────────────

def channel_to_frequency(channel: int) -> int:
    """
    Convert a 2.4 GHz Wi-Fi channel number to its centre frequency in MHz.
    Returns 0 for unknown channels.
    """
    if 1 <= channel <= 13:
        return 2407 + channel * 5
    if channel == 14:
        return 2484
    # 5 GHz channels
    if 36 <= channel <= 165:
        return 5000 + channel * 5
    return 0


def frequency_to_channel(freq: int) -> int:
    """Convert a frequency in MHz back to a channel number (0 if unknown)."""
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if 5180 <= freq <= 5825:
        return (freq - 5000) // 5
    return 0


# ── Performance helpers ───────────────────────────────────────────────────────

import functools
import time as _time


def timed(fn):
    """Decorator: logs execution time for slow functions (threshold: 500ms)."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        t0     = _time.perf_counter()
        result = fn(*args, **kwargs)
        elapsed = _time.perf_counter() - t0
        if elapsed > 0.5:  # only log if > 500ms
            import logging
            logging.getLogger("darkcracker").warning(
                f"SLOW: {fn.__qualname__} took {elapsed:.2f}s"
            )
        return result
    return wrapper


