"""
core/config.py — DARK CRACKER OPS global configuration.
All constants, tool paths, risk definitions, and directory paths.
"""
import shutil
from pathlib import Path

APP_NAME    = "DARK CRACKER OPS"
APP_VERSION = "2.0.0"
APP_GEN     = "Generation 2"

# ── Directories ───────────────────────────────────────────────────────────────
CONFIG_DIR      = Path.home() / ".darkcracker"
DB_PATH         = CONFIG_DIR / "darkcracker.db"
LOG_PATH        = CONFIG_DIR / "darkcracker.log"
SESSIONS_DIR    = CONFIG_DIR / "sessions"
REPORTS_DIR     = CONFIG_DIR / "reports"
WORDLISTS_DIR   = CONFIG_DIR / "wordlists"
TARGETS_FILE    = CONFIG_DIR / "targets.json"
THEME_FILE      = CONFIG_DIR / "theme.json"
CONFIG_FILE     = CONFIG_DIR / "config.json"
DISCLAIMER_FILE = CONFIG_DIR / ".accepted"

# ── Window constraints ────────────────────────────────────────────────────────
WINDOW_MIN_W = 1400
WINDOW_MIN_H = 900

# ── External tools ────────────────────────────────────────────────────────────
TOOLS = {
    "aircrack":      "aircrack-ng",
    "airodump":      "airodump-ng",
    "aireplay":      "aireplay-ng",
    "airmon":        "airmon-ng",
    "hcxdumptool":   "hcxdumptool",
    "hcxpcapngtool": "hcxpcapngtool",
    "hashcat":       "hashcat",
    "nmap":          "nmap",
    "arp_scan":      "arp-scan",
    "reaver":        "reaver",
    "wash":          "wash",
    "hostapd":       "hostapd",
    "dnsmasq":       "dnsmasq",
    "iptables":      "iptables",
    "nmcli":         "nmcli",
    "nikto":         "nikto",
    "gobuster":      "gobuster",
    "sshpass":       "sshpass",
}

# ── Risk port classification ──────────────────────────────────────────────────
RISK_PORTS = {
    "CRITICAL": [23, 512, 513, 514, 5900, 27017, 6379, 9042, 11211],
    "HIGH":     [21, 22, 445, 3389, 3306, 1433, 5432, 5984, 9200, 2375, 4848, 7001],
    "MEDIUM":   [80, 443, 8080, 8443, 8888, 8008, 8081],
    "LOW":      [53, 110, 143, 25, 587, 465, 993, 995],
}

# ── Attack timeouts (seconds) ─────────────────────────────────────────────────
TIMEOUT_SCAN     = 60
TIMEOUT_CAPTURE  = 120
TIMEOUT_CRACK    = 3600
TIMEOUT_CONNECT  = 30
TIMEOUT_DISCOVER = 120
TIMEOUT_PORTSCAN = 300

# ── Default wordlists ─────────────────────────────────────────────────────────
DEFAULT_WORDLISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/fasttrack.txt",
    "/usr/share/wordlists/metasploit/password.lst",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
]

# ── Network scanning defaults ─────────────────────────────────────────────────
DEFAULT_SCAN_PORTS   = "21,22,23,25,53,80,110,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017"
DEFAULT_NMAP_ARGS    = "-sV -O --open -T4"
DEFAULT_CHANNEL_LIST = list(range(1, 15))  # 2.4 GHz channels 1-14

# ── WPS attack settings ───────────────────────────────────────────────────────
WPS_LOCK_DELAY   = 60   # seconds to wait after WPS lockout
WPS_MAX_RETRIES  = 3    # maximum PIN retries before backing off

# ── Evil Twin / AP settings ───────────────────────────────────────────────────
EVIL_TWIN_IFACE_MON  = "wlan1"   # default monitor interface for evil twin
EVIL_TWIN_IFACE_AP   = "wlan0"   # default AP interface
EVIL_TWIN_CHANNEL    = 6
EVIL_TWIN_DHCP_RANGE = "10.0.0.10,10.0.0.100,12h"
EVIL_TWIN_GATEWAY    = "10.0.0.1"
EVIL_TWIN_NETMASK    = "255.255.255.0"


# ── Reporting ─────────────────────────────────────────────────────────────────
REPORT_FORMATS     = ["HTML", "JSON", "TXT"]
DEFAULT_REPORT_FMT = "HTML"

# ── Hashcat modes ─────────────────────────────────────────────────────────────
HASHCAT_MODES = {
    "WPA/WPA2":  2500,
    "WPA-PMKID": 22000,
    "MD5":       0,
    "SHA1":      100,
    "NTLM":      1000,
    "NetNTLMv2": 5600,
}


# ── PATHS dict (alias for directory constants) ────────────────────────────────
PATHS = {
    "config_dir":   CONFIG_DIR,
    "db":           DB_PATH,
    "log":          LOG_PATH,
    "sessions":     SESSIONS_DIR,
    "reports":      REPORTS_DIR,
    "wordlists":    WORDLISTS_DIR,
    "targets":      TARGETS_FILE,
    "theme":        THEME_FILE,
    "config":       CONFIG_FILE,
    "disclaimer":   DISCLAIMER_FILE,
}


def ensure_dirs() -> None:
    """Create all required application directories on first run."""
    for d in [CONFIG_DIR, SESSIONS_DIR, REPORTS_DIR, WORDLISTS_DIR]:
        d.mkdir(parents=True, exist_ok=True)


def missing_tools() -> list:
    """Return list of logical tool names whose executables are not on PATH."""
    return [name for name, cmd in TOOLS.items() if not shutil.which(cmd)]


def get_risk_level(port: int) -> str:
    """Return risk level string for a given port number."""
    for level, ports in RISK_PORTS.items():
        if port in ports:
            return level
    return "INFO"
