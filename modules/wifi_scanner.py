"""
modules/wifi_scanner.py — DARK CRACKER OPS Generation 2
Continuous WiFi network scanner using airodump-ng with CSV output.
Emits parsed network lists every 2 seconds sorted by signal strength.
"""

import csv
import io
import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import Callable, Optional

from core.worker import BaseWorker
from core.config import TOOLS
from core.logger import get_logger

log = get_logger("wifi_scanner")

# ── OUI database (loaded once at import) ──────────────────────────────────────
_OUI_DB: dict = {}
_OUI_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "oui_database.json"
)
try:
    if os.path.exists(_OUI_DB_PATH):
        import json as _json
        with open(_OUI_DB_PATH, "r", errors="replace") as _fh:
            _OUI_DB = _json.load(_fh)
        log.debug("OUI database loaded: %d entries from %s", len(_OUI_DB), _OUI_DB_PATH)
except Exception as _oui_exc:
    log.debug("OUI database not loaded: %s", _oui_exc)


def _lookup_vendor(bssid: str) -> str:
    """Look up vendor from BSSID first 3 bytes against OUI database."""
    if not bssid:
        return "Unknown"
    oui = bssid.replace(":", "").replace("-", "").upper()[:6]
    if _OUI_DB:
        return _OUI_DB.get(oui, "Unknown")
    # Fall back to core.utils get_vendor if available
    try:
        from core.utils import get_vendor as _gv
        return _gv(bssid) or "Unknown"
    except Exception:
        return "Unknown"


# Mapping of airodump-ng encryption strings to normalised labels
_ENC_MAP = {
    "WPA2": "WPA2",
    "WPA":  "WPA",
    "WEP":  "WEP",
    "OPN":  "OPEN",
    "WPA3": "WPA3",
    "OWE":  "OWE",
}


def _norm_enc(raw: str) -> str:
    raw = raw.strip().upper()
    for key, val in _ENC_MAP.items():
        if key in raw:
            return val
    return raw or "UNKNOWN"


def _norm_power(raw: str) -> int:
    """Convert airodump-ng power string to int dBm, negative values only."""
    try:
        val = int(raw.strip())
        return val if val <= 0 else -val
    except (ValueError, AttributeError):
        return -100


class WiFiScanner(BaseWorker):
    """
    Runs airodump-ng continuously and calls back with parsed network data every 2 s.

    Callbacks:
        on_networks(list)       — list of network dicts sorted by signal
        on_log(str, str)        — (tag, message)
        on_done()               — called when the thread exits cleanly
        on_progress(int)        — 0-100 scan progress
        on_finished(bool)       — True on clean completion
    """

    def __init__(
        self,
        interface: str,
        band: str = "2.4",
        on_networks: Optional[Callable] = None,
        on_log: Optional[Callable] = None,
        on_progress: Optional[Callable] = None,
        on_finished: Optional[Callable] = None,
        on_done: Optional[Callable] = None,
        duration: int = 30,
    ):
        super().__init__()
        self.interface  = interface
        self.band       = band
        self.duration   = duration
        self.on_networks = on_networks
        self.on_log      = on_log
        self.on_progress = on_progress
        self.on_finished = on_finished
        self.on_done     = on_done
        self._proc       = None   # airodump-ng process handle
        self._tmpdir     = None   # directory for CSV output

    # ── Thread entry point ────────────────────────────────────────────────────

    def run(self):
        self._tmpdir = tempfile.mkdtemp(prefix="dc_scan_")
        csv_prefix   = os.path.join(self._tmpdir, "airodump")

        # Build airodump-ng command
        airodump = TOOLS.get("airodump", "airodump-ng")
        cmd = [
            airodump,
            "--write", csv_prefix,
            "--output-format", "csv",
            "--write-interval", "2",
        ]

        # Band filter
        if "5" in self.band and "2.4" in self.band:
            cmd += ["--band", "abg"]
        elif "5" in self.band:
            cmd += ["--band", "a"]
        else:
            cmd += ["--band", "bg"]

        cmd.append(self.interface)

        self._call(self.on_log, "SCAN", f"Starting scanner on {self.interface} [{self.band}]")
        log.info("airodump-ng cmd: %s", " ".join(cmd))

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            self._call(self.on_log, "ERROR", "airodump-ng not found — install aircrack-ng suite")
            self._call(self.on_finished, False)
            self._call(self.on_done)
            return
        except Exception as exc:
            self._call(self.on_log, "ERROR", f"Failed to start airodump-ng: {exc}")
            self._call(self.on_finished, False)
            self._call(self.on_done)
            return

        # Optionally run wash in parallel to detect WPS-enabled APs
        wash_data: dict[str, bool] = {}
        wash_proc = self._start_wash()

        # Optionally run tshark to capture probe responses for hidden SSIDs
        hidden_ssids: dict[str, str] = {}  # bssid → ssid
        tshark_proc = self._start_hidden_ssid_capture(csv_prefix)

        start_time = time.time()
        elapsed    = 0

        while not self.is_stopped() and elapsed < self.duration:
            time.sleep(2)
            elapsed = time.time() - start_time

            # Parse latest CSV snapshot
            csv_file = csv_prefix + "-01.csv"
            if not os.path.exists(csv_file):
                continue

            try:
                networks = self._parse_csv(csv_file, wash_data)
                if networks:
                    self._call(self.on_networks, networks)
                    self._call(
                        self.on_log,
                        "SCAN",
                        f"Found {len(networks)} network(s) — elapsed {int(elapsed)}s"
                    )
            except Exception as exc:
                log.debug("CSV parse error: %s", exc)

            # Update wash results
            if wash_proc:
                self._update_wash(wash_data, wash_proc)

            # Emit approximate progress
            pct = min(99, int((elapsed / self.duration) * 100))
            self._call(self.on_progress, pct)

        self._cleanup(wash_proc)
        if tshark_proc:
            try:
                tshark_proc.terminate()
                tshark_proc.wait(timeout=3)
            except Exception:
                pass
        self._call(self.on_progress, 100)
        self._call(self.on_finished, True)
        self._call(self.on_done)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _start_hidden_ssid_capture(self, csv_prefix: str):
        """
        Launch tshark to capture probe responses for hidden SSID detection.
        Returns Popen handle or None if tshark is unavailable.
        """
        tshark = shutil.which("tshark")
        if not tshark:
            return None
        probe_cap = csv_prefix + "_probes.pcapng"
        try:
            return subprocess.Popen(
                [tshark, "-i", self.interface,
                 "-f", "subtype proberesp or subtype beacon",
                 "-a", f"duration:{self.duration}",
                 "-w", probe_cap],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            return None

    def _start_wash(self):
        """Start wash for WPS detection, return Popen or None."""
        wash = shutil.which(TOOLS.get("wash", "wash"))
        if not wash:
            return None
        try:
            return subprocess.Popen(
                [wash, "-i", self.interface, "-C", "--json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except Exception:
            return None

    def _update_wash(self, wash_data: dict, proc) -> None:
        """Read non-blocking output from wash and update BSSID→WPS map."""
        import select
        if proc.poll() is not None:
            return
        try:
            ready, _, _ = select.select([proc.stdout], [], [], 0)
            if not ready:
                return
            line = proc.stdout.readline().strip()
            if not line:
                return
            # Attempt JSON parse first
            try:
                import json
                entry = json.loads(line)
                bssid = entry.get("bssid", "").upper()
                if bssid:
                    wash_data[bssid] = True
                return
            except Exception:
                pass
            # Fallback: plain-text wash output — BSSID is first field
            parts = line.split()
            if parts and re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", parts[0]):
                wash_data[parts[0].upper()] = True
        except Exception:
            pass

    def _parse_csv(self, csv_path: str, wash_data: dict) -> list:
        """
        Parse airodump-ng CSV file and return sorted network list.

        airodump-ng CSV has two sections separated by a blank line:
          1. APs (BSSID, First time seen, Last time seen, channel, Speed,
                  Privacy, Cipher, Authentication, Power, # beacons, # IV,
                  LAN IP, ID-length, ESSID, Key)
          2. Clients (Station MAC, … , Probed ESSIDs)
        """
        with open(csv_path, "r", errors="replace") as fh:
            raw = fh.read()

        # Split into AP section and client section
        sections = re.split(r"\n\s*\n", raw, maxsplit=1)
        ap_section     = sections[0] if sections else ""
        client_section = sections[1] if len(sections) > 1 else ""

        # Parse client→AP associations for the clients field
        client_map: dict[str, list] = {}  # bssid → [client_macs]
        if client_section:
            reader = csv.reader(io.StringIO(client_section))
            for row in reader:
                if len(row) < 2:
                    continue
                if row[0].strip().startswith("Station"):
                    continue
                cli_mac = row[0].strip().upper()
                assoc_bssid = row[5].strip().upper() if len(row) > 5 else ""
                if assoc_bssid and assoc_bssid != "(NOT ASSOCIATED)":
                    client_map.setdefault(assoc_bssid, []).append(cli_mac)

        networks = []
        reader = csv.reader(io.StringIO(ap_section))
        for row in reader:
            if len(row) < 14:
                continue
            bssid = row[0].strip().upper()
            # Skip header row
            if bssid in ("BSSID", ""):
                continue
            # Validate BSSID format
            if not re.match(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", bssid):
                continue

            channel_str = row[3].strip()
            try:
                channel = int(channel_str)
            except ValueError:
                channel = 0

            enc    = _norm_enc(row[5].strip())
            cipher = row[6].strip()
            auth   = row[7].strip()
            power  = _norm_power(row[8].strip())
            beacons = 0
            ivs     = 0
            try:
                beacons = int(row[9].strip())
            except ValueError:
                pass
            try:
                ivs = int(row[10].strip())
            except ValueError:
                pass

            id_len = 0
            try:
                id_len = int(row[12].strip())
            except (ValueError, IndexError):
                pass

            ssid_raw = row[13].strip() if len(row) > 13 else ""
            ssid = ssid_raw if (ssid_raw and id_len > 0) else "<hidden>"

            vendor  = _lookup_vendor(bssid)
            wps     = wash_data.get(bssid, False)
            clients = len(client_map.get(bssid, []))

            # WPS version — try to parse from Privacy/notes column
            wps_version = ""
            if wps:
                # wash sometimes provides version info via JSON; default to "1.0"
                wps_version = wash_data.get(bssid + "_ver", "1.0") if isinstance(wash_data.get(bssid + "_ver"), str) else "1.0"

            networks.append({
                "bssid":       bssid,
                "ssid":        ssid,
                "channel":     channel,
                "enc":         enc,
                "cipher":      cipher,
                "auth":        auth,
                "power":       power,
                "beacons":     beacons,
                "ivs":         ivs,
                "wps":         wps,
                "wps_version": wps_version,
                "clients":     clients,
                "vendor":      vendor,
                "hidden":      ssid == "<hidden>",
            })

        # Sort: WEP first, WPS-enabled second, WPA2 by signal, WPA3 last
        def _sort_key(n: dict):
            enc_upper = n.get("enc", "").upper()
            if "WEP" in enc_upper:
                tier = 0
            elif n.get("wps_version"):
                tier = 1
            elif "WPA3" in enc_upper:
                tier = 3
            else:
                tier = 2
            return (tier, -n.get("power", -100))

        networks.sort(key=_sort_key)
        return networks

    def _cleanup(self, wash_proc) -> None:
        """Terminate subprocesses and remove temp directory."""
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None

        if wash_proc:
            try:
                wash_proc.terminate()
                wash_proc.wait(timeout=3)
            except Exception:
                pass

        if self._tmpdir and os.path.isdir(self._tmpdir):
            try:
                shutil.rmtree(self._tmpdir, ignore_errors=True)
            except Exception:
                pass

    # ── Public control API ────────────────────────────────────────────────────

    def stop(self) -> None:
        """Signal the scan loop to exit."""
        super().stop()
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass
