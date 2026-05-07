"""
modules/wordlist_manager.py — DARK CRACKER OPS Generation 2
Wordlist discovery, SSID-based mutation generation, merging, and download.
"""
from core.worker import BaseWorker

import os
import re
import time
import urllib.request


from core.config import WORDLISTS_DIR, DEFAULT_WORDLISTS
from core.logger import get_logger
from core.utils import fmt_duration

log = get_logger("wordlist_manager")

# Well-known wordlist download sources
WORDLIST_URLS = [
    {
        "name":     "SecLists - Top 1M",
        "url":      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
                    "Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
        "filename": "seclists_top1m.txt",
    },
    {
        "name":     "SecLists - WiFi Common",
        "url":      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
                    "Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt",
        "filename": "seclists_wpa4800.txt",
    },
    {
        "name":     "Kaonashi WPA",
        "url":      "https://github.com/kaonashi-passwords/Kaonashi/raw/master/kaonashi14M.txt",
        "filename": "kaonashi14m.txt",
    },
]

# Common WiFi password suffixes and patterns
_COMMON_SUFFIXES = [
    "", "1", "12", "123", "1234", "12345", "123456",
    "!", "!!", "?", "#", "@", ".",
    "2023", "2024", "2025",
    "_1", "_2", "_wifi", "_home", "_net",
]

_COMMON_PREFIXES = [
    "wifi", "home", "net", "pass", "admin", "router",
    "internet", "wlan", "wireless",
]

_LEET_MAP = {
    "a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7",
}


class WordlistManager:
    """
    Utility class for local wordlist management.
    All methods are synchronous — call from worker threads, not main thread.
    """

    # Default search directories
    SEARCH_DIRS = [
        "/usr/share/wordlists",
        "/usr/share/seclists",
        str(WORDLISTS_DIR),
        os.path.expanduser("~/.darkcracker/wordlists"),
    ]

    # ── Wordlist discovery ────────────────────────────────────────────────────

    def list_local(self, search_dirs: list | None = None) -> list:
        """
        Scan directories for .txt wordlist files.

        Returns list of dicts:
            {path, name, size, count}
        sorted by file size descending.
        """
        dirs = search_dirs if search_dirs else self.SEARCH_DIRS
        results = []
        seen_paths = set()

        for base_dir in dirs:
            if not os.path.isdir(base_dir):
                continue
            try:
                for root, _, files in os.walk(base_dir, followlinks=False):
                    for fname in files:
                        if not fname.lower().endswith(".txt"):
                            continue
                        full_path = os.path.join(root, fname)
                        real_path = os.path.realpath(full_path)
                        if real_path in seen_paths:
                            continue
                        seen_paths.add(real_path)
                        try:
                            stat  = os.stat(full_path)
                            fsize = stat.st_size
                            count = self._count_lines_fast(full_path)
                            results.append({
                                "path":  full_path,
                                "name":  fname,
                                "size":  fsize,
                                "count": count,
                            })
                        except OSError:
                            continue
            except PermissionError:
                continue

        # Also check DEFAULT_WORDLISTS explicitly
        for wl_path in DEFAULT_WORDLISTS:
            real_path = os.path.realpath(wl_path)
            if os.path.exists(wl_path) and real_path not in seen_paths:
                seen_paths.add(real_path)
                try:
                    stat  = os.stat(wl_path)
                    fsize = stat.st_size
                    count = self._count_lines_fast(wl_path)
                    results.append({
                        "path":  wl_path,
                        "name":  os.path.basename(wl_path),
                        "size":  fsize,
                        "count": count,
                    })
                except OSError:
                    pass

        results.sort(key=lambda x: x["size"], reverse=True)
        log.info("Found %d local wordlists", len(results))
        return results

    # ── SSID mutation generator ───────────────────────────────────────────────

    def generate_ssid_mutations(self, ssid: str) -> list:
        """
        Generate 50+ password candidates derived from the target SSID.

        Strategies:
          - Raw SSID as-is
          - Case variations (upper, title, lower)
          - Number suffixes (1, 12, 123, 1234, 12345, 123456)
          - Year suffixes (2020–2025)
          - Common router password patterns
          - Leet-speak substitutions
          - Phone/address padding (1234, 0000)
          - Symbol suffixes (!, ?, #, @)
          - Common WiFi password templates
        """
        candidates: list[str] = []
        seen: set[str] = set()

        def add(pw: str):
            pw = pw.strip()
            # WiFi passwords must be 8-63 chars
            if 8 <= len(pw) <= 63 and pw not in seen:
                seen.add(pw)
                candidates.append(pw)

        base_variants = [
            ssid,
            ssid.lower(),
            ssid.upper(),
            ssid.title(),
            ssid.capitalize(),
            ssid.strip().replace(" ", ""),
            ssid.strip().replace(" ", "_"),
            ssid.strip().replace(" ", "-"),
            ssid.strip().replace(" ", "."),
        ]

        # 1. Base + common suffixes
        for base in base_variants:
            for suffix in _COMMON_SUFFIXES:
                add(base + suffix)

        # 2. Year suffixes 2010-2025
        for base in base_variants:
            for year in range(2010, 2026):
                add(base + str(year))
                add(base + "_" + str(year))
                add(base + str(year) + "!")

        # 3. Repeated chars padding
        for base in base_variants:
            for pad in ["0000", "1111", "9999", "0123", "1234"]:
                add(base + pad)

        # 4. Common WiFi password templates using SSID
        for base in [ssid, ssid.lower()]:
            add(f"{base}wifi")
            add(f"{base}home")
            add(f"{base}pass")
            add(f"{base}password")
            add(f"{base}network")
            add(f"wifi{base}")
            add(f"home{base}")

        # 5. Leet-speak on lowercase
        leet_base = ssid.lower()
        leet_variant = ""
        for ch in leet_base:
            leet_variant += _LEET_MAP.get(ch, ch)
        if leet_variant != leet_base:
            for suffix in ["", "123", "!", "1", "2024"]:
                add(leet_variant + suffix)

        # 6. Partial SSID combinations
        words = re.split(r"[\s_\-\.]+", ssid)
        if len(words) > 1:
            for w in words:
                if len(w) >= 3:
                    for suffix in _COMMON_SUFFIXES[:8]:
                        add(w + suffix)
                    for year in range(2020, 2026):
                        add(w + str(year))

        # 7. Common weak passwords (always include for AP defaults)
        common_passwords = [
            "password", "password1", "password123",
            "12345678", "123456789", "1234567890",
            "admin123", "admin1234",
            "qwerty123", "letmein1",
            "wifi1234", "internet",
            "pass1234", "router123",
        ]
        for pw in common_passwords:
            add(pw)

        # 8. Numeric patterns
        for base in [ssid, ssid.lower()]:
            add(base + "01")
            add(base + "001")
            add(base + "007")
            add(base + "99")
            add(base + "100")

        log.info("Generated %d SSID mutations for '%s'", len(candidates), ssid)
        return candidates

    # ── Wordlist merger ───────────────────────────────────────────────────────

    def merge_wordlists(self, paths: list, output_path: str) -> int:
        """
        Merge multiple wordlist files, deduplicate entries, write to output_path.

        Returns number of unique entries written.
        """
        seen: set[str] = set()
        count = 0

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        try:
            with open(output_path, "w", encoding="utf-8", errors="replace") as out_fh:
                for path in paths:
                    if not os.path.exists(path):
                        log.warning("Wordlist not found, skipping: %s", path)
                        continue
                    log.info("Merging: %s", path)
                    try:
                        with open(path, "r", encoding="utf-8", errors="replace") as in_fh:
                            for line in in_fh:
                                word = line.rstrip("\r\n")
                                if word and word not in seen:
                                    seen.add(word)
                                    out_fh.write(word + "\n")
                                    count += 1
                    except (IOError, OSError) as exc:
                        log.error("Error reading %s: %s", path, exc)
                        continue

        except (IOError, OSError) as exc:
            log.error("Failed to write merged wordlist: %s", exc)
            return 0

        log.info("Merged %d unique entries → %s", count, output_path)
        return count

    # ── Crack time estimator ──────────────────────────────────────────────────

    def estimate_crack_time(self, wordlist_path: str,
                            hash_rate: int = 5_000_000) -> str:
        """
        Estimate cracking time for a wordlist given a hash rate.

        Default hash_rate = 5 MH/s (typical GTX 1080 Ti on WPA2).
        Returns a formatted duration string, e.g. "2h 34m 12s".
        """
        line_count = self._count_lines_fast(wordlist_path)
        if line_count == 0:
            return "unknown (empty wordlist)"
        if hash_rate <= 0:
            return "unknown (invalid hash rate)"

        seconds = int(line_count / hash_rate)

        if seconds < 1:
            return "< 1 second"

        try:
            return fmt_duration(seconds)
        except Exception:
            # Manual fallback if fmt_duration is unavailable
            h, rem = divmod(seconds, 3600)
            m, s   = divmod(rem, 60)
            parts  = []
            if h:
                parts.append(f"{h}h")
            if m:
                parts.append(f"{m}m")
            if s or not parts:
                parts.append(f"{s}s")
            return " ".join(parts)

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _count_lines_fast(path: str) -> int:
        """Count newlines in a file using buffered reads."""
        count = 0
        try:
            with open(path, "rb") as fh:
                buf = bytearray(1 << 16)
                while True:
                    n = fh.readinto(buf)
                    if not n:
                        break
                    count += buf[:n].count(b"\n")
        except (IOError, OSError):
            pass
        return count


# ═══════════════════════════════════════════════════════════════════════════════
#  WordlistDownloader QThread
# ═══════════════════════════════════════════════════════════════════════════════

class WordlistDownloader(BaseWorker):
    """
    Downloads wordlist files from the internet with progress reporting.

    Signals:
        progress(int)           — 0-100 download progress
        log_message(str, str)   — (tag, message)
        finished(bool)          — True on success
    """

    def __init__(self, url: str, name: str, output_dir: str | None = None,
                 parent=None):
        super().__init__()
        self.url        = url
        self.name       = name
        self.output_dir = output_dir or str(WORDLISTS_DIR)
        self._stop      = False

    @classmethod
    def from_preset(cls, preset_index: int,
                    output_dir: str | None = None,
                    parent=None) -> "WordlistDownloader":
        """Create a downloader from the built-in WORDLIST_URLS presets."""
        if preset_index >= len(WORDLIST_URLS):
            raise IndexError(f"No preset at index {preset_index}")
        entry = WORDLIST_URLS[preset_index]
        inst = cls(entry["url"], entry["name"], output_dir, parent)
        inst._filename = entry["filename"]
        return inst

    def run(self):
        self._stop = False
        filename   = getattr(self, "_filename", None)
        if not filename:
            # Derive filename from URL
            filename = self.url.split("/")[-1].split("?")[0] or "wordlist.txt"
            if not filename.endswith(".txt"):
                filename += ".txt"

        os.makedirs(self.output_dir, exist_ok=True)
        out_path = os.path.join(self.output_dir, filename)

        self._safe_emit("log_message", "DOWNLOAD",
            f"Downloading: {self.name}")
        self._safe_emit("log_message", "DOWNLOAD", f"URL: {self.url}")
        self._safe_emit("log_message", "DOWNLOAD", f"Output: {out_path}")
        self._safe_emit("progress", 0)

        tmp_path = out_path + ".tmp"
        try:
            req = urllib.request.Request(
                self.url,
                headers={"User-Agent": "Mozilla/5.0 DarkCrackerOPS/2.0"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                total = int(resp.headers.get("Content-Length", 0))
                downloaded = 0
                chunk_size = 65536  # 64 KB

                start_t = time.time()
                with open(tmp_path, "wb") as fh:
                    while not self._stop:
                        chunk = resp.read(chunk_size)
                        if not chunk:
                            break
                        fh.write(chunk)
                        downloaded += len(chunk)

                        if total > 0:
                            pct = min(99, int((downloaded / total) * 100))
                            self._safe_emit("progress", pct)

                        # Speed calculation
                        elapsed = time.time() - start_t
                        if elapsed > 0.5:
                            speed = downloaded / elapsed
                            if speed > 1_048_576:
                                speed_str = f"{speed / 1_048_576:.1f} MB/s"
                            else:
                                speed_str = f"{speed / 1024:.1f} KB/s"
                            self._safe_emit("log_message", "DOWNLOAD",
                                f"Progress: {downloaded // 1024:,} KB | {speed_str}")

        except Exception as exc:
            self._safe_emit("log_message", "ERROR", f"Download failed: {exc}")
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            self._safe_emit("finished", False)
            return

        if self._stop:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            self._safe_emit("log_message", "DOWNLOAD", "Download cancelled")
            self._safe_emit("finished", False)
            return

        # Rename temp to final
        try:
            if os.path.exists(out_path):
                os.remove(out_path)
            os.rename(tmp_path, out_path)
        except OSError as exc:
            self._safe_emit("log_message", "ERROR", f"Failed to save file: {exc}")
            self._safe_emit("finished", False)
            return

        # Count lines for confirmation
        wm    = WordlistManager()
        count = wm._count_lines_fast(out_path)
        size  = os.path.getsize(out_path)
        self._safe_emit("log_message", "DOWNLOAD",
            f"Complete: {filename} — {count:,} entries, "
            f"{size // 1024:,} KB")
        self._safe_emit("progress", 100)
        self._safe_emit("finished", True)

    def _safe_emit(self, sig, *a):
        pass

    def stop(self) -> None:
        """Cancel download."""
        self._stop = True
