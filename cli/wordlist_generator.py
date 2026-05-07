"""
cli/wordlist_generator.py — Interactive wordlist generator.
Asks for base word, country code, year range, number range, and symbols,
then generates all combinations and saves to a file.
"""
import os
import itertools
import time
from typing import List


def _ask(prompt: str, default: str = "") -> str:
    dflt = f" [{default}]" if default else ""
    try:
        val = input(f"  ▶ {prompt}{dflt}: ").strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        print()
        return default


def _ask_yn(prompt: str, default: bool = True) -> bool:
    hint = "[Y/n]" if default else "[y/N]"
    try:
        val = input(f"  ▶ {prompt} {hint}: ").strip().lower()
        if not val:
            return default
        return val in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return default


def run_wordlist_generator() -> None:
    """Full interactive wordlist generator menu."""
    print("\n" + "=" * 60)
    print("  WORDLIST GENERATOR")
    print("=" * 60 + "\n")

    # ── Gather parameters ──────────────────────────────────────────────────────
    base_word   = _ask("Base word or name (e.g. Tariq, Ahmed, WiFiHome)", "")
    country     = _ask("Country code (e.g. IQ, SA, US) or leave blank", "")
    year_range  = _ask("Year range (e.g. 2000-2025) or leave blank", "")
    num_range   = _ask("Number range (e.g. 1-9999) or leave blank", "")
    use_symbols = _ask_yn("Include common symbols (!@#$%)?", default=True)
    use_leet    = _ask_yn("Include leet substitutions (a→4, e→3)?", default=True)
    use_iraqi   = _ask_yn("Generate Iraqi phone numbers? (077/078/079/075/073/074/071)", default=False)
    use_dates   = _ask_yn("Generate date-based passwords? (DDMMYYYY etc)", default=False)

    if not base_word and not use_iraqi:
        print("  No base word provided — aborting.")
        return

    # ── Build component lists ──────────────────────────────────────────────────
    bases: List[str] = _expand_base(base_word, use_leet) if base_word else []
    years: List[str] = _parse_range_strs(year_range, 1990, 2025)
    nums:  List[str] = _parse_range_strs(num_range, 1, 9999)
    symbols: List[str] = ["!", "@", "#", "$", "%", ".", "*", "_", "?"] if use_symbols else [""]
    country_variants: List[str] = _country_variants(country)

    # ── SSID mutations via WordlistManager ─────────────────────────────────────
    wlm_mutations: List[str] = []
    if base_word:
        try:
            import sys
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            from modules.wordlist_manager import WordlistManager
            wlm_mutations = WordlistManager().generate_ssid_mutations(base_word)
            print(f"  ✔  WordlistManager generated {len(wlm_mutations)} base mutations.")
        except Exception as e:
            print(f"  ⚠  WordlistManager unavailable ({e}) — using built-in generator only.")

    # ── Generate combinations ──────────────────────────────────────────────────
    passwords: set = set()

    # Start with WLM mutations
    passwords.update(wlm_mutations)

    # base alone
    for b in bases:
        passwords.add(b)
        passwords.add(b.lower())
        passwords.add(b.upper())
        passwords.add(b.capitalize())

    # base + country
    for b in bases:
        for c in country_variants:
            passwords.add(f"{b}{c}")
            passwords.add(f"{c}{b}")
            passwords.add(f"{b}_{c}")

    # base + year
    for b in bases:
        for y in years:
            passwords.add(f"{b}{y}")
            passwords.add(f"{y}{b}")

    # base + number suffix
    for b in bases:
        for n in nums[:2000]:  # cap to avoid explosion
            passwords.add(f"{b}{n}")

    # base + symbol
    for b in bases:
        for s in symbols:
            if s:
                passwords.add(f"{b}{s}")
                passwords.add(f"{s}{b}")

    # base + year + symbol
    for b in bases:
        for y in years[:20]:
            for s in symbols[:4]:
                if s:
                    passwords.add(f"{b}{y}{s}")
                    passwords.add(f"{b}{s}{y}")

    # base + country + year
    for b in bases:
        for c in country_variants:
            for y in years[:10]:
                passwords.add(f"{b}{c}{y}")

    # base + num + symbol
    for b in bases:
        for n in nums[:100]:
            for s in symbols[:3]:
                if s:
                    passwords.add(f"{b}{n}{s}")

    # WiFi common patterns
    for b in bases:
        for suffix in ["", "123", "1234", "12345", "2024", "2025", "wifi",
                       "net", "home", "@home", "#123", "pass", "password"]:
            passwords.add(f"{b}{suffix}")
        passwords.add(f"wifi{b}")
        passwords.add(f"{b}wifi")

    # Remove empties and filter realistic lengths (8-63 chars for WPA)
    passwords = {p for p in passwords if 8 <= len(p) <= 63}

    # ── Iraqi phone numbers ───────────────────────────────────────────────────
    if use_iraqi:
        print("  ▶  Generating Iraqi phone numbers…")
        iraqi_count = 0
        for num in _iraqi_phones():
            if 8 <= len(num) <= 63:
                passwords.add(num)
                iraqi_count += 1
        print(f"  ✔  Added {iraqi_count:,} Iraqi phone numbers")

    # ── Date-based passwords ──────────────────────────────────────────────────
    if use_dates:
        print("  ▶  Generating date-based passwords…")
        year_lo, year_hi = 1990, 2025
        if year_range:
            try:
                parts = year_range.split("-")
                year_lo = int(parts[0].strip())
                year_hi = int(parts[1].strip()) if len(parts) > 1 else year_lo
            except Exception:
                pass
        date_count = 0
        for pwd in _date_passwords(range(year_lo, year_hi + 1)):
            if 8 <= len(pwd) <= 63:
                passwords.add(pwd)
                date_count += 1
        print(f"  ✔  Added {date_count:,} date-based passwords")

    # Final filter
    passwords = {p for p in passwords if 8 <= len(p) <= 63}

    # ── Preview mode ──────────────────────────────────────────────────────────
    if passwords:
        print(f"\n  Preview — first 20 passwords (sorted):")
        print("  " + "-" * 40)
        for pwd in sorted(passwords)[:20]:
            print(f"  {pwd}")
        print("  " + "-" * 40)

    # ── Crack time estimate ───────────────────────────────────────────────────
    total = len(passwords)
    speed = 1_000_000  # 1M/s
    secs  = total / speed if speed > 0 else 0
    hours = int(secs // 3600)
    mins  = int((secs % 3600) // 60)
    s_rem = int(secs % 60)
    print(f"\n  Passwords generated : {total:,}")
    print(f"  Estimated crack time @ 1M/s: {hours}h {mins}m {s_rem}s")

    # ── Confirm save ──────────────────────────────────────────────────────────
    if not _ask_yn("Save to file?", default=True):
        print("  Aborted — no file written.")
        return

    # ── Save to file ───────────────────────────────────────────────────────────
    ts        = time.strftime("%Y%m%d_%H%M%S")
    safe_base = "".join(c for c in (base_word or "wordlist") if c.isalnum())[:20]
    out_path  = os.path.join(os.getcwd(), f"wordlist_{safe_base}_{ts}.txt")

    try:
        with open(out_path, "w", encoding="utf-8") as f:
            for pwd in sorted(passwords):
                f.write(pwd + "\n")
        print(f"\n  ✔  Generated {len(passwords):,} passwords")
        print(f"  ✔  Saved to : {out_path}\n")
    except Exception as e:
        print(f"\n  ✖  Could not write file: {e}\n")


# ── Helpers ────────────────────────────────────────────────────────────────────

_LEET_MAP = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}


def _expand_base(word: str, use_leet: bool) -> List[str]:
    variants = {word, word.lower(), word.upper(), word.capitalize()}
    if use_leet:
        leet = word.lower()
        for k, v in _LEET_MAP.items():
            leet = leet.replace(k, v)
        variants.add(leet)
        # Mixed case + leet
        variants.add(leet.capitalize())
    return list(variants)


def _parse_range_strs(spec: str, default_lo: int, default_hi: int) -> List[str]:
    """Parse 'lo-hi' range spec into string list. Returns empty list if spec is blank."""
    if not spec:
        return []
    try:
        if "-" in spec:
            parts = spec.split("-")
            lo = int(parts[0].strip())
            hi = int(parts[1].strip())
        else:
            lo = hi = int(spec.strip())
        return [str(i) for i in range(lo, min(hi + 1, lo + 10000))]
    except (ValueError, IndexError):
        return []


def _iraqi_phones():
    """
    Generator for all Iraqi mobile numbers.
    Format: 07XXXXXXXX (10 digits total).
    Prefixes: 077, 078, 079, 075, 073, 074, 071.
    """
    prefixes = ['077', '078', '079', '075', '073', '074', '071']
    for prefix in prefixes:
        for n in range(10_000_000):
            yield f"{prefix}{n:07d}"


def _date_passwords(year_range) -> List[str]:
    """
    Generate date-based passwords for DDMMYYYY, MMDDYYYY, DDMMYY formats.
    Also combines dates with common WiFi words.
    """
    common_words = ["home", "wifi", "net", "pass", "network", "internet"]
    results: List[str] = []
    for year in year_range:
        for month in range(1, 13):
            for day in range(1, 32):
                # Basic date strings
                ddmmyyyy = f"{day:02d}{month:02d}{year}"
                mmddyyyy = f"{month:02d}{day:02d}{year}"
                ddmmyy   = f"{day:02d}{month:02d}{str(year)[2:]}"
                for date_str in (ddmmyyyy, mmddyyyy, ddmmyy):
                    results.append(date_str)
                    for word in common_words:
                        results.append(f"{date_str}{word}")
                        results.append(f"{word}{date_str}")
    return results


def _country_variants(code: str) -> List[str]:
    """Return country code variants: original, lower, upper."""
    if not code:
        return [""]
    return [code, code.lower(), code.upper()]


# ── Generator alias functions (required by test harness) ─────────────────────

def _gen_iraqi_phones(prefixes=None, sample: bool = False):
    """Generator for Iraqi phone numbers filtered to given prefixes."""
    all_prefixes = prefixes if prefixes else ['077', '078', '079', '075', '073', '074', '071']
    for prefix in all_prefixes:
        limit = 100 if sample else 10_000_000
        for n in range(limit):
            yield f"{prefix}{n:07d}"


def _gen_dates(years=None, use_words: bool = True):
    """Generator for date-based password strings."""
    if years is None:
        years = range(1990, 2026)
    common_words = ["home", "wifi", "net", "pass", "network"] if use_words else []
    for year in years:
        for month in range(1, 13):
            for day in range(1, 32):
                ddmmyyyy = f"{day:02d}{month:02d}{year}"
                mmddyyyy = f"{month:02d}{day:02d}{year}"
                ddmmyy   = f"{day:02d}{month:02d}{str(year)[2:]}"
                for date_str in (ddmmyyyy, mmddyyyy, ddmmyy):
                    yield date_str
                    for word in common_words:
                        yield f"{date_str}{word}"
                        yield f"{word}{date_str}"


def _gen_ssid_mutations(ssid: str):
    """Generator for SSID-based password mutations."""
    try:
        from modules.wordlist_manager import WordlistManager
        yield from WordlistManager().generate_ssid_mutations(ssid)
    except Exception:
        pass
    # Built-in mutations
    for suffix in ["", "123", "1234", "12345", "2024", "2025", "wifi",
                   "net", "home", "@home", "#123", "pass", "password"]:
        yield f"{ssid}{suffix}"
        if suffix:
            yield f"{suffix}{ssid}"
    yield ssid.lower()
    yield ssid.upper()
    yield ssid.capitalize()


def _gen_arabic_patterns(base: str = ""):
    """Generator for common Arabic/Middle-Eastern password patterns."""
    arabic_numbers = ["١٢٣٤", "٢٠٢٤", "٢٠٢٥"]
    patterns = ["home", "wifi", "internet", "شبكة", "بيت", "سر"]
    for p in patterns:
        if base:
            yield f"{base}{p}"
            yield f"{p}{base}"
        yield p
    for n in arabic_numbers:
        if base:
            yield f"{base}{n}"


def _gen_common_patterns(base: str = ""):
    """Generator for common WiFi password patterns."""
    suffixes = ["123", "1234", "12345", "123456", "2024", "2025",
                "wifi", "home", "pass", "password", "net", "router"]
    for s in suffixes:
        if base:
            yield f"{base}{s}"
            yield f"{s}{base}"
        yield s
    if base:
        yield base
        yield base.lower()
        yield base.upper()
        yield base.capitalize()


def _gen_custom_pattern(pattern: str, charset: str = "0123456789"):
    """Generator that fills '?' placeholders in a pattern from charset."""
    import itertools
    placeholders = [i for i, c in enumerate(pattern) if c == '?']
    n = len(placeholders)
    if n == 0:
        yield pattern
        return
    for combo in itertools.product(charset, repeat=n):
        result = list(pattern)
        for pos, ch in zip(placeholders, combo):
            result[pos] = ch
        yield "".join(result)
