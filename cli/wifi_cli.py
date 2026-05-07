"""
cli/wifi_cli.py — WiFi attack menu: scan, auto-attack, evil twin, crack, wordlist manager.
"""
import threading
import time
from typing import List, Optional

from cli.display import (
    print_section, print_menu, print_table,
    info, success_msg, warn_msg, error_msg, log as cli_log,
    get_input, ask_yn, wait_enter, get_choice, safe_print,
    print_progress, Spinner
)
from cli.colors import cyan, green, red, yellow, bold, dim, gray, RESET


# ── Shared state ───────────────────────────────────────────────────────────────
_networks: List[dict] = []
_scan_lock = threading.Lock()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _get_interfaces() -> List[str]:
    try:
        from modules.interface_manager import InterfaceManager
        ifaces = InterfaceManager().detect_interfaces()
        return [i["name"] for i in ifaces if i.get("name")]
    except Exception:
        return []


def _pick_interface() -> Optional[str]:
    ifaces = _get_interfaces()
    if not ifaces:
        warn_msg("No wireless interfaces detected.")
        manual = get_input("Enter interface name manually", "wlan0")
        return manual or None
    if len(ifaces) == 1:
        info(f"Using interface: {cyan(ifaces[0])}")
        return ifaces[0]
    print_section("SELECT INTERFACE")
    for i, name in enumerate(ifaces, 1):
        safe_print(f"  {cyan(f'[{i}]')}  {name}")
    choice = get_choice(len(ifaces), "Interface")
    if choice and 1 <= choice <= len(ifaces):
        return ifaces[choice - 1]
    return None


def _pick_network() -> Optional[dict]:
    """Display the cached network list and let the user pick one."""
    with _scan_lock:
        nets = list(_networks)
    if not nets:
        warn_msg("No networks in memory — run a scan first.")
        return None

    headers = ["#", "SSID", "BSSID", "CH", "ENC", "PWR", "WPS"]
    rows = []
    for i, n in enumerate(nets, 1):
        rows.append([
            str(i),
            n.get("ssid", "<hidden>"),
            n.get("bssid", ""),
            str(n.get("channel", "")),
            n.get("enc", ""),
            str(n.get("power", "")),
            green("YES") if n.get("wps") else dim("no"),
        ])
    print_section("DISCOVERED NETWORKS")
    print_table(headers, rows)

    choice = get_choice(len(nets), "Select target (0=cancel)")
    if not choice:
        return None
    if 1 <= choice <= len(nets):
        return nets[choice - 1]
    return None


def _pick_wordlist() -> str:
    """Return a wordlist path chosen by the user."""
    try:
        from modules.wordlist_manager import WordlistManager
        local = WordlistManager().list_local()
    except Exception:
        local = []

    from core.config import DEFAULT_WORDLISTS
    all_lists = list({p for p in DEFAULT_WORDLISTS + local if p})

    available = [p for p in all_lists if __import__("os").path.isfile(p)]
    if not available:
        warn_msg("No wordlists found. Enter path manually.")
        return get_input("Wordlist path", "/usr/share/wordlists/rockyou.txt")

    print_section("SELECT WORDLIST")
    for i, p in enumerate(available, 1):
        safe_print(f"  {cyan(f'[{i}]')}  {p}")
    safe_print(f"  {cyan(f'[{len(available)+1}]')}  Enter custom path")

    choice = get_choice(len(available) + 1, "Wordlist")
    if choice and 1 <= choice <= len(available):
        return available[choice - 1]
    return get_input("Wordlist path", "/usr/share/wordlists/rockyou.txt")


# ── Sub-menus ──────────────────────────────────────────────────────────────────

def _scan_networks() -> None:
    """Scan for nearby WiFi networks and populate _networks."""
    iface = _pick_interface()
    if not iface:
        return

    dur = int(get_input("Scan duration (seconds)", "30") or "30")

    print_section("WIFI SCAN")
    info(f"Scanning on {cyan(iface)} for {cyan(str(dur))}s  (Ctrl-C to stop early)")
    safe_print()

    stop_event = threading.Event()

    def _on_networks(nets: list) -> None:
        with _scan_lock:
            _networks.clear()
            _networks.extend(nets)
        safe_print(f"\r  {cyan('Networks found:')} {green(str(len(nets)))}  ", end="", flush=True)

    def _on_log(tag: str, msg: str) -> None:
        cli_log(tag, msg)

    def _on_done() -> None:
        stop_event.set()

    try:
        from modules.wifi_scanner import WiFiScanner
        scanner = WiFiScanner(
            interface  = iface,
            on_networks= _on_networks,
            on_log     = _on_log,
            on_done    = _on_done,
            duration   = dur,
        )
        scanner.start()
        try:
            stop_event.wait(timeout=dur + 10)
        except KeyboardInterrupt:
            pass
        scanner.stop()
        scanner.join(timeout=5)
    except Exception as e:
        error_msg(f"Scan error: {e}")
        wait_enter()
        return

    safe_print()
    with _scan_lock:
        nets = list(_networks)

    if not nets:
        warn_msg("No networks found. Check interface and monitor mode.")
        wait_enter()
        return

    headers = ["#", "SSID", "BSSID", "CH", "ENC", "SIGNAL", "WPS"]
    rows = []
    for i, n in enumerate(nets, 1):
        rows.append([
            str(i),
            n.get("ssid", "<hidden>"),
            n.get("bssid", ""),
            str(n.get("channel", "")),
            n.get("enc", ""),
            str(n.get("power", "")) + " dBm",
            green("YES") if n.get("wps") else dim("no"),
        ])
    print_table(headers, rows)
    success_msg(f"Scan complete — {len(nets)} networks discovered.")
    wait_enter()


def _auto_attack() -> None:
    """Guided auto-attack: pick network → configure → launch."""
    target = _pick_network()
    if not target:
        if ask_yn("No networks cached. Run a scan now?"):
            _scan_networks()
            target = _pick_network()
        if not target:
            return

    iface = _pick_interface()
    if not iface:
        return

    print_section("ATTACK CONFIGURATION")
    safe_print(f"  Target  : {cyan(target.get('ssid','?'))}  {dim(target.get('bssid',''))}")
    safe_print(f"  Channel : {cyan(str(target.get('channel','?')))}")
    safe_print(f"  Enc     : {cyan(target.get('enc','?'))}")
    safe_print()

    # Attack mode
    modes = ["Auto (recommended)", "WPA2", "WEP", "WPA3", "WPS"]
    print_menu("ATTACK MODE", modes)
    mode_choice = get_choice(len(modes))
    if not mode_choice:
        return
    mode_map = {1: "Auto", 2: "WPA2", 3: "WEP", 4: "WPA3", 5: "WPS"}
    mode = mode_map.get(mode_choice, "Auto")

    wordlist = ""
    if mode not in ("WEP", "WPS"):
        wordlist = _pick_wordlist()

    timeout = int(get_input("Attack timeout (seconds)", "300") or "300")

    config = {
        "interface": iface,
        "bssid":     target.get("bssid", ""),
        "ssid":      target.get("ssid", ""),
        "channel":   int(target.get("channel", 1)),
        "enc":       target.get("enc", "WPA2"),
        "wordlist":  wordlist,
        "mode":      mode,
        "timeout":   timeout,
    }

    print_section("LAUNCHING ATTACK")
    info(f"Mode: {cyan(mode)}  |  Target: {cyan(target.get('ssid','?'))}")
    safe_print(dim("  [Ctrl-C to abort]"))
    safe_print()

    stop_event = threading.Event()
    capture_path = [None]

    def _on_log(tag: str, msg: str) -> None:
        cli_log(tag, msg)

    def _on_progress(pct: int) -> None:
        print_progress(pct, "Attack progress")

    def _on_phase(phase: str) -> None:
        safe_print(f"\n  {cyan('▶')}  {bold(phase)}")

    def _on_capture(path: str, ctype: str) -> None:
        capture_path[0] = path
        success_msg(f"Capture saved: {path} ({ctype})")

    def _on_finished(success: bool) -> None:
        stop_event.set()
        if success:
            success_msg("Attack phase complete — ready for cracking.")
        else:
            warn_msg("Attack finished (no capture obtained).")

    def _on_pmkid(path: str) -> None:
        capture_path[0] = path
        success_msg(f"PMKID hash file: {path}")

    def _on_handshake(path: str) -> None:
        capture_path[0] = path
        success_msg(f"Handshake capture: {path}")

    def _on_wps_pin(result: str) -> None:
        success_msg(f"WPS result: {result}")
        stop_event.set()

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
        try:
            stop_event.wait(timeout=timeout + 30)
        except KeyboardInterrupt:
            warn_msg("Aborted by user.")
        engine.stop()
        engine.join(timeout=10)
    except Exception as e:
        error_msg(f"Attack error: {e}")
        wait_enter()
        return

    safe_print()
    # Offer to crack if a capture was obtained
    if capture_path[0] and wordlist:
        if ask_yn("Capture obtained. Launch cracker now?"):
            _crack_file(capture_path[0], wordlist)
    wait_enter()


def _evil_twin() -> None:
    """Set up and run an evil twin AP."""
    print_section("EVIL TWIN AP")
    warn_msg("Evil Twin creates a rogue AP with a captive portal to capture credentials.")
    if not ask_yn("Continue?"):
        return

    target = _pick_network()
    if not target:
        # Allow manual entry
        ssid    = get_input("Target SSID", "")
        bssid   = get_input("Target BSSID (AA:BB:CC:DD:EE:FF)", "")
        channel = int(get_input("Channel", "6") or "6")
        target  = {"ssid": ssid, "bssid": bssid, "channel": channel}

    ap_iface  = get_input("AP interface (creates hotspot)", "wlan0")
    mon_iface = get_input("Monitor interface (for deauth)", "wlan1")

    print_section("STARTING EVIL TWIN")
    info(f"Cloning: {cyan(target.get('ssid','?'))}  CH {cyan(str(target.get('channel','?')))}")
    safe_print(dim("  [Ctrl-C to stop]"))
    safe_print()

    stop_event = threading.Event()

    def _on_log(tag: str, msg: str) -> None:
        cli_log(tag, msg)

    def _on_client(client: dict) -> None:
        safe_print(f"\n  {cyan('CLIENT')}  {client.get('mac','')}  {client.get('ip','')}")

    def _on_cred(cred: dict) -> None:
        safe_print(f"\n  {green('CREDENTIAL')}  {cred.get('username','')}:{cred.get('password','')}")

    def _on_deauth(count: int) -> None:
        safe_print(f"\r  {cyan('Deauth packets sent:')} {count}  ", end="", flush=True)

    def _on_finished(ok: bool) -> None:
        stop_event.set()

    try:
        from modules.evil_twin import EvilTwin
        et = EvilTwin(
            on_log          = _on_log,
            on_client       = _on_client,
            on_cred         = _on_cred,
            on_deauth_count = _on_deauth,
            on_finished     = _on_finished,
        )
        et.clone_ap(
            ssid       = target.get("ssid", ""),
            bssid      = target.get("bssid", ""),
            channel    = int(target.get("channel", 6)),
            ap_iface   = ap_iface,
            mon_iface  = mon_iface,
        )
        et.start()
        try:
            stop_event.wait(timeout=3600)
        except KeyboardInterrupt:
            warn_msg("Stopping evil twin…")
        et.stop()
        et.join(timeout=10)
    except Exception as e:
        error_msg(f"Evil twin error: {e}")
    wait_enter()


def _crack_capture(cap_path: str = "", wordlist: str = "") -> None:
    """Crack a capture file interactively."""
    print_section("CRACK CAPTURE FILE")
    if not cap_path:
        cap_path = get_input("Capture file path (.hc22000 or .cap)", "")
    if not cap_path:
        return
    if not wordlist:
        wordlist = _pick_wordlist()
    _crack_file(cap_path, wordlist)
    wait_enter()


def _crack_file(cap_path: str, wordlist: str) -> None:
    """Run the cracker on cap_path with wordlist; blocking until done."""
    print_section("CRACKING")
    info(f"File     : {cyan(cap_path)}")
    info(f"Wordlist : {cyan(wordlist)}")
    safe_print()

    stop_event = threading.Event()

    def _on_log(tag: str, msg: str) -> None:
        cli_log(tag, msg)

    def _on_progress(pct: int) -> None:
        print_progress(pct, "Cracking")

    def _on_speed(speed: str) -> None:
        safe_print(f"\r  {cyan('Speed:')} {speed:<20}", end="", flush=True)

    def _on_password(pwd: str) -> None:
        safe_print()
        success_msg(f"PASSWORD FOUND: {bold(green(pwd))}")
        stop_event.set()

    def _on_finished(ok: bool) -> None:
        if not stop_event.is_set():
            if ok:
                success_msg("Cracking complete — check output above.")
            else:
                warn_msg("Cracking finished — password not found in wordlist.")
        stop_event.set()

    try:
        from modules.cracker import Cracker
        cracker = Cracker(
            on_log      = _on_log,
            on_progress = _on_progress,
            on_speed    = _on_speed,
            on_password = _on_password,
            on_finished = _on_finished,
        )
        cracker.capture_file = cap_path
        cracker.wordlist     = wordlist
        cracker.start()
        try:
            stop_event.wait(timeout=7200)
        except KeyboardInterrupt:
            warn_msg("Cracking aborted.")
        cracker.stop()
        cracker.join(timeout=10)
    except Exception as e:
        error_msg(f"Cracker error: {e}")
    safe_print()


def _wordlist_manager() -> None:
    """Wordlist management sub-menu."""
    while True:
        print_menu("WORDLIST MANAGER", [
            "List local wordlists",
            "Generate SSID mutations",
            "Estimate crack time",
            "Download wordlist",
        ])
        choice = get_choice(4)
        if choice is None:
            continue
        if choice == 0:
            break
        elif choice == 1:
            _wl_list_local()
        elif choice == 2:
            _wl_generate_mutations()
        elif choice == 3:
            _wl_estimate_time()
        elif choice == 4:
            _wl_download()


def _wl_list_local() -> None:
    print_section("LOCAL WORDLISTS")
    try:
        from modules.wordlist_manager import WordlistManager
        paths = WordlistManager().list_local()
        if not paths:
            warn_msg("No wordlists found in default locations.")
        else:
            for p in paths:
                size = ""
                try:
                    import os
                    size = f" {dim(f'({os.path.getsize(p) // 1024} KB)')}"
                except Exception:
                    pass
                safe_print(f"  {cyan('●')}  {p}{size}")
    except Exception as e:
        error_msg(str(e))
    wait_enter()


def _wl_generate_mutations() -> None:
    ssid = get_input("SSID to generate mutations for", "")
    if not ssid:
        return
    try:
        from modules.wordlist_manager import WordlistManager
        mutations = WordlistManager().generate_ssid_mutations(ssid)
        print_section(f"MUTATIONS FOR: {ssid}")
        for m in mutations[:50]:
            safe_print(f"  {m}")
        if len(mutations) > 50:
            safe_print(f"  {dim(f'... and {len(mutations)-50} more')}")
        safe_print()
        if ask_yn("Save to file?"):
            import os
            from core.config import WORDLISTS_DIR
            path = str(WORDLISTS_DIR / f"mutations_{ssid[:20]}.txt")
            with open(path, "w") as f:
                f.write("\n".join(mutations))
            success_msg(f"Saved: {path}")
    except Exception as e:
        error_msg(str(e))
    wait_enter()


def _wl_estimate_time() -> None:
    wl = _pick_wordlist()
    if not wl:
        return
    try:
        from modules.wordlist_manager import WordlistManager
        result = WordlistManager().estimate_crack_time(wl)
        print_section("CRACK TIME ESTIMATE")
        for k, v in result.items():
            safe_print(f"  {cyan(k):<25}  {v}")
    except Exception as e:
        error_msg(str(e))
    wait_enter()


def _wl_download() -> None:
    try:
        from modules.wordlist_manager import WORDLIST_URLS, WordlistManager
    except Exception as e:
        error_msg(f"Wordlist manager unavailable: {e}")
        wait_enter()
        return

    print_section("DOWNLOAD WORDLIST")
    for i, wl in enumerate(WORDLIST_URLS, 1):
        safe_print(f"  {cyan(f'[{i}]')}  {wl['name']}")

    choice = get_choice(len(WORDLIST_URLS))
    if not choice or choice == 0:
        return

    selected = WORDLIST_URLS[choice - 1]
    info(f"Downloading: {selected['name']}")

    # WordlistDownloader needs subclassing; use direct urllib download instead
    try:
        import urllib.request
        from core.config import WORDLISTS_DIR
        dest = str(WORDLISTS_DIR / selected["filename"])
        with Spinner(f"Downloading {selected['name']}…"):
            urllib.request.urlretrieve(selected["url"], dest)
        success_msg(f"Saved: {dest}")
    except Exception as e:
        error_msg(f"Download failed: {e}")
    wait_enter()


def _passive_recon() -> None:
    """Run passive WiFi reconnaissance (beacons, probes, deauth, channel utilization)."""
    iface = _pick_interface()
    if not iface:
        return
    print_section("PASSIVE WIFI RECON")
    try:
        dur = int(get_input("Capture duration (seconds)", "60") or "60")
    except Exception:
        dur = 60

    try:
        from cli.wifi_recon import run_recon
        run_recon(interface=iface, duration=dur)
    except Exception as e:
        error_msg(f"Recon error: {e}")
    wait_enter()


# ── Top-level WiFi menu ────────────────────────────────────────────────────────

def wifi_menu() -> None:
    while True:
        print_menu("WIFI ATTACKS", [
            "Scan Networks         — discover nearby APs",
            "Auto Attack           — scan → pick → attack → crack",
            "Evil Twin             — rogue AP + captive portal",
            "Crack Capture File    — crack existing .hc22000 / .cap",
            "Wordlist Manager      — local lists, mutations, downloads",
            "Passive Recon         — beacons, probes, deauth, channel utilization",
        ])
        choice = get_choice(6)
        if choice is None:
            continue
        if choice == 0:
            break
        elif choice == 1:
            _scan_networks()
        elif choice == 2:
            _auto_attack()
        elif choice == 3:
            _evil_twin()
        elif choice == 4:
            _crack_capture()
        elif choice == 5:
            _wordlist_manager()
        elif choice == 6:
            _passive_recon()
