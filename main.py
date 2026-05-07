#!/usr/bin/env python3
"""
DARK CRACKER OPS — Generation 2  |  Automated CLI Edition
Entry point.

Usage:
    sudo python3 main.py                    # Interactive automated CLI
    sudo python3 main.py --headless --help  # Headless / scripted mode
    sudo python3 main.py --menu             # Legacy numbered-menu CLI
"""
import sys
import os

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# ── Root check ────────────────────────────────────────────────────────────────
try:
    from core.utils import is_root
    if not is_root():
        print("\n[!] DARK CRACKER OPS requires root privileges.")
        print("[!] Run: sudo python3 main.py\n")
        sys.exit(1)
except ImportError:
    if os.geteuid() != 0:
        print("[!] Run as root: sudo python3 main.py")
        sys.exit(1)

# ── Ensure application directories ───────────────────────────────────────────
try:
    from core.config import ensure_dirs
    ensure_dirs()
except Exception as e:
    print(f"[WARN] Could not create config dirs: {e}", file=sys.stderr)

# ── Headless / scripted mode ──────────────────────────────────────────────────
if "--headless" in sys.argv:
    try:
        from modules.headless import parse_args, run_headless
        sys.exit(run_headless(parse_args()))
    except ImportError as e:
        print(f"[!] Headless mode unavailable: {e}")
        sys.exit(1)

# ── Legacy numbered-menu CLI ──────────────────────────────────────────────────
if "--menu" in sys.argv:
    try:
        from cli.menus import main_menu
        main_menu()
        sys.exit(0)
    except ImportError as e:
        print(f"[!] Menu mode unavailable: {e}")
        sys.exit(1)

# ── Automated startup ─────────────────────────────────────────────────────────
from cli.colors import cyan, green, red, yellow, bold, dim, RESET


def _detect_adapters() -> list:
    """Return list of wireless interface dicts via InterfaceManager."""
    try:
        from modules.interface_manager import InterfaceManager
        return InterfaceManager().detect_interfaces()
    except Exception as e:
        print(f"  {red('[!]')} InterfaceManager error: {e}")
        return []


def _pick_adapter(adapters: list) -> str:
    """Show adapter list and return the chosen interface name."""
    if not adapters:
        manual = input(f"  {cyan('▶')} No adapters detected. Enter interface name: ").strip()
        return manual or "wlan0"

    if len(adapters) == 1:
        iface = adapters[0]["name"]
        print(f"  {green('✔')}  Auto-selected adapter: {cyan(iface)}")
        return iface

    print(f"\n  {'#':<4}  {'INTERFACE':<14}  {'MODE':<12}  MONITOR")
    print("  " + "─" * 45)
    for i, a in enumerate(adapters, 1):
        mon = green("YES") if a.get("supports_monitor") else red("no")
        print(f"  {cyan(str(i)):<4}  {a['name']:<14}  {a.get('mode','?'):<12}  {mon}")

    while True:
        try:
            raw = input(f"\n  {cyan('▶')} Select adapter [1-{len(adapters)}]: ").strip()
            idx = int(raw) - 1
            if 0 <= idx < len(adapters):
                return adapters[idx]["name"]
            print(f"  Enter a number between 1 and {len(adapters)}.")
        except (ValueError, EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)


def _show_banner() -> None:
    print(f"""{bold(cyan('''
██████╗  █████╗ ██████╗ ██╗  ██╗     ██████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗
██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝    ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██║  ██║███████║██████╔╝█████╔╝     ██║     ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝
██║  ██║██╔══██║██╔══██╗██╔═██╗     ██║     ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
██████╔╝██║  ██║██║  ██║██║  ██╗    ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
'''))}
{dim('  Generation 2  |  Fully Automated Offensive Security Platform')}
{dim('  Authorized Penetration Testing Only')}
""")


def main() -> None:
    _show_banner()

    # ── Adapter selection ─────────────────────────────────────────────────────
    print(cyan("  Detecting wireless adapters…"))
    adapters = _detect_adapters()
    iface    = _pick_adapter(adapters)
    print(f"  {green('✔')}  Using: {bold(cyan(iface))}")

    # ── Mode selection (only question asked after adapter) ────────────────────
    print(f"""
  {cyan('[1]')}  WiFi Attack        — full automated attack pipeline
  {cyan('[2]')}  Wordlist Generator — custom password list builder
  {dim('[0]')}  Exit
""")

    while True:
        try:
            raw = input(f"  {cyan('▶')} Select [0-2]: ").strip()
            choice = int(raw)
            if 0 <= choice <= 2:
                break
            print("  Enter 0, 1, or 2.")
        except (ValueError, EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

    if choice == 0:
        print(f"\n  {dim('Goodbye.')}\n")
        sys.exit(0)

    elif choice == 1:
        from cli.automation import WiFiAutomation
        WiFiAutomation(interface=iface).run()

    elif choice == 2:
        from cli.wordlist_generator import run_wordlist_generator
        run_wordlist_generator()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Interrupted. Goodbye.\n")
        sys.exit(0)
