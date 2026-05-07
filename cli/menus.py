"""
cli/menus.py — Main menu entry point for DARK CRACKER OPS CLI.
"""
import shutil
import sys

from cli.display import (
    print_banner, print_menu, print_section,
    info, warn_msg, error_msg, success_msg,
    get_choice, wait_enter, safe_print, dim, cyan, green, red, yellow, gray
)
from cli.colors import BOLD, RESET, _FG_BCYAN, _FG_BRED, _FG_BGREEN, _FG_BYELLOW


def _status_line() -> str:
    """Build the header status line shown under the banner."""
    try:
        from core.config import TOOLS
        total   = len(TOOLS)
        missing = sum(1 for cmd in TOOLS.values() if not shutil.which(cmd))
        avail   = total - missing
        tool_s  = (
            f"{green(str(avail))}/{total} tools"
            if missing == 0
            else f"{yellow(str(avail))}/{total} tools {red(f'({missing} missing)')}"
        )
    except Exception:
        tool_s = dim("tools: unknown")

    try:
        from core.database import get_db
        db       = get_db()
        sessions = db.get_all_sessions()
        sess_s   = cyan(str(len(sessions))) + dim(" sessions")
    except Exception:
        sess_s = dim("db: unavailable")

    return f"  {tool_s}   {sess_s}   {cyan('root')} {green('✔')}"


def _disclaimer_check() -> bool:
    """Show disclaimer once; return False if user declines."""
    try:
        from core.config import DISCLAIMER_FILE
        if DISCLAIMER_FILE.exists():
            return True
    except Exception:
        pass

    print_section("LEGAL DISCLAIMER")
    safe_print(f"""
  {yellow('WARNING:')} This tool is designed for authorized penetration testing,
  security research, and educational purposes ONLY.

  {red('Unauthorized use against systems you do not own or have explicit')}
  {red('written permission to test is ILLEGAL and may result in criminal')}
  {red('prosecution under computer fraud laws.')}

  By continuing, you confirm:
    • You have explicit authorization to test the target systems.
    • You accept full legal responsibility for your actions.
    • The developers assume NO liability for misuse.
""")

    try:
        ans = input(f"  {cyan('▶')} I accept the terms above [yes/no]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False

    if ans != "yes":
        error_msg("Disclaimer not accepted. Exiting.")
        return False

    try:
        from core.config import DISCLAIMER_FILE
        DISCLAIMER_FILE.touch()
    except Exception:
        pass
    return True


def _settings_menu() -> None:
    """Settings and information sub-menu."""
    while True:
        print_menu("SETTINGS & INFO", [
            "System Health — tool availability check",
            "Database Info — session statistics",
            "Scheduler — manage scheduled tasks",
            "Missing Tools — install guidance",
            "About",
        ])
        choice = get_choice(5)
        if choice is None:
            continue
        if choice == 0:
            break
        elif choice == 1:
            _show_health()
        elif choice == 2:
            _show_db_info()
        elif choice == 3:
            _scheduler_menu()
        elif choice == 4:
            _show_missing_tools()
        elif choice == 5:
            _show_about()


def _show_health() -> None:
    print_section("SYSTEM HEALTH")
    try:
        from core.config import TOOLS
        rows = []
        for name, cmd in TOOLS.items():
            found = shutil.which(cmd) is not None
            status = green("● FOUND") if found else red("● MISSING")
            rows.append([name, cmd, status])
        from cli.display import print_table
        print_table(["TOOL", "COMMAND", "STATUS"], rows)
    except Exception as e:
        error_msg(str(e))
    wait_enter()


def _show_db_info() -> None:
    print_section("DATABASE INFO")
    try:
        from core.database import get_db
        db       = get_db()
        sessions = db.get_all_sessions()
        cracked  = sum(1 for s in sessions if s.get("result") == "success")
        hosts    = sum(s.get("hosts_found", 0) for s in sessions)
        safe_print(f"  Sessions  : {cyan(str(len(sessions)))}")
        safe_print(f"  Cracked   : {green(str(cracked))}")
        safe_print(f"  Hosts     : {cyan(str(hosts))}")
    except Exception as e:
        error_msg(str(e))
    wait_enter()


def _scheduler_menu() -> None:
    print_section("SCHEDULER")
    try:
        from modules.scheduler import Scheduler
        sched = Scheduler()
        tasks = sched.get_tasks()
        if not tasks:
            info("No scheduled tasks.")
        else:
            rows = []
            for t in tasks:
                rows.append([
                    t.get("id", "")[:8],
                    t.get("name", ""),
                    t.get("cron", ""),
                    green("ON") if t.get("enabled") else red("OFF"),
                ])
            from cli.display import print_table
            print_table(["ID", "NAME", "CRON", "STATUS"], rows)
    except Exception as e:
        error_msg(f"Scheduler unavailable: {e}")
    wait_enter()


def _show_missing_tools() -> None:
    print_section("MISSING TOOLS")
    try:
        from core.config import missing_tools
        missing = missing_tools()
        if not missing:
            success_msg("All tools are installed!")
        else:
            warn_msg(f"{len(missing)} tool(s) missing:")
            for t in missing:
                safe_print(f"    {red('✖')}  {t}")
            safe_print(f"\n  {dim('Install on Kali:')}  {cyan('sudo apt install aircrack-ng hashcat nmap hcxtools hostapd dnsmasq reaver')}")
    except Exception as e:
        error_msg(str(e))
    wait_enter()


def _show_about() -> None:
    print_section("ABOUT")
    try:
        from core.config import APP_NAME, APP_VERSION, APP_GEN
        safe_print(f"  {cyan(APP_NAME)}  {dim(f'v{APP_VERSION}')}  {dim(f'— {APP_GEN}')}")
    except Exception:
        safe_print(f"  {cyan('DARK CRACKER OPS')}  {dim('Generation 2')}")
    safe_print(f"""
  {dim('Platform  :')}  Offensive Security / Penetration Testing
  {dim('Interface :')}  Numbered-menu CLI
  {dim('Backend   :')}  Python 3  |  SQLite  |  aircrack-ng suite
  {dim('Author    :')}  DarkCracker Team
  {dim('License   :')}  For authorized use only
""")
    wait_enter()


# ── Main menu ──────────────────────────────────────────────────────────────────

_MENU_OPTIONS = [
    "WiFi Attacks         — scan, crack, evil twin, WPS",
    "Network              — host discovery, port scan, vuln scan",
    "Session History      — view sessions, generate reports",
    "Wordlist Generator   — custom password list builder",
    "Settings / Info      — tools, scheduler, database",
]


def main_menu() -> None:
    """Entry point — main numbered menu loop."""
    if not _disclaimer_check():
        sys.exit(0)

    while True:
        print_banner()
        safe_print(_status_line())
        print_menu("MAIN MENU", _MENU_OPTIONS, show_back=False)
        safe_print(f"  {gray('[0]')}  {dim('Exit')}\n")

        choice = get_choice(len(_MENU_OPTIONS), "Select module")
        if choice is None:
            continue

        if choice == 0:
            safe_print(f"\n  {dim('Goodbye.')}\n")
            sys.exit(0)
        elif choice == 1:
            try:
                from cli.wifi_cli import wifi_menu
                wifi_menu()
            except Exception as e:
                error_msg(f"WiFi module error: {e}")
                wait_enter()
        elif choice == 2:
            try:
                from cli.network_cli import network_menu
                network_menu()
            except Exception as e:
                error_msg(f"Network module error: {e}")
                wait_enter()
        elif choice == 3:
            try:
                from cli.history_cli import history_menu
                history_menu()
            except Exception as e:
                error_msg(f"History module error: {e}")
                wait_enter()
        elif choice == 4:
            try:
                from cli.wordlist_generator import run_wordlist_generator
                run_wordlist_generator()
            except Exception as e:
                error_msg(f"Wordlist generator error: {e}")
                wait_enter()
        elif choice == 5:
            _settings_menu()
