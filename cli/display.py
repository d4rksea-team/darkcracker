"""
cli/display.py — All display utilities: banner, menus, tables, spinners, input helpers.
Thread-safe print via a module-level lock.
"""
import sys
import time
import threading
import shutil
from typing import List, Optional, Callable

from cli.colors import (
    cyan, green, red, yellow, bold, dim, gray, white, accent,
    RESET, BOLD, DIM, _FG_BCYAN, _FG_BGREEN, _FG_BRED, _FG_BYELLOW, _FG_GRAY
)

_print_lock = threading.Lock()


def safe_print(*args, **kwargs) -> None:
    """Thread-safe print."""
    with _print_lock:
        print(*args, **kwargs)


# ── Banner ─────────────────────────────────────────────────────────────────────

BANNER = f"""{BOLD}{_FG_BCYAN}
██████╗  █████╗ ██████╗ ██╗  ██╗     ██████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗
██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝    ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██║  ██║███████║██████╔╝█████╔╝     ██║     ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝
██║  ██║██╔══██║██╔══██╗██╔═██╗     ██║     ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
██████╔╝██║  ██║██║  ██║██║  ██╗    ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                             ██████╗ ██████╗ ███████╗
                            ██╔═══██╗██╔══██╗██╔════╝
                            ██║   ██║██████╔╝███████╗
                            ██║   ██║██╔═══╝ ╚════██║
                            ╚██████╔╝██║     ███████║
                             ╚═════╝ ╚═╝     ╚══════╝{RESET}
{DIM}                  Generation 2  |  Offensive Security Platform  |  Root Mode{RESET}
"""


def print_banner() -> None:
    print(BANNER)


def print_section(title: str) -> None:
    """Print a section divider with title."""
    w = shutil.get_terminal_size((80, 24)).columns
    bar = "─" * w
    print(f"\n{_FG_BCYAN}{bar}{RESET}")
    print(f"{BOLD}{_FG_BCYAN}  {title.upper()}{RESET}")
    print(f"{_FG_BCYAN}{bar}{RESET}")


def print_menu(title: str, options: List[str], show_back: bool = True) -> None:
    """
    Print a numbered menu.

    options — list of option labels (without numbers)
    show_back — append "0. Back" at end
    """
    print_section(title)
    for i, opt in enumerate(options, 1):
        num = cyan(f"  [{i}]")
        print(f"{num}  {opt}")
    if show_back:
        print(f"{gray('  [0]')}  {dim('Back')}")
    print()


def print_table(headers: List[str], rows: List[list], max_col_width: int = 30) -> None:
    """Print a formatted ASCII table."""
    if not rows:
        print(dim("  (no data)"))
        return

    # Build column widths
    col_w = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_w):
                col_w[i] = min(max_col_width, max(col_w[i], len(str(cell))))

    sep = "┼".join("─" * (w + 2) for w in col_w)
    header_line = "│".join(f" {h:<{col_w[i]}} " for i, h in enumerate(headers))

    print(f"  ┌{'┬'.join('─' * (w + 2) for w in col_w)}┐")
    print(f"  │{_FG_BCYAN}{BOLD}{header_line}{RESET}│")
    print(f"  ├{sep}┤")
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            s = str(cell)
            if len(s) > max_col_width:
                s = s[:max_col_width - 1] + "…"
            cells.append(f" {s:<{col_w[i]}} ")
        print(f"  │{'│'.join(cells)}│")
    print(f"  └{'┴'.join('─' * (w + 2) for w in col_w)}┘")


def print_progress(pct: float, label: str = "", width: int = 40) -> None:
    """Print an inline progress bar (uses \\r to overwrite)."""
    filled = int(width * pct / 100)
    bar    = "█" * filled + "░" * (width - filled)
    line   = f"\r  {_FG_BCYAN}[{bar}]{RESET} {pct:5.1f}%  {label:<20}"
    sys.stdout.write(line)
    sys.stdout.flush()


class Spinner:
    """Context manager that shows an animated spinner while work runs."""
    _FRAMES = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

    def __init__(self, label: str = "Working…"):
        self._label   = label
        self._stop    = threading.Event()
        self._thread  = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        i = 0
        while not self._stop.is_set():
            frame = self._FRAMES[i % len(self._FRAMES)]
            sys.stdout.write(f"\r  {_FG_BCYAN}{frame}{RESET}  {self._label}  ")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        self._thread.join()
        sys.stdout.write("\r" + " " * (len(self._label) + 12) + "\r")
        sys.stdout.flush()


# ── Status helpers ─────────────────────────────────────────────────────────────

def info(msg: str) -> None:
    safe_print(f"  {cyan('ℹ')}  {msg}")

def success_msg(msg: str) -> None:
    safe_print(f"  {green('✔')}  {msg}")

def warn_msg(msg: str) -> None:
    safe_print(f"  {yellow('⚠')}  {msg}")

def error_msg(msg: str) -> None:
    safe_print(f"  {red('✖')}  {msg}")

def log(tag: str, msg: str) -> None:
    ts = time.strftime("%H:%M:%S")
    color_map = {
        "INFO":    cyan,
        "OK":      green,
        "SUCCESS": green,
        "WARN":    yellow,
        "WARNING": yellow,
        "ERROR":   red,
        "FAIL":    red,
        "DEBUG":   gray,
    }
    tag_upper = tag.upper()
    color_fn  = color_map.get(tag_upper, white)
    safe_print(f"  {gray(ts)}  {color_fn(f'[{tag_upper}]'):<20}  {msg}")


# ── Input helpers ──────────────────────────────────────────────────────────────

def get_input(prompt: str, default: str = "") -> str:
    """Prompt the user for a string value."""
    dflt = f" [{dim(default)}]" if default else ""
    try:
        val = input(f"  {cyan('▶')} {prompt}{dflt}: ").strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        print()
        return default


def ask_yn(prompt: str, default: bool = False) -> bool:
    """Ask a yes/no question. Returns bool."""
    hint = f"[{'Y' if default else 'y'}/{'n' if default else 'N'}]"
    try:
        val = input(f"  {cyan('▶')} {prompt} {dim(hint)}: ").strip().lower()
        if not val:
            return default
        return val in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return default


def wait_enter(msg: str = "Press Enter to continue…") -> None:
    try:
        input(f"\n  {dim(msg)}")
    except (EOFError, KeyboardInterrupt):
        print()


def get_choice(max_val: int, prompt: str = "Select") -> Optional[int]:
    """
    Prompt for a numbered menu choice.
    Returns int in range 0..max_val, or None on invalid input / Ctrl-C.
    """
    try:
        raw = input(f"  {cyan('▶')} {prompt} [0-{max_val}]: ").strip()
        val = int(raw)
        if 0 <= val <= max_val:
            return val
        error_msg(f"Enter a number between 0 and {max_val}.")
        return None
    except ValueError:
        error_msg("Invalid input — enter a number.")
        return None
    except (EOFError, KeyboardInterrupt):
        print()
        return 0
