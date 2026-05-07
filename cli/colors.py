"""
cli/colors.py — ANSI color codes and helper functions.
"""

# ── Raw codes ──────────────────────────────────────────────────────────────────
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"

# Foreground colors
_FG_RED     = "\033[31m"
_FG_GREEN   = "\033[32m"
_FG_YELLOW  = "\033[33m"
_FG_CYAN    = "\033[36m"
_FG_WHITE   = "\033[37m"
_FG_GRAY    = "\033[90m"
_FG_BRED    = "\033[91m"   # bright red
_FG_BGREEN  = "\033[92m"   # bright green
_FG_BYELLOW = "\033[93m"   # bright yellow
_FG_BCYAN   = "\033[96m"   # bright cyan
_FG_BWHITE  = "\033[97m"   # bright white


# ── Helper functions ───────────────────────────────────────────────────────────

def cyan(s: str) -> str:
    return f"{_FG_BCYAN}{s}{RESET}"

def green(s: str) -> str:
    return f"{_FG_BGREEN}{s}{RESET}"

def red(s: str) -> str:
    return f"{_FG_BRED}{s}{RESET}"

def yellow(s: str) -> str:
    return f"{_FG_BYELLOW}{s}{RESET}"

def bold(s: str) -> str:
    return f"{BOLD}{s}{RESET}"

def dim(s: str) -> str:
    return f"{DIM}{s}{RESET}"

def gray(s: str) -> str:
    return f"{_FG_GRAY}{s}{RESET}"

def white(s: str) -> str:
    return f"{_FG_BWHITE}{s}{RESET}"

def danger(s: str) -> str:
    return f"{BOLD}{_FG_BRED}{s}{RESET}"

def success(s: str) -> str:
    return f"{BOLD}{_FG_BGREEN}{s}{RESET}"

def warn(s: str) -> str:
    return f"{_FG_BYELLOW}{s}{RESET}"

def accent(s: str) -> str:
    """Primary accent — bright cyan bold."""
    return f"{BOLD}{_FG_BCYAN}{s}{RESET}"
