"""
core/logger.py — Thread-safe, singleton-per-name logger for DARK CRACKER OPS.
Writes DEBUG+ to the log file and INFO+ to stdout.
"""
import logging
import sys

# Registry keeps one Logger instance per name so we never add duplicate handlers
_loggers: dict = {}


def get_logger(name: str) -> logging.Logger:
    """
    Return (or create) a Logger for the given short name.
    The underlying logger is registered as 'darkcracker.<name>'.
    """
    if name in _loggers:
        return _loggers[name]

    log = logging.getLogger(f"darkcracker.{name}")
    log.setLevel(logging.DEBUG)
    # Prevent propagation to root logger to avoid duplicate console output
    log.propagate = False

    if not log.handlers:
        # ── Console handler (INFO and above) ──────────────────────────────────
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        log.addHandler(ch)

        # ── File handler (DEBUG and above) ────────────────────────────────────
        try:
            from core.config import LOG_PATH, CONFIG_DIR
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(str(LOG_PATH), encoding="utf-8")
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter(
                "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            ))
            log.addHandler(fh)
        except Exception as exc:
            # If we cannot open the log file, keep going with console-only
            log.warning("Could not open log file: %s", exc)

    _loggers[name] = log
    return log


def set_log_level(level: int) -> None:
    """Adjust the log level of every registered logger (e.g. logging.DEBUG)."""
    for log in _loggers.values():
        log.setLevel(level)
        for handler in log.handlers:
            handler.setLevel(level)
