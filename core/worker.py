"""
core/worker.py — Base worker thread for DARK CRACKER OPS.
Replaces PyQt5 QThread with standard threading.Thread + callbacks.
"""
import threading
from typing import Callable, Optional


class BaseWorker(threading.Thread):
    """
    Base class for all background workers.
    Provides: stop(), is_stopped(), safe callback invocation.
    All worker classes in modules/ inherit from this.
    """

    def __init__(self, daemon: bool = True):
        super().__init__(daemon=daemon)
        self._stop_event = threading.Event()

    def stop(self) -> None:
        """Signal the worker to stop at the next safe point."""
        self._stop_event.set()

    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    @staticmethod
    def _call(fn: Optional[Callable], *args) -> None:
        """Safely invoke a callback — does nothing if fn is None."""
        if fn is not None:
            try:
                fn(*args)
            except Exception:
                pass
