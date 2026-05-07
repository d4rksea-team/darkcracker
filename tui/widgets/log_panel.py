"""
tui/widgets/log_panel.py — Thread-safe scrolling log panel.
"""
from datetime import datetime
from textual.widget import Widget
from textual.app import ComposeResult
from textual.widgets import RichLog


class LogPanel(Widget):

    DEFAULT_CSS = """
    LogPanel { height: 1fr; }
    """

    def compose(self) -> ComposeResult:
        yield RichLog(id="richlog", markup=True, max_lines=1000, wrap=True)

    def write(self, msg: str, color: str = "white") -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        try:
            self.query_one("#richlog", RichLog).write(
                f"[dim]{ts}[/]  [{color}]{msg}[/]"
            )
        except Exception:
            pass

    def log_callback(self, tag: str, msg: str) -> None:
        color_map = {
            "ERROR": "red", "WARN": "yellow", "SUCCESS": "green",
            "CRACK": "cyan", "PMKID": "cyan", "SCAN": "cyan",
            "BT": "magenta", "NET": "blue",
        }
        color = color_map.get(tag.upper(), "white")
        self.write(f"[{tag}] {msg}", color)

    def clear(self) -> None:
        try:
            self.query_one("#richlog", RichLog).clear()
        except Exception:
            pass
