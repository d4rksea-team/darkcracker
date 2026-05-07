"""
tui/widgets/header.py — Custom top bar with live clock and status.
"""
import os
from datetime import datetime
from textual.widget import Widget
from textual.app import ComposeResult
from textual.widgets import Static
from assets.branding import TOOL_NAME, TOOL_VERSION, TEAM_NAME


class AppHeader(Widget):

    DEFAULT_CSS = """
    AppHeader {
        height: 3;
        background: #060d14;
        border-bottom: tall #0e1f30;
        layout: horizontal;
        align: center middle;
        padding: 0 2;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(f"[bold cyan]▌ {TOOL_NAME}[/] [dim]v{TOOL_VERSION}[/]")
        yield Static("", id="hdr-spacer")
        yield Static(f"[bold yellow][ {TEAM_NAME} ][/]")
        yield Static("", id="hdr-status")

    def on_mount(self) -> None:
        self.set_interval(1, self._tick)

    def _tick(self) -> None:
        root = os.geteuid() == 0
        root_str = "[green]● ROOT[/]" if root else "[red]✖ NO ROOT[/]"
        now = datetime.now().strftime("%H:%M:%S")
        try:
            self.query_one("#hdr-status", Static).update(
                f"{root_str}  [dim]{now}[/]"
            )
        except Exception:
            pass
