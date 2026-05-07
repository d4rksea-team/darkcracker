"""
tui/app.py — DARK CRACKER OPS TUI Application root.
"""
from textual.app import App, ComposeResult
from textual.widgets import TabbedContent, TabPane, Header, Footer
from textual.binding import Binding

from assets.branding import TOOL_NAME, TOOL_VERSION, TEAM_NAME, LICENSE_TEXT
from tui.screens.dashboard import DashboardTab
from tui.screens.wifi      import WiFiTab
from tui.screens.network   import NetworkTab
from tui.screens.history   import HistoryTab


class DarkCrackerApp(App):
    """DARK CRACKER OPS — Terminal UI"""

    CSS_PATH  = "styles.tcss"
    TITLE     = f"{TOOL_NAME} v{TOOL_VERSION} | {TEAM_NAME}"
    SUB_TITLE = LICENSE_TEXT

    BINDINGS = [
        Binding("1", "switch_tab('dashboard')", "Dashboard"),
        Binding("2", "switch_tab('wifi')",      "WiFi"),
        Binding("3", "switch_tab('network')",   "Network"),
        Binding("4", "switch_tab('history')",   "History"),
        Binding("q", "quit",                    "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(initial="dashboard"):
            with TabPane("⌂  DASHBOARD",   id="dashboard"):  yield DashboardTab()
            with TabPane("◈  WIFI ATTACK", id="wifi"):        yield WiFiTab()
            with TabPane("⊞  NETWORK",     id="network"):     yield NetworkTab()
            with TabPane("⊟  HISTORY",     id="history"):     yield HistoryTab()
        yield Footer()

    def action_switch_tab(self, tab: str) -> None:
        self.query_one(TabbedContent).active = tab
