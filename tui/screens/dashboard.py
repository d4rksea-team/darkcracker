"""
tui/screens/dashboard.py — Dashboard home tab.
"""
import shutil
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Button, RichLog, TabbedContent
from textual.containers import Horizontal, Vertical
from core.database import get_db
from core.config import TOOLS


class StatCard(Widget):
    DEFAULT_CSS = """
    StatCard {
        background: #060d14; border: tall #0e1f30;
        height: 7; width: 1fr; padding: 1 2; align: center middle;
    }
    StatCard:hover { border: tall #00e5ff; }
    """
    def __init__(self, label: str, cid: str, **kw):
        super().__init__(**kw)
        self._label = label
        self._cid   = cid

    def compose(self) -> ComposeResult:
        yield Static("[bold cyan]0[/]", id=self._cid + "-val")
        yield Static(f"[dim]{self._label}[/]")

    def set_value(self, v) -> None:
        try:
            self.query_one(f"#{self._cid}-val", Static).update(f"[bold cyan]{v}[/]")
        except Exception:
            pass


class DashboardTab(Widget):

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield StatCard("SESSIONS",   "s-sessions")
            yield StatCard("NETWORKS",   "s-networks")
            yield StatCard("CRACKED",    "s-cracked")
            yield StatCard("HOSTS",      "s-hosts")
            yield StatCard("VULNS",      "s-vulns")

        with Horizontal(id="mid-row"):
            with Vertical(id="quick"):
                yield Static("[bold cyan]QUICK LAUNCH[/]", classes="section-title")
                yield Button("◈  WIFI ATTACK",     id="q-wifi",   classes="primary")
                yield Button("⊞  NETWORK SCAN",    id="q-net",    classes="primary")
                yield Button("▶  AUTO ATTACK",     id="q-auto",   classes="danger")
                yield Button("⚡  EVIL TWIN",       id="q-evil",   classes="warning")
                yield Button("⊟  GENERATE REPORT", id="q-report", classes="success")

            with Vertical(id="health"):
                yield Static("[bold cyan]SYSTEM HEALTH[/]", classes="section-title")
                yield Static("", id="health-body")

        yield Static("[bold cyan]RECENT ACTIVITY[/]", classes="section-title")
        yield RichLog(id="activity", markup=True, max_lines=15)

    def on_mount(self) -> None:
        self._refresh()
        self.set_interval(15, self._refresh)

    def _refresh(self) -> None:
        try:
            db       = get_db()
            sessions = db.get_all_sessions()
            cracked  = sum(1 for s in sessions if s.get("result") == "success")
            hosts    = sum(s.get("hosts_found", 0) for s in sessions)
            self.query_one("#s-sessions-val", Static).update(f"[bold cyan]{len(sessions)}[/]")
            self.query_one("#s-cracked-val",  Static).update(f"[bold cyan]{cracked}[/]")
            self.query_one("#s-hosts-val",    Static).update(f"[bold cyan]{hosts}[/]")
        except Exception:
            pass

        lines = []
        try:
            tools = TOOLS if isinstance(TOOLS, dict) else {}
        except Exception:
            tools = {}
        for name, cmd in list(tools.items())[:10]:
            ok  = shutil.which(cmd) is not None
            dot = "[green]●[/]" if ok else "[red]●[/]"
            lines.append(f"  {dot} [dim]{cmd}[/]")
        try:
            self.query_one("#health-body", Static).update("\n".join(lines))
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        tab = {
            "q-wifi":   "wifi", "q-net": "network",
            "q-auto":   "wifi", "q-evil": "wifi",    "q-report": "history",
        }.get(event.button.id)
        if tab:
            try:
                self.app.query_one(TabbedContent).active = tab
            except Exception:
                pass
