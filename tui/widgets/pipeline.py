"""
tui/widgets/pipeline.py — 9-stage attack pipeline progress widget.
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static
from textual.containers import Horizontal

STAGES = ["SCAN", "CAPTURE", "CRACK", "CONNECT", "DISCOVER", "PORTS", "ENUM", "INTEL", "REPORT"]

_ICONS = {
    "waiting": ("dim",   "○"),
    "running": ("cyan",  "◉"),
    "done":    ("green", "●"),
    "error":   ("red",   "✖"),
    "skip":    ("dim",   "—"),
}

_PHASE_MAP = {
    "scanning":    ("SCAN",     "running"),  "scan_done":   ("SCAN",     "done"),
    "capturing":   ("CAPTURE",  "running"),  "cap_done":    ("CAPTURE",  "done"),
    "cracking":    ("CRACK",    "running"),  "crack_done":  ("CRACK",    "done"),
    "connecting":  ("CONNECT",  "running"),  "connected":   ("CONNECT",  "done"),
    "discovering": ("DISCOVER", "running"),  "disc_done":   ("DISCOVER", "done"),
    "port_scan":   ("PORTS",    "running"),  "ports_done":  ("PORTS",    "done"),
    "enumerating": ("ENUM",     "running"),  "enum_done":   ("ENUM",     "done"),
    "intel_scan":  ("INTEL",    "running"),  "intel_done":  ("INTEL",    "done"),
    "reporting":   ("REPORT",   "running"),  "done":        ("REPORT",   "done"),
}


class PipelineWidget(Widget):

    DEFAULT_CSS = """
    PipelineWidget {
        height: 4;
        background: #060d14;
        border: tall #0e1f30;
        padding: 1 2;
    }
    """

    def __init__(self, **kw):
        super().__init__(**kw)
        self._state = {s: "waiting" for s in STAGES}

    def compose(self) -> ComposeResult:
        with Horizontal():
            for i, s in enumerate(STAGES):
                yield Static(self._render(s), id=f"ps-{s}")
                if i < len(STAGES) - 1:
                    yield Static(" [dim]→[/] ")

    def _render(self, stage: str) -> str:
        color, icon = _ICONS[self._state.get(stage, "waiting")]
        return f"[{color}]{icon} {stage}[/]"

    def set_stage(self, stage: str, status: str) -> None:
        self._state[stage] = status
        try:
            self.query_one(f"#ps-{stage}", Static).update(self._render(stage))
        except Exception:
            pass

    def on_phase(self, phase: str) -> None:
        pair = _PHASE_MAP.get(phase)
        if pair:
            self.set_stage(*pair)

    def reset(self) -> None:
        for s in STAGES:
            self.set_stage(s, "waiting")
