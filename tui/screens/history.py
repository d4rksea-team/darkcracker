"""
tui/screens/history.py — Session history and PDF report generation.
"""
import threading
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Button, Input, Select, DataTable
from textual.containers import Horizontal, Vertical
from tui.widgets.log_panel import LogPanel
from core.database import get_db


class HistoryTab(Widget):

    def compose(self) -> ComposeResult:
        yield Static("[bold cyan]ATTACK HISTORY[/]", classes="section-title")
        with Horizontal():
            yield Button("⟳ REFRESH",    id="btn-refresh", classes="primary")
            yield Button("⊟ EXPORT PDF", id="btn-pdf",     classes="success")
            yield Button("✖ DELETE",     id="btn-del",     classes="danger")
        tbl = DataTable(id="hist-tbl", zebra_stripes=True, cursor_type="row")
        tbl.add_columns("SESSION", "DATE", "SSID", "BSSID", "ATTACK", "RESULT", "DURATION", "HOSTS")
        yield tbl
        yield Static("[bold cyan]SESSION DETAILS[/]", classes="section-title")
        yield LogPanel(id="detail-log")
        with Horizontal():
            yield Static("Classification: ")
            yield Select([
                ("TLP:RED",   "TLP:RED"),   ("TLP:AMBER", "TLP:AMBER"),
                ("TLP:GREEN", "TLP:GREEN"), ("INTERNAL",  "INTERNAL"),
                ("PUBLIC",    "PUBLIC"),
            ], id="classif", allow_blank=False)
            yield Input(
                placeholder="Output path (default: ~/.darkcracker/reports/)",
                id="out-path"
            )
        yield LogPanel(id="rpt-log")

    def on_mount(self) -> None:
        self._load()

    def _load(self) -> None:
        try:
            db  = get_db()
            tbl = self.query_one("#hist-tbl", DataTable)
            tbl.clear()
            for s in db.get_all_sessions():
                color = "green" if s.get("result") == "success" else "red"
                tbl.add_row(
                    s.get("id", "")[:12],
                    s.get("start_time", "")[:16],
                    s.get("target_ssid", ""),
                    s.get("target_bssid", ""),
                    s.get("attack_type", ""),
                    f"[{color}]{s.get('result','').upper()}[/]",
                    str(s.get("duration", "")),
                    str(s.get("hosts_found", "")),
                )
        except Exception as e:
            try:
                self.query_one("#rpt-log", LogPanel).write(f"Load error: {e}", "red")
            except Exception:
                pass

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        try:
            row     = event.data_table.get_row(event.row_key)
            sess_id = str(row[0])
            db      = get_db()
            s       = db.get_session(sess_id)
            hosts   = db.get_session_hosts(sess_id)
            ports   = db.get_session_ports(sess_id)
            vulns   = db.get_session_vulns(sess_id)
            log     = self.query_one("#detail-log", LogPanel)
            log.clear()
            log.write(f"[bold cyan]ID:[/] {s.get('id','')}")
            log.write(f"[cyan]TARGET:[/]  {s.get('target_ssid','')} ({s.get('target_bssid','')})")
            log.write(f"[cyan]ATTACK:[/]  {s.get('attack_type','')}  [{s.get('result','').upper()}]")
            if s.get("password"):
                log.write(f"[bold green]PASSWORD:[/] {s['password']}")
            log.write(
                f"[cyan]HOSTS:[/]   {len(hosts)}"
                f"   [cyan]PORTS:[/] {len(ports)}"
                f"   [cyan]VULNS:[/] {len(vulns)}"
            )
            for h in hosts[:8]:
                log.write(f"  ● {h.get('ip')} — {h.get('hostname','')} [{h.get('vendor','')}]")
        except Exception as e:
            try:
                self.query_one("#detail-log", LogPanel).write(f"Error: {e}", "red")
            except Exception:
                pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-refresh":
            self._load()
        elif event.button.id == "btn-pdf":
            self._export_pdf()

    def _export_pdf(self) -> None:
        try:
            tbl     = self.query_one("#hist-tbl", DataTable)
            row     = tbl.get_row_at(tbl.cursor_row)
            sess_id = str(row[0])
            classif = self.query_one("#classif",  Select).value
            out     = self.query_one("#out-path", Input).value.strip()
            threading.Thread(
                target=self._pdf_worker, args=(sess_id, classif, out), daemon=True
            ).start()
        except Exception as e:
            try:
                self.query_one("#rpt-log", LogPanel).write(f"Error: {e}", "red")
            except Exception:
                pass

    def _pdf_worker(self, sess_id: str, classif: str, out: str) -> None:
        try:
            from modules.report_generator import ReportGenerator
            from core.config import REPORTS_DIR, ensure_dirs
            from datetime import datetime
            ensure_dirs()
            db   = get_db()
            data = {
                "session":         db.get_session(sess_id),
                "hosts":           db.get_session_hosts(sess_id),
                "ports":           db.get_session_ports(sess_id),
                "vulnerabilities": db.get_session_vulns(sess_id),
                "credentials":     db.get_session_creds(sess_id),
                "classification":  classif,
            }
            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = out or str(REPORTS_DIR / f"report_{sess_id[:8]}_{ts}.pdf")
            ReportGenerator().generate(data=data, fmt="pdf", output_path=path)
            self.app.call_from_thread(
                self.query_one("#rpt-log", LogPanel).write,
                f"Report saved: {path}", "green"
            )
        except Exception as e:
            self.app.call_from_thread(
                self.query_one("#rpt-log", LogPanel).write,
                f"Report error: {e}", "red"
            )
