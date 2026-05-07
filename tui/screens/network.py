"""
tui/screens/network.py — Post-connection network scanning.
"""
import threading
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Button, Input, DataTable, TabbedContent, TabPane
from textual.containers import Horizontal, Vertical
from tui.widgets.log_panel import LogPanel

_RISK_COLOR = {
    "CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green", "INFO": "dim"
}


class NetworkTab(Widget):

    def compose(self) -> ComposeResult:
        with TabbedContent(initial="n-hosts"):
            with TabPane("HOST DISCOVERY",  id="n-hosts"): yield from self._hosts()
            with TabPane("PORT SCAN",       id="n-ports"): yield from self._ports()
            with TabPane("VULNERABILITIES", id="n-vulns"): yield from self._vulns()

    def _hosts(self) -> ComposeResult:
        with Vertical():
            with Horizontal():
                yield Input(placeholder="192.168.1.0/24", id="n-target")
                yield Button("▶ DISCOVER",  id="btn-discover", classes="primary")
                yield Button("▶ SCAN ALL",  id="btn-scan-all", classes="warning")
            tbl = DataTable(id="h-tbl", zebra_stripes=True, cursor_type="row")
            tbl.add_columns("IP", "MAC", "HOSTNAME", "VENDOR", "OS", "RISK")
            yield tbl
            yield LogPanel(id="n-log")

    def _ports(self) -> ComposeResult:
        with Vertical():
            with Horizontal():
                yield Input(placeholder="IP or select from hosts tab", id="p-target")
                yield Input(
                    value="21,22,23,25,53,80,443,445,3306,3389,5900,8080,8443",
                    id="p-ports"
                )
                yield Button("▶ SCAN", id="btn-portscan", classes="primary")
            tbl = DataTable(id="p-tbl", zebra_stripes=True)
            tbl.add_columns("HOST", "PORT", "PROTO", "STATE", "SERVICE", "VERSION", "RISK")
            yield tbl

    def _vulns(self) -> ComposeResult:
        with Vertical():
            yield Static("[bold cyan]VULNERABILITIES[/]", classes="section-title")
            tbl = DataTable(id="v-tbl", zebra_stripes=True)
            tbl.add_columns("HOST", "PORT", "CVE", "SEVERITY", "CVSS", "DESCRIPTION")
            yield tbl

    def on_button_pressed(self, event: Button.Pressed) -> None:
        {
            "btn-discover": self._run_discovery,
            "btn-scan-all": self._scan_all,
            "btn-portscan": self._run_portscan,
        }.get(event.button.id, lambda: None)()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "h-tbl":
            try:
                row = event.data_table.get_row(event.row_key)
                self.query_one("#p-target", Input).value = str(row[0])
                self.query_one("TabbedContent").active = "n-ports"
            except Exception:
                pass

    def _run_discovery(self) -> None:
        try:
            target = self.query_one("#n-target", Input).value.strip() or "192.168.1.0/24"
        except Exception:
            target = "192.168.1.0/24"
        threading.Thread(target=self._disc_worker, args=(target,), daemon=True).start()

    def _disc_worker(self, target: str) -> None:
        try:
            from modules.network_discovery import NetworkDiscovery
            nd = NetworkDiscovery(
                on_host     = lambda h: self.app.call_from_thread(self._add_host, h),
                on_log      = lambda t, m: self.app.call_from_thread(
                    self.query_one("#n-log", LogPanel).write, f"[{t}] {m}"),
                on_finished = lambda ok: self.app.call_from_thread(
                    self.query_one("#n-log", LogPanel).write, "Discovery complete.", "green"),
            )
            nd.target = target
            nd.start()
            nd.join()
        except Exception as e:
            self.app.call_from_thread(
                self.query_one("#n-log", LogPanel).write, f"Error: {e}", "red")

    def _add_host(self, h: dict) -> None:
        try:
            risk  = h.get("risk", "LOW")
            color = _RISK_COLOR.get(risk, "dim")
            self.query_one("#h-tbl", DataTable).add_row(
                h.get("ip", ""), h.get("mac", ""), h.get("hostname", ""),
                h.get("vendor", ""), h.get("os_guess", ""),
                f"[{color}]{risk}[/]",
            )
        except Exception:
            pass

    def _scan_all(self) -> None:
        try:
            tbl   = self.query_one("#h-tbl", DataTable)
            hosts = [str(tbl.get_row(k)[0]) for k in tbl.rows]
            ports = self.query_one("#p-ports", Input).value.strip()
            for ip in hosts:
                threading.Thread(
                    target=self._port_worker, args=(ip, ports), daemon=True
                ).start()
        except Exception:
            pass

    def _run_portscan(self) -> None:
        try:
            target = self.query_one("#p-target", Input).value.strip()
            ports  = self.query_one("#p-ports",  Input).value.strip()
        except Exception:
            return
        if target:
            threading.Thread(target=self._port_worker, args=(target, ports), daemon=True).start()

    def _port_worker(self, target: str, ports: str) -> None:
        try:
            from modules.port_scanner import PortScanner
            ps = PortScanner(
                on_port  = lambda p: self.app.call_from_thread(self._add_port, p),
                on_vuln  = lambda v: self.app.call_from_thread(self._add_vuln, v),
                on_log   = lambda t, m: self.app.call_from_thread(
                    self.query_one("#n-log", LogPanel).write, f"[{t}] {m}"),
            )
            ps.target = target
            ps.ports  = ports
            ps.start()
            ps.join()
        except Exception as e:
            self.app.call_from_thread(
                self.query_one("#n-log", LogPanel).write, f"Error: {e}", "red")

    def _add_port(self, p: dict) -> None:
        try:
            risk  = p.get("risk_level", "INFO")
            color = _RISK_COLOR.get(risk, "dim")
            self.query_one("#p-tbl", DataTable).add_row(
                p.get("host", ""), str(p.get("port", "")),
                p.get("protocol", "tcp"), p.get("state", ""),
                p.get("service", ""), p.get("version", ""),
                f"[{color}]{risk}[/]",
            )
        except Exception:
            pass

    def _add_vuln(self, v: dict) -> None:
        try:
            sev   = v.get("severity", "LOW")
            color = _RISK_COLOR.get(sev, "dim")
            self.query_one("#v-tbl", DataTable).add_row(
                v.get("host", ""), str(v.get("port", "")),
                v.get("cve_id", ""), f"[{color}]{sev}[/]",
                str(v.get("cvss_score", "")), v.get("description", "")[:60],
            )
        except Exception:
            pass
