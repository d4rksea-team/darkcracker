"""
tui/screens/wifi.py — WiFi scan + attack screen.
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import (
    Static, Button, Input, Select, DataTable,
    TabbedContent, TabPane
)
from textual.containers import Horizontal, Vertical
from tui.widgets.pipeline import PipelineWidget
from tui.widgets.log_panel import LogPanel


class WiFiTab(Widget):

    def compose(self) -> ComposeResult:
        with TabbedContent(initial="w-scan"):
            with TabPane("SCANNER",       id="w-scan"):   yield from self._scanner()
            with TabPane("ATTACK CONFIG", id="w-config"): yield from self._config()
            with TabPane("LIVE ATTACK",   id="w-live"):   yield from self._live()

    def _scanner(self) -> ComposeResult:
        with Vertical():
            with Horizontal(id="scan-bar"):
                yield Static("Interface: ")
                yield Select(self._ifaces(), id="scan-iface", allow_blank=False)
                yield Button("▶ START", id="btn-scan-start", classes="primary")
                yield Button("■ STOP",  id="btn-scan-stop",  classes="danger")
            tbl = DataTable(id="net-tbl", zebra_stripes=True, cursor_type="row")
            tbl.add_columns("SSID", "BSSID", "CH", "ENC", "PWR", "WPS", "CLIENTS")
            yield tbl

    def _config(self) -> ComposeResult:
        with Vertical(id="cfg-panel"):
            yield Static("[bold cyan]ATTACK CONFIGURATION[/]", classes="section-title")
            with Horizontal():
                yield Static("Interface : ", classes="lbl")
                yield Select(self._ifaces(), id="atk-iface", allow_blank=False)
            with Horizontal():
                yield Static("BSSID     : ", classes="lbl")
                yield Input(placeholder="AA:BB:CC:DD:EE:FF", id="atk-bssid")
            with Horizontal():
                yield Static("SSID      : ", classes="lbl")
                yield Input(placeholder="Target network name", id="atk-ssid")
            with Horizontal():
                yield Static("Channel   : ", classes="lbl")
                yield Input(placeholder="e.g. 6", id="atk-ch")
            with Horizontal():
                yield Static("Wordlist  : ", classes="lbl")
                yield Input(value="/usr/share/wordlists/rockyou.txt", id="atk-wl")
            with Horizontal():
                yield Static("Mode      : ", classes="lbl")
                yield Select([
                    ("Auto — detect and pick best method",  "auto"),
                    ("WPA2 — PMKID (no client needed)",     "pmkid"),
                    ("WPA2 — Handshake + deauth",           "handshake"),
                    ("WEP — ARP replay",                    "wep"),
                    ("WPA3 — Dragonblood / downgrade",      "wpa3"),
                    ("WPS — Pixie Dust then brute force",   "wps"),
                    ("Evil Twin — captive portal harvest",  "evil_twin"),
                ], id="atk-mode", allow_blank=False)
            with Horizontal():
                yield Static("Timeout   : ", classes="lbl")
                yield Input(value="3600", id="atk-timeout")
            yield Static("")
            yield Button("▶▶  LAUNCH FULL ATTACK", id="btn-launch", classes="danger")

    def _live(self) -> ComposeResult:
        with Vertical():
            yield PipelineWidget(id="pipeline")
            with Horizontal(id="metrics"):
                yield Static("Speed: —",    id="m-speed")
                yield Static("Progress: —", id="m-pct")
                yield Static("ETA: —",      id="m-eta")
            yield Static("[bold cyan]ATTACK LOG[/]", classes="section-title")
            yield LogPanel(id="atk-log")
            yield Button("■ STOP ATTACK", id="btn-stop-atk", classes="danger")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        handlers = {
            "btn-scan-start": self._start_scan,
            "btn-scan-stop":  self._stop_scan,
            "btn-launch":     self._launch_attack,
            "btn-stop-atk":   self._stop_attack,
        }
        fn = handlers.get(event.button.id)
        if fn:
            fn()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        try:
            row = self.query_one("#net-tbl", DataTable).get_row(event.row_key)
            self.query_one("#atk-ssid",  Input).value = str(row[0])
            self.query_one("#atk-bssid", Input).value = str(row[1])
            self.query_one("#atk-ch",    Input).value = str(row[2])
            self.query_one("TabbedContent").active = "w-config"
        except Exception:
            pass

    def _start_scan(self) -> None:
        try:
            iface = self.query_one("#scan-iface", Select).value
        except Exception:
            iface = "wlan0"
        self._log(f"Starting WiFi scan on {iface}...", "cyan")
        import threading
        threading.Thread(target=self._scan_worker, args=(iface,), daemon=True).start()

    def _scan_worker(self, iface: str) -> None:
        try:
            from modules.wifi_scanner import WiFiScanner
            scanner = WiFiScanner(
                interface   = iface,
                on_networks = lambda nets: self.app.call_from_thread(self._update_table, nets),
                on_log      = lambda t, m: self.app.call_from_thread(self._log, f"[{t}] {m}"),
            )
            scanner.start()
            scanner.join()
        except Exception as e:
            self.app.call_from_thread(self._log, f"Scan error: {e}", "red")

    def _update_table(self, networks: list) -> None:
        try:
            tbl = self.query_one("#net-tbl", DataTable)
            tbl.clear()
            for n in networks:
                tbl.add_row(
                    n.get("essid", n.get("ssid", "")),
                    n.get("bssid", ""),
                    str(n.get("channel", "")),
                    n.get("encryption", n.get("enc", "")),
                    str(n.get("power", n.get("signal", ""))),
                    "YES" if n.get("wps") else "—",
                    str(n.get("clients", 0)),
                )
        except Exception:
            pass

    def _stop_scan(self) -> None:
        self._log("Scan stopped.", "yellow")

    def _launch_attack(self) -> None:
        try:
            cfg = {
                "interface": self.query_one("#atk-iface",   Select).value,
                "bssid":     self.query_one("#atk-bssid",   Input).value.strip(),
                "ssid":      self.query_one("#atk-ssid",    Input).value.strip(),
                "channel":   int(self.query_one("#atk-ch",  Input).value or "0"),
                "wordlist":  self.query_one("#atk-wl",      Input).value.strip(),
                "mode":      self.query_one("#atk-mode",    Select).value,
                "timeout":   int(self.query_one("#atk-timeout", Input).value or "3600"),
            }
            if not cfg["bssid"] or not cfg["interface"]:
                self._log("Interface and BSSID are required.", "red")
                return
            self.query_one("TabbedContent").active = "w-live"
            self.query_one(PipelineWidget).reset()
            self._log(f"Launching {cfg['mode'].upper()} on {cfg['ssid']} ({cfg['bssid']})", "cyan")
            import threading
            threading.Thread(target=self._attack_worker, args=(cfg,), daemon=True).start()
        except Exception as e:
            self._log(f"Config error: {e}", "red")

    def _attack_worker(self, cfg: dict) -> None:
        try:
            from modules.attack_engine import AutoAttackEngine
            pipeline = self.query_one(PipelineWidget)
            engine = AutoAttackEngine(
                config      = cfg,
                on_log      = lambda t, m: self.app.call_from_thread(self._log, f"[{t}] {m}"),
                on_progress = lambda p: self.app.call_from_thread(
                    self.query_one("#m-pct", Static).update, f"Progress: {p}%"),
                on_phase    = lambda ph: self.app.call_from_thread(pipeline.on_phase, ph),
                on_finished = lambda ok: self.app.call_from_thread(
                    self._log,
                    "Attack finished — password found!" if ok else "Attack finished — not found.",
                    "green" if ok else "yellow"),
            )
            engine.start()
            engine.join()
        except Exception as e:
            self.app.call_from_thread(self._log, f"Attack error: {e}", "red")

    def _stop_attack(self) -> None:
        self._log("Stop signal sent.", "yellow")

    def _log(self, msg: str, color: str = "white") -> None:
        try:
            self.query_one("#atk-log", LogPanel).write(msg, color)
        except Exception:
            pass

    def _ifaces(self) -> list:
        try:
            from core.utils import get_wifi_interfaces
            ifaces = get_wifi_interfaces()
            return [(i, i) for i in ifaces] or [("wlan0", "wlan0")]
        except Exception:
            return [("wlan0", "wlan0")]
