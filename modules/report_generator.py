"""
modules/report_generator.py — Multi-format report generation for DARK CRACKER OPS.
Supports PDF (reportlab), HTML (inline), JSON, and TXT formats.
"""
import json
import os
import traceback
from datetime import datetime

from assets.branding import (
    ASCII_LOGO, TOOL_NAME, TOOL_VERSION, TEAM_NAME,
    TEAM_TAGLINE, COPYRIGHT, LICENSE_TEXT,
    get_report_header_html,
)

# ── Color constants (HTML/CSS) ─────────────────────────────────────────────────
C_BG        = "#020508"
C_PANEL     = "#060d14"
C_PANEL_ALT = "#0a1628"
C_BORDER    = "#0e1f30"
C_ACCENT    = "#00e5ff"
C_ACCENT2   = "#00ff88"
C_DANGER    = "#ff2244"
C_WARNING   = "#ffc800"
C_TEXT      = "#a8c8e0"
C_TEXT_DIM  = "#3a6080"
C_BRIGHT    = "#e0f0ff"

# ── Section render order ───────────────────────────────────────────────────────
SECTION_ORDER = [
    "Executive Summary",
    "WiFi Networks Found",
    "Network Hosts",
    "Open Ports & Services",
    "Discovered Credentials",
    "Vulnerability Findings",
    "Attack Timeline",
    "Network Intelligence",
    "Recommendations",
    "Technical Appendix",
]

# ── Internal key mapping: section name → data key ────────────────────────────
SECTION_DATA_KEY = {
    "Executive Summary":    "executive_summary_text",
    "WiFi Networks Found":  "wifi_networks",
    "Network Hosts":        "hosts",
    "Open Ports & Services": "ports",
    "Discovered Credentials": "creds",
    "Vulnerability Findings": "vulnerabilities",
    "Attack Timeline":       "events",
    "Network Intelligence":  "network_intelligence",
    "Recommendations":       "recommendations",
    "Technical Appendix":    "technical_appendix",
}


class ReportGenerator:
    """
    Multi-format penetration test report generator.

    Usage:
        gen = ReportGenerator()
        ok  = gen.generate(data_dict, "/path/to/report.html", fmt="HTML")
    """

    def __init__(self):
        self._has_reportlab = False
        try:
            import reportlab  # noqa
            self._has_reportlab = True
        except ImportError:
            pass

    # ── Public entry point ────────────────────────────────────────────────────

    def generate(self, data: dict, output_path: str, fmt: str = "HTML") -> bool:
        """
        Generate a report and write it to output_path.

        Args:
            data:        Full report data dict (see module docstring).
            output_path: Filesystem path for the output file.
            fmt:         One of "HTML", "JSON", "TXT", "PDF".

        Returns:
            True on success, False on any error.
        """
        fmt = fmt.upper()
        try:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        except Exception:
            pass  # If dirname is empty, that's fine

        dispatch = {
            "HTML": self._gen_html,
            "JSON": self._gen_json,
            "TXT":  self._gen_txt,
            "PDF":  self._gen_pdf,
        }

        fn = dispatch.get(fmt)
        if fn is None:
            return False

        try:
            return fn(data, output_path)
        except Exception:
            traceback.print_exc()
            return False

    # ── HTML generator ────────────────────────────────────────────────────────

    def _gen_html(self, data: dict, path: str) -> bool:
        meta     = data.get("metadata", {})
        sections = data.get("sections", SECTION_ORDER)
        ts       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        classification = meta.get("classification", "CONFIDENTIAL")
        class_color = {"CONFIDENTIAL": C_WARNING, "SECRET": C_DANGER,
                       "PUBLIC": C_ACCENT2}.get(classification, C_WARNING)

        html_parts = [
            "<!DOCTYPE html>",
            "<html lang='en'>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
            f"<title>{TOOL_NAME} — Penetration Test Report</title>",
            "<style>",
            self._html_css(),
            "</style>",
            "</head>",
            "<body>",
            # Header
            get_report_header_html(),
            # Classification banner
            f"<div class='classification' style='background:{class_color}22;border:1px solid {class_color};"
            f"color:{class_color};text-align:center;padding:6px;font-weight:bold;"
            f"font-size:13px;letter-spacing:4px;'>{classification}</div>",
            # Metadata table
            "<div class='section'>",
            "<h2 class='sec-title'>ENGAGEMENT METADATA</h2>",
            "<table class='meta-table'>",
            f"<tr><td class='meta-key'>Engagement</td><td>{self._safe_str(meta.get('engagement_name'))}</td></tr>",
            f"<tr><td class='meta-key'>Target Organization</td><td>{self._safe_str(meta.get('target_org'))}</td></tr>",
            f"<tr><td class='meta-key'>Operator</td><td>{self._safe_str(meta.get('operator'))}</td></tr>",
            f"<tr><td class='meta-key'>Date</td><td>{self._safe_str(meta.get('date'))}</td></tr>",
            f"<tr><td class='meta-key'>Classification</td><td style='color:{class_color};font-weight:bold;'>{classification}</td></tr>",
            f"<tr><td class='meta-key'>Generated</td><td>{ts}</td></tr>",
            "</table>",
            "</div>",
        ]

        # Sections
        for section in SECTION_ORDER:
            if section not in sections:
                continue
            html_parts.append(self._html_section(section, data))

        # Footer
        html_parts += [
            f"<div class='footer'>{COPYRIGHT} — {LICENSE_TEXT} — Generated by {TOOL_NAME} v{TOOL_VERSION}</div>",
            "</body></html>",
        ]

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(html_parts))
            return True
        except Exception:
            traceback.print_exc()
            return False

    def _html_section(self, section: str, data: dict) -> str:
        """Render a single report section as an HTML <details> block."""
        key = SECTION_DATA_KEY.get(section, "")
        items = data.get(key, [])
        meta  = data.get("metadata", {})

        content = ""

        if section == "Executive Summary":
            text = meta.get("executive_summary", "") or self._safe_str(items)
            content = f"<p class='exec-summary'>{text.replace(chr(10), '<br>')}</p>"

        elif section == "WiFi Networks Found":
            content = self._html_table(
                ["SSID", "BSSID", "Channel", "Security", "Signal", "WPS", "Status"],
                [["ssid", "bssid", "channel", "security", "signal", "wps", "status"]],
                items,
            )

        elif section == "Network Hosts":
            content = self._html_table(
                ["IP Address", "MAC", "Hostname", "OS", "Open Ports"],
                [["ip", "mac", "hostname", "os", "ports"]],
                items,
            )

        elif section == "Open Ports & Services":
            content = self._html_table(
                ["Host", "Port", "Protocol", "Service", "Version", "Risk"],
                [["host", "port", "protocol", "service", "version", "risk"]],
                items,
            )

        elif section == "Discovered Credentials":
            content = self._html_table(
                ["Service", "Host", "Port", "Username", "Password", "Status", "Source"],
                [["service", "host", "port", "username", "password", "status", "source"]],
                items,
                highlight_col=5,
                highlight_map={
                    "VALID":      C_ACCENT2,
                    "INVALID":    C_DANGER,
                    "UNVERIFIED": C_WARNING,
                },
            )

        elif section == "Vulnerability Findings":
            if not items:
                content = "<p class='empty'>No vulnerability findings recorded.</p>"
            else:
                parts = []
                for vuln in items:
                    sev   = self._safe_str(vuln.get("severity", "INFO"))
                    sev_c = {"CRITICAL": C_DANGER, "HIGH": C_DANGER,
                             "MEDIUM": C_WARNING, "LOW": C_ACCENT2,
                             "INFO": C_ACCENT}.get(sev.upper(), C_TEXT)
                    parts.append(
                        f"<div class='vuln-item'>"
                        f"<span class='vuln-sev' style='color:{sev_c};'>[{sev}]</span> "
                        f"<span class='vuln-title'>{self._safe_str(vuln.get('title', vuln.get('type', '?')))}</span>"
                        f"<p class='vuln-desc'>{self._safe_str(vuln.get('description', vuln.get('url', '')))}</p>"
                        f"</div>"
                    )
                content = "\n".join(parts)

        elif section == "Attack Timeline":
            if not items:
                content = "<p class='empty'>No timeline events recorded.</p>"
            else:
                parts = ["<div class='timeline'>"]
                for ev in items:
                    parts.append(
                        f"<div class='tl-event'>"
                        f"<span class='tl-time'>{self._safe_str(ev.get('time', ev.get('timestamp', '')))}</span>"
                        f"<span class='tl-msg'>{self._safe_str(ev.get('message', ev.get('event', str(ev))))}</span>"
                        f"</div>"
                    )
                parts.append("</div>")
                content = "\n".join(parts)

        elif section == "Network Intelligence":
            if not items or not isinstance(items, dict):
                content = "<p class='empty'>No network intelligence data.</p>"
            else:
                rows_html = "".join(
                    f"<tr><td class='meta-key'>{self._safe_str(k)}</td>"
                    f"<td>{self._safe_str(v)}</td></tr>"
                    for k, v in items.items()
                )
                content = f"<table class='meta-table'>{rows_html}</table>"

        elif section == "Recommendations":
            if not items:
                content = (
                    "<ul class='recs'>"
                    "<li>Change all default credentials immediately.</li>"
                    "<li>Enable WPA3 on all wireless access points.</li>"
                    "<li>Disable WPS on all access points.</li>"
                    "<li>Segment wireless networks from wired infrastructure.</li>"
                    "<li>Deploy wireless intrusion detection/prevention systems.</li>"
                    "<li>Patch all identified vulnerabilities within SLA timelines.</li>"
                    "<li>Enable logging and alerting on all network devices.</li>"
                    "</ul>"
                )
            else:
                lis = "".join(
                    f"<li>{self._safe_str(r)}</li>" for r in items
                )
                content = f"<ul class='recs'>{lis}</ul>"

        elif section == "Technical Appendix":
            content = (
                f"<pre class='appendix'>"
                f"Tool: {TOOL_NAME} v{TOOL_VERSION}\n"
                f"Team: {TEAM_NAME} — {TEAM_TAGLINE}\n"
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"{LICENSE_TEXT}\n"
                f"</pre>"
            )
            if items:
                content += f"<pre class='appendix'>{self._safe_str(items)}</pre>"

        else:
            content = "<p class='empty'>No data available for this section.</p>"

        return (
            f"<details class='section' open>"
            f"<summary class='sec-title'>{section.upper()}</summary>"
            f"<div class='sec-content'>{content}</div>"
            f"</details>"
        )

    def _html_table(self, headers: list, _key_rows, items: list,
                    highlight_col: int = -1,
                    highlight_map: dict = None) -> str:
        """
        Render a generic HTML table from a list of dicts.
        headers:       List of column header strings.
        _key_rows:     List of one row of keys (first entry is used as key list).
        items:         List of dicts to render.
        highlight_col: Column index to apply color highlighting.
        highlight_map: Dict of value → color for the highlighted column.
        """
        if not items:
            return "<p class='empty'>No data recorded.</p>"

        keys = _key_rows[0] if _key_rows else []
        rows = [f"<tr>{''.join(f'<th>{h}</th>' for h in headers)}</tr>"]

        for item in items:
            cells = ""
            for i, k in enumerate(keys):
                val = self._safe_str(item.get(k, ""))
                style = ""
                if highlight_col == i and highlight_map:
                    color = highlight_map.get(val.upper(), "")
                    if color:
                        style = f" style='color:{color};font-weight:bold;'"
                cells += f"<td{style}>{val}</td>"
            rows.append(f"<tr>{cells}</tr>")

        return f"<table class='data-table'>\n{''.join(rows)}\n</table>"

    def _html_css(self) -> str:
        return f"""
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: {C_BG};
            color: {C_TEXT};
            font-family: "Consolas", "Courier New", monospace;
            font-size: 13px;
            line-height: 1.6;
        }}
        .section {{
            background: {C_PANEL};
            border: 1px solid {C_BORDER};
            border-radius: 4px;
            margin: 12px 16px;
            padding: 0;
            overflow: hidden;
        }}
        .sec-title {{
            background: {C_PANEL_ALT};
            color: {C_ACCENT};
            font-size: 12px;
            font-weight: bold;
            letter-spacing: 2px;
            padding: 8px 14px;
            cursor: pointer;
            border-bottom: 1px solid {C_BORDER};
            list-style: none;
        }}
        details > summary {{ list-style: none; }}
        details > summary::-webkit-details-marker {{ display: none; }}
        .sec-content {{ padding: 12px 14px; }}
        .meta-table {{ width: 100%; border-collapse: collapse; }}
        .meta-table td {{ padding: 4px 10px; border-bottom: 1px solid {C_BORDER}; }}
        .meta-key {{ color: {C_ACCENT}; font-weight: bold; width: 200px; }}
        .data-table {{
            width: 100%; border-collapse: collapse; font-size: 11px;
        }}
        .data-table th {{
            background: {C_PANEL_ALT};
            color: {C_ACCENT};
            padding: 5px 8px;
            border: 1px solid {C_BORDER};
            text-align: left;
            font-size: 10px;
            letter-spacing: 1px;
        }}
        .data-table td {{
            padding: 4px 8px;
            border: 1px solid {C_BORDER};
            color: {C_TEXT};
        }}
        .data-table tr:nth-child(even) td {{ background: {C_PANEL_ALT}; }}
        .data-table tr:hover td {{ background: #0e3050; color: {C_BRIGHT}; }}
        .vuln-item {{
            border-left: 3px solid {C_BORDER};
            padding: 6px 10px;
            margin: 6px 0;
            background: {C_PANEL_ALT};
        }}
        .vuln-sev {{ font-weight: bold; margin-right: 6px; }}
        .vuln-title {{ color: {C_BRIGHT}; font-weight: bold; }}
        .vuln-desc {{ color: {C_TEXT}; margin-top: 4px; font-size: 11px; }}
        .timeline {{ border-left: 2px solid {C_BORDER}; padding-left: 12px; }}
        .tl-event {{ padding: 4px 0; display: flex; gap: 12px; }}
        .tl-time {{ color: {C_TEXT_DIM}; min-width: 160px; font-size: 11px; }}
        .tl-msg  {{ color: {C_TEXT}; }}
        .recs li {{ color: {C_TEXT}; margin: 4px 0 4px 20px; }}
        .exec-summary {{ color: {C_TEXT}; white-space: pre-wrap; }}
        .ai-summary {{ color: {C_TEXT}; white-space: pre-wrap; }}
        .appendix {{
            background: {C_BG};
            color: {C_TEXT_DIM};
            border: 1px solid {C_BORDER};
            padding: 10px;
            font-size: 11px;
            overflow-x: auto;
        }}
        .empty {{ color: {C_TEXT_DIM}; font-style: italic; }}
        .footer {{
            text-align: center;
            color: {C_TEXT_DIM};
            font-size: 10px;
            padding: 16px;
            border-top: 1px solid {C_BORDER};
            margin-top: 20px;
        }}
        """

    # ── JSON generator ────────────────────────────────────────────────────────

    def _gen_json(self, data: dict, path: str) -> bool:
        payload = dict(data)
        payload["_generated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        payload["_generator"]    = f"{TOOL_NAME} v{TOOL_VERSION}"
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, default=self._safe_str)
            return True
        except Exception:
            traceback.print_exc()
            return False

    # ── TXT generator ─────────────────────────────────────────────────────────

    def _gen_txt(self, data: dict, path: str) -> bool:
        meta     = data.get("metadata", {})
        sections = data.get("sections", SECTION_ORDER)
        ts       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        border_full = "=" * 72
        border_thin = "-" * 72

        def box(text: str) -> str:
            return f"{border_full}\n  {text}\n{border_full}"

        lines = []

        # Logo
        lines.extend(ASCII_LOGO)
        lines.append("")
        lines.append(box(f"{TOOL_NAME} v{TOOL_VERSION} — PENETRATION TEST REPORT"))
        lines.append("")

        # Metadata
        lines.append("ENGAGEMENT METADATA")
        lines.append(border_thin)
        for k, v in [
            ("Engagement",        meta.get("engagement_name", "")),
            ("Target Org",        meta.get("target_org",      "")),
            ("Operator",          meta.get("operator",        "")),
            ("Date",              meta.get("date",            "")),
            ("Classification",    meta.get("classification",  "")),
            ("Generated",         ts),
        ]:
            lines.append(f"  {k:<22}: {self._safe_str(v)}")
        lines.append("")

        # Sections
        for section in SECTION_ORDER:
            if section not in sections:
                continue
            lines.append(box(section.upper()))
            lines.append("")
            key   = SECTION_DATA_KEY.get(section, "")
            items = data.get(key, [])

            if section == "Executive Summary":
                text = meta.get("executive_summary", "") or self._safe_str(items)
                for ln in text.splitlines():
                    lines.append(f"  {ln}")

            elif section in ("WiFi Networks Found",
                             "Network Hosts", "Open Ports & Services",
                             "Discovered Credentials"):
                if not items:
                    lines.append("  (no data)")
                else:
                    for item in items:
                        lines.append("  " + "  |  ".join(
                            f"{k}: {self._safe_str(v)}"
                            for k, v in item.items()
                            if not k.startswith("_")
                        ))

            elif section == "Vulnerability Findings":
                if not items:
                    lines.append("  (no findings)")
                else:
                    for i, vuln in enumerate(items, 1):
                        sev   = self._safe_str(vuln.get("severity", "INFO"))
                        title = self._safe_str(vuln.get("title", vuln.get("type", "Unknown")))
                        desc  = self._safe_str(vuln.get("description", vuln.get("url", "")))
                        lines.append(f"  [{i:03d}] [{sev}] {title}")
                        lines.append(f"       {desc}")

            elif section == "Attack Timeline":
                if not items:
                    lines.append("  (no events)")
                else:
                    for ev in items:
                        t = self._safe_str(ev.get("time", ev.get("timestamp", "")))
                        m = self._safe_str(ev.get("message", ev.get("event", str(ev))))
                        lines.append(f"  {t:<22}  {m}")

            elif section == "Recommendations":
                if not items:
                    defaults = [
                        "Change all default credentials immediately.",
                        "Enable WPA3 on all wireless access points.",
                        "Disable WPS on all access points.",
                        "Segment wireless networks from wired infrastructure.",
                        "Deploy wireless intrusion detection/prevention systems.",
                        "Patch all identified vulnerabilities within SLA timelines.",
                    ]
                    for r in defaults:
                        lines.append(f"  • {r}")
                else:
                    for r in items:
                        lines.append(f"  • {self._safe_str(r)}")

            elif section == "Network Intelligence":
                if not items or not isinstance(items, dict):
                    lines.append("  (no network intelligence data)")
                else:
                    for k, v in items.items():
                        lines.append(f"  {self._safe_str(k):<28}: {self._safe_str(v)}")

            elif section == "Technical Appendix":
                lines.append(f"  Tool      : {TOOL_NAME} v{TOOL_VERSION}")
                lines.append(f"  Team      : {TEAM_NAME} — {TEAM_TAGLINE}")
                lines.append(f"  Generated : {ts}")
                lines.append(f"  License   : {LICENSE_TEXT}")
                if items:
                    lines.append("")
                    lines.append(f"  {self._safe_str(items)}")

            else:
                if items:
                    lines.append(f"  {self._safe_str(items)}")
                else:
                    lines.append("  (no data)")

            lines.append("")

        # Footer
        lines.append(border_full)
        lines.append(f"  {COPYRIGHT} — {LICENSE_TEXT}")
        lines.append(f"  Generated by {TOOL_NAME} v{TOOL_VERSION} on {ts}")
        lines.append(border_full)

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
            return True
        except Exception:
            traceback.print_exc()
            return False

    # ── PDF generator ─────────────────────────────────────────────────────────

    def _gen_pdf(self, data: dict, path: str) -> bool:
        """
        Generate a PDF report using reportlab.
        Raises ImportError if reportlab is not installed.
        Uses white background with dark navy text (practical for print/PDF).
        """
        if not self._has_reportlab:
            raise ImportError(
                "reportlab is not installed. Install it with: pip install reportlab"
            )

        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable,
        )
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.lib.enums import TA_CENTER

        meta     = data.get("metadata", {})
        sections = data.get("sections", SECTION_ORDER)
        ts       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Color palette for PDF (white bg, navy text, cyan headers)
        pdf_text  = colors.HexColor("#020508")
        pdf_panel = colors.HexColor("#f4f8fb")
        pdf_dim   = colors.HexColor("#3a6080")

        doc = SimpleDocTemplate(
            path,
            pagesize=A4,
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=18 * mm,
            bottomMargin=18 * mm,
            title=f"{TOOL_NAME} — Penetration Test Report",
            author=meta.get("operator", TEAM_NAME),
        )

        styles = getSampleStyleSheet()
        sty_title = ParagraphStyle(
            "DCTitle",
            parent=styles["Title"],
            fontSize=20,
            textColor=pdf_text,
            spaceAfter=6,
            fontName="Helvetica-Bold",
        )
        sty_h1 = ParagraphStyle(
            "DCH1",
            parent=styles["Heading1"],
            fontSize=13,
            textColor=colors.HexColor("#00a0cc"),
            spaceBefore=12,
            spaceAfter=4,
            fontName="Helvetica-Bold",
            borderPad=4,
        )
        sty_body = ParagraphStyle(
            "DCBody",
            parent=styles["Normal"],
            fontSize=9,
            textColor=pdf_text,
            leading=13,
        )
        sty_mono = ParagraphStyle(
            "DCMono",
            parent=styles["Code"],
            fontSize=8,
            textColor=pdf_dim,
            backColor=pdf_panel,
            leading=12,
        )
        sty_center = ParagraphStyle(
            "DCCenter",
            parent=styles["Normal"],
            fontSize=10,
            textColor=pdf_text,
            alignment=TA_CENTER,
        )
        sty_meta_key = ParagraphStyle(
            "DCMetaKey",
            parent=styles["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#00a0cc"),
            fontName="Helvetica-Bold",
        )

        def tbl_style_base():
            return TableStyle([
                ("BACKGROUND",  (0, 0), (-1, 0),  colors.HexColor("#004060")),
                ("TEXTCOLOR",   (0, 0), (-1, 0),  colors.white),
                ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
                ("FONTSIZE",    (0, 0), (-1, 0),  8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, pdf_panel]),
                ("TEXTCOLOR",   (0, 1), (-1, -1), pdf_text),
                ("FONTNAME",    (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE",    (0, 1), (-1, -1), 8),
                ("GRID",        (0, 0), (-1, -1), 0.4, colors.HexColor("#c0d8e8")),
                ("VALIGN",      (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING",  (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING",   (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
            ])

        story = []

        # ── Cover page ────────────────────────────────────────────────────────
        story.append(Spacer(1, 20 * mm))
        logo_text = "\n".join(ASCII_LOGO)
        story.append(Paragraph(
            f"<font color='#006688'><pre>{logo_text}</pre></font>",
            sty_mono
        ))
        story.append(Spacer(1, 8 * mm))
        story.append(Paragraph(f"{TOOL_NAME} v{TOOL_VERSION}", sty_title))
        story.append(Paragraph("Penetration Test Report", ParagraphStyle(
            "sub", parent=styles["Normal"],
            fontSize=14, textColor=pdf_dim, spaceAfter=10,
        )))

        classification = meta.get("classification", "CONFIDENTIAL")
        cls_color_map = {
            "CONFIDENTIAL": colors.HexColor("#cc8800"),
            "SECRET":       colors.HexColor("#cc0022"),
            "PUBLIC":       colors.HexColor("#00aa66"),
        }
        cls_color = cls_color_map.get(classification, colors.HexColor("#cc8800"))

        story.append(Paragraph(
            f"<font color='#{cls_color.hexval()[2:]}'><b>◆ {classification} ◆</b></font>",
            sty_center
        ))
        story.append(Spacer(1, 8 * mm))

        cover_data = [
            [Paragraph("<b>Engagement</b>",        sty_meta_key), Paragraph(self._safe_str(meta.get("engagement_name")), sty_body)],
            [Paragraph("<b>Target Organization</b>",sty_meta_key), Paragraph(self._safe_str(meta.get("target_org")),      sty_body)],
            [Paragraph("<b>Operator</b>",           sty_meta_key), Paragraph(self._safe_str(meta.get("operator")),        sty_body)],
            [Paragraph("<b>Date</b>",               sty_meta_key), Paragraph(self._safe_str(meta.get("date")),            sty_body)],
            [Paragraph("<b>Generated</b>",          sty_meta_key), Paragraph(ts,                                          sty_body)],
        ]
        cover_tbl = Table(cover_data, colWidths=[55 * mm, None])
        cover_tbl.setStyle(TableStyle([
            ("GRID",       (0, 0), (-1, -1), 0.4, colors.HexColor("#c0d8e8")),
            ("BACKGROUND", (0, 0), (0, -1),  pdf_panel),
            ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(cover_tbl)
        story.append(Spacer(1, 6 * mm))

        exec_sum = meta.get("executive_summary", "")
        if exec_sum:
            story.append(Paragraph("Executive Summary", sty_h1))
            story.append(Paragraph(exec_sum.replace("\n", "<br/>"), sty_body))

        story.append(PageBreak())

        # ── Table of Contents ─────────────────────────────────────────────────
        story.append(Paragraph("TABLE OF CONTENTS", sty_h1))
        story.append(HRFlowable(width="100%", thickness=0.5,
                                color=colors.HexColor("#c0d8e8")))
        story.append(Spacer(1, 3 * mm))
        toc_num = 1
        for section in SECTION_ORDER:
            if section in sections:
                story.append(Paragraph(
                    f"{toc_num}. {section}",
                    ParagraphStyle("toc", parent=styles["Normal"],
                                   fontSize=10, textColor=pdf_text,
                                   leftIndent=10, spaceAfter=3)
                ))
                toc_num += 1
        story.append(PageBreak())

        # ── Section pages ─────────────────────────────────────────────────────
        for section in SECTION_ORDER:
            if section not in sections:
                continue

            story.append(Paragraph(section.upper(), sty_h1))
            story.append(HRFlowable(width="100%", thickness=0.5,
                                    color=colors.HexColor("#c0d8e8")))
            story.append(Spacer(1, 3 * mm))

            key   = SECTION_DATA_KEY.get(section, "")
            items = data.get(key, [])

            if section == "Executive Summary":
                text = meta.get("executive_summary", "") or self._safe_str(items)
                story.append(Paragraph(text.replace("\n", "<br/>"), sty_body))

            elif section == "WiFi Networks Found":
                self._pdf_table(story, items,
                                ["SSID", "BSSID", "Channel", "Security", "Signal", "WPS"],
                                ["ssid", "bssid", "channel", "security", "signal", "wps"],
                                sty_body, tbl_style_base)

            elif section == "Network Hosts":
                self._pdf_table(story, items,
                                ["IP Address", "MAC", "Hostname", "OS", "Ports"],
                                ["ip", "mac", "hostname", "os", "ports"],
                                sty_body, tbl_style_base)

            elif section == "Open Ports & Services":
                self._pdf_table(story, items,
                                ["Host", "Port", "Protocol", "Service", "Version", "Risk"],
                                ["host", "port", "protocol", "service", "version", "risk"],
                                sty_body, tbl_style_base)

            elif section == "Discovered Credentials":
                self._pdf_table(story, items,
                                ["Service", "Host", "Port", "Username", "Password",
                                 "Status", "Source"],
                                ["service", "host", "port", "username", "password",
                                 "status", "source"],
                                sty_body, tbl_style_base)

            elif section == "Vulnerability Findings":
                if not items:
                    story.append(Paragraph("No vulnerability findings recorded.", sty_body))
                else:
                    for vuln in items:
                        sev   = self._safe_str(vuln.get("severity", "INFO")).upper()
                        title = self._safe_str(vuln.get("title", vuln.get("type", "Unknown")))
                        desc  = self._safe_str(vuln.get("description", vuln.get("url", "")))
                        sev_c_map = {
                            "CRITICAL": "#cc0022", "HIGH": "#cc3300",
                            "MEDIUM":   "#cc8800", "LOW":  "#007744", "INFO": "#005588",
                        }
                        sev_hex = sev_c_map.get(sev, "#005588")
                        story.append(Paragraph(
                            f"<font color='{sev_hex}'>[{sev}]</font>  <b>{title}</b>",
                            sty_body
                        ))
                        story.append(Paragraph(desc, ParagraphStyle(
                            "vd", parent=styles["Normal"],
                            fontSize=8, textColor=pdf_dim,
                            leftIndent=20, spaceAfter=4,
                        )))

            elif section == "Attack Timeline":
                if not items:
                    story.append(Paragraph("No timeline events recorded.", sty_body))
                else:
                    tl_data = [["Time", "Event"]]
                    for ev in items:
                        t = self._safe_str(ev.get("time", ev.get("timestamp", "")))
                        m = self._safe_str(ev.get("message", ev.get("event", str(ev))))
                        tl_data.append([t, m])
                    tl_tbl = Table(tl_data, colWidths=[45 * mm, None])
                    tl_tbl.setStyle(tbl_style_base())
                    story.append(tl_tbl)

            elif section == "Recommendations":
                recs = items or [
                    "Change all default credentials immediately.",
                    "Enable WPA3 on all wireless access points.",
                    "Disable WPS on all access points.",
                    "Segment wireless networks from wired infrastructure.",
                    "Deploy wireless intrusion detection/prevention systems.",
                    "Patch all identified vulnerabilities within SLA timelines.",
                    "Enable logging and alerting on all network devices.",
                ]
                for rec in recs:
                    story.append(Paragraph(
                        f"• {self._safe_str(rec)}",
                        ParagraphStyle("rec", parent=styles["Normal"],
                                       fontSize=9, textColor=pdf_text,
                                       leftIndent=10, spaceAfter=4)
                    ))

            elif section == "Technical Appendix":
                appendix_lines = [
                    f"Tool:      {TOOL_NAME} v{TOOL_VERSION}",
                    f"Team:      {TEAM_NAME} — {TEAM_TAGLINE}",
                    f"Generated: {ts}",
                    f"License:   {LICENSE_TEXT}",
                ]
                if items:
                    appendix_lines.append(self._safe_str(items))
                story.append(Paragraph(
                    "\n".join(appendix_lines).replace("\n", "<br/>"),
                    sty_mono
                ))

            else:
                if items:
                    story.append(Paragraph(self._safe_str(items), sty_body))
                else:
                    story.append(Paragraph("No data available.", sty_body))

            story.append(Spacer(1, 4 * mm))
            story.append(PageBreak())

        # Build PDF
        doc.build(story)
        return True

    def _pdf_table(self, story: list, items: list, headers: list, keys: list,
                   sty_body, tbl_style_fn):
        """Append a generic table to the PDF story list."""
        if not items:
            from reportlab.platypus import Paragraph
            story.append(Paragraph("No data recorded.", sty_body))
            return

        from reportlab.platypus import Table
        table_data = [headers]
        for item in items:
            row = [self._safe_str(item.get(k, "")) for k in keys]
            table_data.append(row)

        tbl = Table(table_data, repeatRows=1)
        tbl.setStyle(tbl_style_fn())
        story.append(tbl)

    # ── Utility ───────────────────────────────────────────────────────────────

    @staticmethod
    def _safe_str(val) -> str:
        """Convert any value to a safe string for table/report rendering."""
        if val is None:
            return ""
        if isinstance(val, list):
            if not val:
                return ""
            return ", ".join(ReportGenerator._safe_str(v) for v in val[:8])
        if isinstance(val, dict):
            return " | ".join(
                f"{k}: {ReportGenerator._safe_str(v)}"
                for k, v in list(val.items())[:6]
            )
        if isinstance(val, bool):
            return "Yes" if val else "No"
        return str(val)
