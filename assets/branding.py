"""
assets/branding.py — DARK CRACKER OPS team branding.
Edit TEAM_NAME, TOOL_NAME, and TOOL_COLORS to customize.
"""

TOOL_NAME    = "DARK CRACKER OPS"
TOOL_VERSION = "2.0.0"
TOOL_GEN     = "Generation 2"
TEAM_NAME    = "DARK SEA"
TEAM_TAGLINE = "Elite WiFi Penetration Suite"
TEAM_WEBSITE = "darkseaops.io"
COPYRIGHT    = "© 2025 DARK SEA TEAM"
LICENSE_TEXT = "For Authorized Penetration Testing Only"

TOOL_COLORS = {
    "background":    "#020508",
    "panel":         "#060d14",
    "panel_alt":     "#0a1628",
    "border":        "#0e1f30",
    "border_active": "#00e5ff",
    "accent":        "#00e5ff",
    "accent2":       "#00ff88",
    "danger":        "#ff2244",
    "warning":       "#ffc800",
    "text":          "#a8c8e0",
    "text_dim":      "#3a6080",
    "text_bright":   "#e0f0ff",
    "selection":     "#0e3050",
}

ASCII_LOGO = [
    "██████╗  █████╗ ██████╗ ██╗  ██╗",
    "██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝",
    "██║  ██║███████║██████╔╝█████╔╝ ",
    "██║  ██║██╔══██║██╔══██╗██╔═██╗ ",
    "██████╔╝██║  ██║██║  ██║██║  ██╗",
    "╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝",
    "      CRACKER OPS — Gen 2        ",
]


def get_window_title() -> str:
    """Return the full window title string."""
    return f"{TOOL_NAME} v{TOOL_VERSION} — {TEAM_NAME} | {LICENSE_TEXT}"


def get_splash_lines() -> list:
    """Return all lines for the splash / boot screen."""
    return ASCII_LOGO + [
        f"  {TEAM_NAME} — {TEAM_TAGLINE}",
        f"  {COPYRIGHT}",
        f"  {LICENSE_TEXT}",
    ]


def get_report_header_html() -> str:
    """Return an HTML block for use at the top of HTML reports."""
    return f"""
    <div style="background:#020508;padding:20px;border-bottom:2px solid #00e5ff;">
        <pre style="color:#00e5ff;font-family:monospace;font-size:11px;margin:0">{chr(10).join(ASCII_LOGO)}</pre>
        <h2 style="color:#00e5ff;font-family:monospace;margin:8px 0 4px">{TOOL_NAME} v{TOOL_VERSION}</h2>
        <p style="color:#a8c8e0;margin:0">{TEAM_NAME} — {TEAM_TAGLINE}</p>
        <p style="color:#3a6080;font-size:0.8em;margin:4px 0 0">{COPYRIGHT} | {LICENSE_TEXT}</p>
    </div>
    """
