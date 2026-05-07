from core.worker import BaseWorker
"""
modules/theme_engine.py — Runtime theme management for DARK CRACKER OPS.
Pre-built themes: Dark Sea (default), Dracula, Nord, Monokai, Solarized Dark, Blood Red, Matrix Green.
Themes saved/loaded from ~/.darkcracker/theme.json.
"""
import json
import os
from dataclasses import dataclass, asdict
from typing import Optional



@dataclass
class Theme:
    """Represents a complete UI theme with all color and font settings."""

    name:          str   = "Dark Sea"
    bg:            str   = "#020508"
    panel:         str   = "#060d14"
    panel_alt:     str   = "#0a1628"
    border:        str   = "#0e1f30"
    border_active: str   = "#00e5ff"
    accent:        str   = "#00e5ff"
    accent2:       str   = "#00ff88"
    danger:        str   = "#ff2244"
    warning:       str   = "#ffc800"
    text:          str   = "#a8c8e0"
    text_dim:      str   = "#3a6080"
    text_bright:   str   = "#e0f0ff"
    selection:     str   = "#0e3050"
    font_family:   str   = "Consolas"
    font_size:     int   = 12

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Serialize theme to a plain dictionary."""
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Theme":
        """Deserialize a Theme from a dictionary, ignoring unknown keys."""
        valid_fields = Theme.__dataclass_fields__.keys()
        filtered = {k: v for k, v in d.items() if k in valid_fields}
        return Theme(**filtered)

    # ── QSS generation ────────────────────────────────────────────────────────

    def to_qss(self) -> str:
        """
        Generate a complete QSS stylesheet from this theme's colors.
        Mirrors the structure of gui/styles.py with substituted palette.
        """
        bg            = self.bg
        panel         = self.panel
        panel_alt     = self.panel_alt
        border        = self.border
        _border_active = self.border_active  # reserved for focus-ring styling
        accent        = self.accent
        accent2       = self.accent2
        danger        = self.danger
        warning       = self.warning
        text          = self.text
        text_dim      = self.text_dim
        text_bright   = self.text_bright
        selection     = self.selection
        font          = f'"{self.font_family}", "Consolas", "Courier New", monospace'
        fsize         = self.font_size

        # Derive secondary tones (darkened accent for pressed/active states)
        def _darken_hex(hex_color: str, factor: float = 0.4) -> str:
            """Return a darkened version of a hex color by blending with black."""
            h = hex_color.lstrip("#")
            if len(h) == 6:
                r = int(int(h[0:2], 16) * factor)
                g = int(int(h[2:4], 16) * factor)
                b = int(int(h[4:6], 16) * factor)
                return f"#{r:02x}{g:02x}{b:02x}"
            return hex_color

        accent_dark    = _darken_hex(accent,   0.35)
        _accent2_dark  = _darken_hex(accent2,  0.25)  # reserved for future use
        _danger_dark   = _darken_hex(danger,   0.35)  # reserved for future use
        _warning_dark  = _darken_hex(warning,  0.35)  # reserved for future use

        return f"""
/* ════════════════════════════════════════════════════════════════════════════
   DARK CRACKER OPS — Dynamic QSS Stylesheet (Theme: {self.name})
   ════════════════════════════════════════════════════════════════════════════ */

/* ── Global / Application window ─────────────────────────────────────────── */
QWidget {{
    background-color: {bg};
    color: {text};
    font-family: {font};
    font-size: {fsize}px;
    selection-background-color: {selection};
    selection-color: {accent};
    border: none;
    outline: none;
}}

QMainWindow {{
    background-color: {bg};
}}

QMainWindow::separator {{
    background-color: {border};
    width: 1px;
    height: 1px;
}}

/* ── Menu bar ─────────────────────────────────────────────────────────────── */
QMenuBar {{
    background-color: {panel};
    color: {text};
    border-bottom: 1px solid {border};
    padding: 2px 4px;
    spacing: 2px;
}}

QMenuBar::item {{
    background-color: transparent;
    padding: 4px 10px;
    border-radius: 2px;
}}

QMenuBar::item:selected {{
    background-color: {selection};
    color: {accent};
}}

QMenuBar::item:pressed {{
    background-color: {accent_dark};
    color: {accent};
}}

QMenu {{
    background-color: {panel};
    color: {text};
    border: 1px solid {border};
    padding: 4px 0;
}}

QMenu::item {{
    padding: 5px 24px 5px 16px;
    background-color: transparent;
}}

QMenu::item:selected {{
    background-color: {selection};
    color: {accent};
}}

QMenu::item:disabled {{
    color: {text_dim};
}}

QMenu::separator {{
    height: 1px;
    background-color: {border};
    margin: 3px 6px;
}}

QMenu::indicator {{
    width: 14px;
    height: 14px;
}}

/* ── Tab widget ───────────────────────────────────────────────────────────── */
QTabWidget {{
    background-color: {panel};
    border: none;
}}

QTabWidget::pane {{
    background-color: {panel};
    border: 1px solid {border};
    border-top: none;
}}

QTabWidget::tab-bar {{
    alignment: left;
}}

QTabBar {{
    background-color: {bg};
    border-bottom: 1px solid {border};
}}

QTabBar::tab {{
    background-color: {bg};
    color: {text_dim};
    border: none;
    border-bottom: 2px solid transparent;
    min-width: 120px;
    min-height: 32px;
    padding: 0 16px;
    margin-right: 1px;
    font-weight: normal;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}

QTabBar::tab:selected {{
    background-color: {panel};
    color: {accent};
    border-bottom: 2px solid {accent};
}}

QTabBar::tab:hover:!selected {{
    background-color: {panel};
    color: {text};
    border-bottom: 2px solid {border};
}}

QTabBar::tab:disabled {{
    color: {text_dim};
}}

/* ── Table widget ─────────────────────────────────────────────────────────── */
QTableWidget {{
    background-color: {panel};
    alternate-background-color: {panel_alt};
    color: {text};
    gridline-color: transparent;
    border: 1px solid {border};
    border-radius: 0;
    selection-background-color: {selection};
    selection-color: {accent};
    show-decoration-selected: 1;
}}

QTableWidget::item {{
    padding: 4px 8px;
    border: none;
}}

QTableWidget::item:selected {{
    background-color: {selection};
    color: {accent};
}}

QTableWidget::item:hover {{
    background-color: {panel_alt};
}}

QHeaderView {{
    background-color: {panel_alt};
    color: {text_dim};
    border: none;
}}

QHeaderView::section {{
    background-color: {panel_alt};
    color: {text_dim};
    border: none;
    border-right: 1px solid {border};
    border-bottom: 1px solid {border};
    padding: 5px 8px;
    font-weight: bold;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-size: {max(9, fsize - 1)}px;
}}

QHeaderView::section:hover {{
    background-color: {border};
    color: {text};
}}

QHeaderView::section:checked {{
    color: {accent};
}}

QHeaderView::section:first {{
    border-left: none;
}}

/* ── List widget ──────────────────────────────────────────────────────────── */
QListWidget {{
    background-color: {panel};
    color: {text};
    border: 1px solid {border};
    alternate-background-color: {panel_alt};
    selection-background-color: {selection};
    selection-color: {accent};
}}

QListWidget::item {{
    padding: 4px 8px;
    border: none;
}}

QListWidget::item:selected {{
    background-color: {selection};
    color: {accent};
}}

QListWidget::item:hover {{
    background-color: {panel_alt};
}}

/* ── Push buttons ─────────────────────────────────────────────────────────── */
QPushButton {{
    background-color: {panel_alt};
    color: {text};
    border: 1px solid {border};
    border-radius: 2px;
    padding: 5px 14px;
    min-height: 26px;
    min-width: 70px;
    font-family: {font};
    font-size: {fsize}px;
}}

QPushButton:hover {{
    background-color: {border};
    color: {accent};
    border: 1px solid {accent};
}}

QPushButton:pressed {{
    background-color: {accent_dark};
    color: {accent};
    border: 1px solid {accent};
}}

QPushButton:disabled {{
    background-color: {panel};
    color: {text_dim};
    border: 1px solid {border};
}}

QPushButton:checked {{
    background-color: {accent_dark};
    color: {accent};
    border: 1px solid {accent};
}}

/* ── Line edit ────────────────────────────────────────────────────────────── */
QLineEdit {{
    background-color: {panel_alt};
    color: {text};
    border: 1px solid {border};
    border-radius: 2px;
    padding: 4px 8px;
    min-height: 24px;
    selection-background-color: {selection};
    selection-color: {accent};
}}

QLineEdit:focus {{
    border: 1px solid {accent};
    color: {text_bright};
}}

QLineEdit:disabled {{
    background-color: {panel};
    color: {text_dim};
    border: 1px solid {panel_alt};
}}

QLineEdit:read-only {{
    background-color: {panel};
    color: {text_dim};
}}

/* ── Combo box ────────────────────────────────────────────────────────────── */
QComboBox {{
    background-color: {panel_alt};
    color: {text};
    border: 1px solid {border};
    border-radius: 2px;
    padding: 4px 8px;
    min-height: 24px;
    min-width: 80px;
}}

QComboBox:hover {{
    border: 1px solid {accent};
    color: {text_bright};
}}

QComboBox:focus {{
    border: 1px solid {accent};
}}

QComboBox:disabled {{
    background-color: {panel};
    color: {text_dim};
    border: 1px solid {panel_alt};
}}

QComboBox::drop-down {{
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 22px;
    border-left: 1px solid {border};
    background-color: {panel_alt};
}}

QComboBox::down-arrow {{
    width: 10px;
    height: 10px;
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid {text_dim};
}}

QComboBox::down-arrow:hover {{
    border-top-color: {accent};
}}

QComboBox QAbstractItemView {{
    background-color: {panel};
    color: {text};
    border: 1px solid {border};
    selection-background-color: {selection};
    selection-color: {accent};
    outline: none;
}}

QComboBox QAbstractItemView::item {{
    padding: 4px 8px;
    min-height: 22px;
}}

QComboBox QAbstractItemView::item:hover {{
    background-color: {panel_alt};
}}

/* ── Spin box ─────────────────────────────────────────────────────────────── */
QSpinBox, QDoubleSpinBox {{
    background-color: {panel_alt};
    color: {text};
    border: 1px solid {border};
    border-radius: 2px;
    padding: 4px 8px;
    min-height: 24px;
}}

QSpinBox:focus, QDoubleSpinBox:focus {{
    border: 1px solid {accent};
}}

QSpinBox::up-button, QDoubleSpinBox::up-button,
QSpinBox::down-button, QDoubleSpinBox::down-button {{
    background-color: {panel_alt};
    border-left: 1px solid {border};
    width: 18px;
}}

QSpinBox::up-button:hover, QDoubleSpinBox::up-button:hover,
QSpinBox::down-button:hover, QDoubleSpinBox::down-button:hover {{
    background-color: {border};
}}

QSpinBox::up-arrow, QDoubleSpinBox::up-arrow {{
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-bottom: 5px solid {text_dim};
    width: 0;
    height: 0;
}}

QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {{
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid {text_dim};
    width: 0;
    height: 0;
}}

/* ── Text edit ────────────────────────────────────────────────────────────── */
QTextEdit, QPlainTextEdit {{
    background-color: {panel};
    color: {text};
    border: 1px solid {border};
    font-family: {font};
    font-size: {fsize}px;
    selection-background-color: {selection};
    selection-color: {accent};
    padding: 4px;
}}

QTextEdit:focus, QPlainTextEdit:focus {{
    border: 1px solid {accent};
}}

/* ── Labels ───────────────────────────────────────────────────────────────── */
QLabel {{
    color: {text};
    background-color: transparent;
    padding: 0;
}}

QLabel:disabled {{
    color: {text_dim};
}}

/* ── Group box ────────────────────────────────────────────────────────────── */
QGroupBox {{
    background-color: {panel};
    border: 1px solid {border};
    border-top: 2px solid {border};
    margin-top: 8px;
    padding-top: 10px;
    font-weight: bold;
    color: {text_dim};
    text-transform: uppercase;
    font-size: {max(9, fsize - 1)}px;
    letter-spacing: 0.5px;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 6px;
    left: 10px;
    top: -1px;
    color: {text_dim};
    background-color: {panel};
}}

QGroupBox:focus {{
    border: 1px solid {accent};
    border-top: 2px solid {accent};
}}

/* ── Progress bar ─────────────────────────────────────────────────────────── */
QProgressBar {{
    background-color: {panel_alt};
    border: 1px solid {border};
    border-radius: 2px;
    min-height: 10px;
    max-height: 14px;
    text-align: center;
    color: transparent;
}}

QProgressBar::chunk {{
    background-color: {accent};
    border-radius: 1px;
}}

/* ── Scroll bar ───────────────────────────────────────────────────────────── */
QScrollBar:vertical {{
    background-color: {panel};
    width: 8px;
    margin: 0;
    border: none;
}}

QScrollBar::handle:vertical {{
    background-color: {border};
    min-height: 20px;
    border-radius: 4px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {accent};
}}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {{
    height: 0;
    background: none;
}}

QScrollBar::add-page:vertical,
QScrollBar::sub-page:vertical {{
    background: none;
}}

QScrollBar:horizontal {{
    background-color: {panel};
    height: 8px;
    margin: 0;
    border: none;
}}

QScrollBar::handle:horizontal {{
    background-color: {border};
    min-width: 20px;
    border-radius: 4px;
}}

QScrollBar::handle:horizontal:hover {{
    background-color: {accent};
}}

QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal {{
    width: 0;
    background: none;
}}

QScrollBar::add-page:horizontal,
QScrollBar::sub-page:horizontal {{
    background: none;
}}

/* ── Splitter ─────────────────────────────────────────────────────────────── */
QSplitter::handle {{
    background-color: {border};
}}

QSplitter::handle:horizontal {{
    width: 1px;
}}

QSplitter::handle:vertical {{
    height: 1px;
}}

QSplitter::handle:hover {{
    background-color: {accent};
}}

/* ── Check box ────────────────────────────────────────────────────────────── */
QCheckBox {{
    color: {text};
    spacing: 6px;
    background-color: transparent;
}}

QCheckBox:disabled {{
    color: {text_dim};
}}

QCheckBox::indicator {{
    width: 14px;
    height: 14px;
    background-color: {panel_alt};
    border: 1px solid {border};
    border-radius: 2px;
}}

QCheckBox::indicator:checked {{
    background-color: {accent_dark};
    border: 1px solid {accent};
}}

QCheckBox::indicator:hover {{
    border: 1px solid {accent};
}}

/* ── Radio button ─────────────────────────────────────────────────────────── */
QRadioButton {{
    color: {text};
    spacing: 6px;
    background-color: transparent;
}}

QRadioButton::indicator {{
    width: 14px;
    height: 14px;
    background-color: {panel_alt};
    border: 1px solid {border};
    border-radius: 7px;
}}

QRadioButton::indicator:checked {{
    background-color: {accent};
    border: 2px solid {accent_dark};
}}

QRadioButton::indicator:hover {{
    border: 1px solid {accent};
}}

/* ── Slider ───────────────────────────────────────────────────────────────── */
QSlider::groove:horizontal {{
    background-color: {panel_alt};
    height: 4px;
    border-radius: 2px;
}}

QSlider::handle:horizontal {{
    background-color: {accent};
    width: 12px;
    height: 12px;
    border-radius: 6px;
    margin: -4px 0;
}}

QSlider::sub-page:horizontal {{
    background-color: {accent};
    height: 4px;
    border-radius: 2px;
}}

/* ── Tool tip ─────────────────────────────────────────────────────────────── */
QToolTip {{
    background-color: {panel};
    color: {text};
    border: 1px solid {accent};
    padding: 4px 8px;
    font-family: {font};
    font-size: {max(9, fsize - 1)}px;
    opacity: 230;
}}

/* ── Status bar ───────────────────────────────────────────────────────────── */
QStatusBar {{
    background-color: {panel};
    color: {text_dim};
    border-top: 1px solid {border};
    font-size: {max(9, fsize - 1)}px;
    padding: 2px 8px;
}}

QStatusBar::item {{
    border: none;
}}

QStatusBar QLabel {{
    color: {text_dim};
    background-color: transparent;
}}

/* ── Tool bar ─────────────────────────────────────────────────────────────── */
QToolBar {{
    background-color: {panel};
    border-bottom: 1px solid {border};
    spacing: 4px;
    padding: 2px 4px;
}}

QToolBar::separator {{
    background-color: {border};
    width: 1px;
    margin: 4px 4px;
}}

QToolButton {{
    background-color: transparent;
    color: {text};
    border: 1px solid transparent;
    border-radius: 2px;
    padding: 3px 6px;
}}

QToolButton:hover {{
    background-color: {border};
    color: {accent};
    border: 1px solid {border};
}}

QToolButton:pressed {{
    background-color: {accent_dark};
}}

QToolButton:checked {{
    background-color: {accent_dark};
    color: {accent};
    border: 1px solid {accent};
}}

/* ── Dialog ───────────────────────────────────────────────────────────────── */
QDialog {{
    background-color: {panel};
    color: {text};
}}

QDialogButtonBox QPushButton {{
    min-width: 80px;
}}

/* ── Frame ────────────────────────────────────────────────────────────────── */
QFrame {{
    background-color: transparent;
    border: none;
}}

QFrame[frameShape="4"],
QFrame[frameShape="5"] {{
    color: {border};
}}

/* ── Stack / Scroll area ──────────────────────────────────────────────────── */
QStackedWidget {{
    background-color: {panel};
}}

QScrollArea {{
    background-color: {panel};
    border: 1px solid {border};
}}

QScrollArea > QWidget > QWidget {{
    background-color: {panel};
}}

/* ── Dock widget ──────────────────────────────────────────────────────────── */
QDockWidget {{
    background-color: {panel};
    titlebar-close-icon: none;
    titlebar-normal-icon: none;
}}

QDockWidget::title {{
    background-color: {panel_alt};
    padding: 4px 8px;
    text-align: left;
    color: {text_dim};
    font-size: {max(9, fsize - 1)}px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 1px solid {border};
}}

/* ── Tree widget ──────────────────────────────────────────────────────────── */
QTreeWidget {{
    background-color: {panel};
    alternate-background-color: {panel_alt};
    color: {text};
    border: 1px solid {border};
    selection-background-color: {selection};
    selection-color: {accent};
    show-decoration-selected: 1;
}}

QTreeWidget::item {{
    padding: 3px 4px;
    border: none;
}}

QTreeWidget::item:selected {{
    background-color: {selection};
    color: {accent};
}}

QTreeWidget::item:hover {{
    background-color: {panel_alt};
}}

QTreeWidget::branch {{
    background-color: {panel};
}}

/* ── Tab bar close button ─────────────────────────────────────────────────── */
QTabBar::close-button {{
    image: none;
    subcontrol-position: right;
}}
"""


# ── Built-in theme definitions ────────────────────────────────────────────────

BUILT_IN_THEMES: dict = {
    "Dark Sea": Theme(
        name="Dark Sea",
        bg="#020508", panel="#060d14", panel_alt="#0a1628",
        border="#0e1f30", border_active="#00e5ff",
        accent="#00e5ff", accent2="#00ff88",
        danger="#ff2244", warning="#ffc800",
        text="#a8c8e0", text_dim="#3a6080", text_bright="#e0f0ff",
        selection="#0e3050",
        font_family="Consolas", font_size=12,
    ),
    "Dracula": Theme(
        name="Dracula",
        bg="#282a36", panel="#21222c", panel_alt="#2d2f3f",
        border="#44475a", border_active="#bd93f9",
        accent="#bd93f9", accent2="#50fa7b",
        danger="#ff5555", warning="#ffb86c",
        text="#f8f8f2", text_dim="#6272a4", text_bright="#ffffff",
        selection="#44475a",
        font_family="Consolas", font_size=12,
    ),
    "Nord": Theme(
        name="Nord",
        bg="#2e3440", panel="#3b4252", panel_alt="#434c5e",
        border="#4c566a", border_active="#88c0d0",
        accent="#88c0d0", accent2="#a3be8c",
        danger="#bf616a", warning="#ebcb8b",
        text="#d8dee9", text_dim="#4c566a", text_bright="#eceff4",
        selection="#434c5e",
        font_family="Consolas", font_size=12,
    ),
    "Monokai": Theme(
        name="Monokai",
        bg="#272822", panel="#1e1f1c", panel_alt="#2d2e2a",
        border="#3e3d32", border_active="#a6e22e",
        accent="#a6e22e", accent2="#66d9e8",
        danger="#f92672", warning="#e6db74",
        text="#f8f8f2", text_dim="#75715e", text_bright="#ffffff",
        selection="#49483e",
        font_family="Consolas", font_size=12,
    ),
    "Solarized Dark": Theme(
        name="Solarized Dark",
        bg="#002b36", panel="#073642", panel_alt="#074049",
        border="#586e75", border_active="#2aa198",
        accent="#2aa198", accent2="#859900",
        danger="#dc322f", warning="#b58900",
        text="#839496", text_dim="#586e75", text_bright="#eee8d5",
        selection="#073642",
        font_family="Consolas", font_size=12,
    ),
    "Blood Red": Theme(
        name="Blood Red",
        bg="#0a0000", panel="#140000", panel_alt="#1e0000",
        border="#3a0000", border_active="#ff2244",
        accent="#ff2244", accent2="#ff6644",
        danger="#ff0000", warning="#ff8800",
        text="#ffaaaa", text_dim="#662222", text_bright="#ffffff",
        selection="#3a0000",
        font_family="Consolas", font_size=12,
    ),
    "Matrix Green": Theme(
        name="Matrix Green",
        bg="#000300", panel="#001200", panel_alt="#002200",
        border="#003300", border_active="#00ff41",
        accent="#00ff41", accent2="#00cc33",
        danger="#ff0000", warning="#aaff00",
        text="#00bb2d", text_dim="#005500", text_bright="#00ff41",
        selection="#003300",
        font_family="Consolas", font_size=12,
    ),
}

# Config file path
_CONFIG_DIR  = os.path.expanduser("~/.darkcracker")
_CONFIG_FILE = os.path.join(_CONFIG_DIR, "theme.json")

# ── Singleton ─────────────────────────────────────────────────────────────────

_instance: Optional["ThemeEngine"] = None


def get_theme_engine() -> "ThemeEngine":
    """Return the global ThemeEngine singleton, creating it if necessary."""
    global _instance
    if _instance is None:
        _instance = ThemeEngine()
    return _instance


class ThemeEngine(object):
    """
    Runtime theme manager — loads, applies, and saves UI themes.

    Signals:
        theme_changed(name: str, qss: str)
    """

    def __init__(self, parent=None):
        super().__init__()
        self._current_theme: Theme = BUILT_IN_THEMES["Dark Sea"]
        self._custom_themes: dict[str, Theme] = {}
        self._load_saved_theme()

    # ── Private helpers ───────────────────────────────────────────────────────

    def _load_saved_theme(self):
        """Load the previously saved theme from disk."""
        if not os.path.isfile(_CONFIG_FILE):
            return
        try:
            with open(_CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            theme_name = data.get("active_theme", "Dark Sea")
            # Check builtins first
            if theme_name in BUILT_IN_THEMES:
                self._current_theme = BUILT_IN_THEMES[theme_name]
                return
            # Try custom theme stored inline
            custom_data = data.get("custom_themes", {})
            if theme_name in custom_data:
                self._custom_themes[theme_name] = Theme.from_dict(custom_data[theme_name])
                self._current_theme = self._custom_themes[theme_name]
                return
        except Exception:
            pass  # Fall back to default silently

    def _save_config(self):
        """Persist the active theme name (and any custom themes) to disk."""
        try:
            os.makedirs(_CONFIG_DIR, exist_ok=True)
            custom_serial = {n: t.to_dict() for n, t in self._custom_themes.items()}
            data = {
                "active_theme":  self._current_theme.name,
                "custom_themes": custom_serial,
            }
            with open(_CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass  # Non-fatal — theme just won't persist

    def _all_themes(self) -> dict:
        merged = dict(BUILT_IN_THEMES)
        merged.update(self._custom_themes)
        return merged

    # ── Public API ────────────────────────────────────────────────────────────

    def get_current_theme(self) -> Theme:
        """Return the currently active Theme."""
        return self._current_theme

    def get_theme_names(self) -> list:
        """Return all available theme names (built-in + custom)."""
        return list(self._all_themes().keys())

    def get_builtin_themes(self) -> dict:
        """Return the dict of built-in Theme objects keyed by name."""
        return dict(BUILT_IN_THEMES)

    def apply_theme(self, name: str, app=None):
        """
        Switch to a named theme.
        Saves the selection and emits theme_changed.
        """
        themes = self._all_themes()
        if name not in themes:
            return
        self._current_theme = themes[name]
        qss = self._current_theme.to_qss()
        self._save_config()
        self._safe_emit("theme_changed", name, qss)

    def apply_custom_theme(self, theme: "Theme", app=None):
        """
        Apply a Theme object directly (without saving it as a named custom theme).
        """
        self._current_theme = theme
        qss = theme.to_qss()
        self._safe_emit("theme_changed", theme.name, qss)

    def save_theme(self, theme: Theme, name: str):
        """
        Persist a custom theme under the given name and activate it.
        """
        theme.name = name
        self._custom_themes[name] = theme
        self._current_theme = theme
        self._save_config()
        self._safe_emit("theme_changed", name, theme.to_qss())
