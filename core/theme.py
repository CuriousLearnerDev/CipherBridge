"""密桥全局主题 — 工位工具风 QSS（扁、少色、少圆角），支持亮/暗切换."""

from __future__ import annotations

import os
from PyQt6.QtGui import QFont, QPalette, QColor
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QLabel, QWidget, QComboBox, QPushButton, QVBoxLayout, QFrame

# 视觉原则：单强调色、直角偏多、少卡片堆叠；绿色只表示「运行中」，不做按钮主色。
PALETTES: dict[str, dict[str, str]] = {
    "dark": {
        "bg": "#161718",
        "surface": "#1e1f21",
        "surface2": "#27282a",
        "border": "#353638",
        "text": "#c8c9cb",
        "text_dim": "#7a7c80",
        "accent": "#8a9aab",
        "primary": "#8a9aab",
        "danger": "#b87a72",
        "warn": "#b89a5a",
        "ok": "#7a9a78",
        "purple": "#8a8498",
        "teal": "#7a9490",
        "input_bg": "#121314",
        "selection": "#2e3844",
        "code_bg": "#101112",
        "code_fg": "#c8c9cb",
        "tab_text": "#7a7c80",
        "tab_text_selected": "#e0e1e2",
        "danger_hover_bg": "#3a2a28",
        "primary_fg": "#121314",
        "accent_fg": "#121314",
        "focus": "#8a9aab",
    },
    "light": {
        "bg": "#ececed",
        "surface": "#f7f7f8",
        "surface2": "#e2e3e5",
        "border": "#c4c5c8",
        "text": "#1a1b1d",
        "text_dim": "#63666b",
        "accent": "#4a5c6e",
        "primary": "#4a5c6e",
        "danger": "#a05048",
        "warn": "#8a6e30",
        "ok": "#3d6b45",
        "purple": "#5c5670",
        "teal": "#3d6a64",
        "input_bg": "#ffffff",
        "selection": "#c8d4e0",
        "code_bg": "#1a1b1d",
        "code_fg": "#d4d5d6",
        "tab_text": "#63666b",
        "tab_text_selected": "#1a1b1d",
        "danger_hover_bg": "#f5e8e6",
        "primary_fg": "#ffffff",
        "accent_fg": "#ffffff",
        "focus": "#4a5c6e",
    },
}

_current_theme = "dark"
C: dict[str, str] = dict(PALETTES["dark"])
THEME_QSS = ""
LOG_COLORS: dict[str, str] = {}
HTTP_LOG_COLORS: dict[str, str] = {}


def current_theme() -> str:
    return _current_theme


def build_theme_qss(c: dict[str, str]) -> str:
    r = "3px"  # 全局圆角：工具感，避免胶囊/大圆角
    return f"""
QWidget {{
    background-color: {c['bg']};
    color: {c['text']};
    font-family: "Segoe UI", "Microsoft YaHei UI", sans-serif;
    font-size: 12px;
}}
QMainWindow {{ background-color: {c['bg']}; }}

#sidebar {{
    background-color: {c['surface']};
    border-right: 1px solid {c['border']};
}}
#sidebar QGroupBox {{
    background-color: transparent;
    border: none;
    border-top: 1px solid {c['border']};
    border-radius: 0;
    margin-top: 8px;
    padding: 10px 2px 4px 2px;
    font-weight: 600;
    font-size: 11px;
}}
#sidebar QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 0;
    padding: 0 0 4px 0;
    color: {c['text_dim']};
}}
#sidebar QPushButton {{
    min-height: 24px;
    padding: 3px 8px;
    border-radius: {r};
}}
#sidebar QComboBox, #sidebar QSpinBox {{
    min-height: 22px;
    padding: 2px 5px;
    border-radius: {r};
}}
#appTitle {{
    font-size: 13px;
    font-weight: 600;
    background: transparent;
}}
#appSubtitle {{
    font-size: 11px;
    color: {c['text_dim']};
    background: transparent;
}}
#sidebarBrandCard {{
    background: transparent;
    border: none;
    border-radius: 0;
    margin: 0;
    padding-bottom: 6px;
}}
#sidebarBrandLogo {{
    background: transparent;
    border: none;
    border-radius: 0;
    padding: 0;
}}
#sidebarBrandNameCn {{
    font-size: 14px;
    font-weight: 600;
    letter-spacing: 0;
    color: {c['text']};
    background: transparent;
}}
#sidebarBrandNameEn {{
    font-size: 10px;
    font-weight: 500;
    color: {c['text_dim']};
    background: transparent;
    padding-top: 0;
}}
#sidebarBrandSub {{
    font-size: 10px;
    font-weight: 400;
    color: {c['text_dim']};
    background: transparent;
}}
#sidebarBrandDivider {{
    background-color: {c['border']};
    max-height: 1px;
    margin: 2px 0;
}}
#sidebarBrandCreditMuted {{
    font-size: 9px;
    color: {c['text_dim']};
    background: transparent;
}}
#sidebarBrandCreditOrg {{
    font-size: 9px;
    font-weight: 500;
    color: {c['text_dim']};
    background: transparent;
}}
#sidebarBrandCreditAuthor {{
    font-size: 9px;
    font-weight: 500;
    color: {c['text_dim']};
    background: transparent;
}}
#sidebarBrandTitle {{
    font-size: 13px;
    font-weight: 600;
    background: transparent;
}}
#sidebarBrandTagline {{
    font-size: 10px;
    color: {c['text_dim']};
    background: transparent;
}}
#aiReadyChip {{
    border-radius: {r};
    padding: 2px 8px;
    font-size: 11px;
}}
#aiNextHint {{
    background: {c['surface']};
    border: 1px solid {c['border']};
    border-left: 2px solid {c['border']};
    border-radius: {r};
    padding: 8px 10px;
    color: {c['text_dim']};
}}
#aiHeroBtn {{
    font-size: 13px;
    font-weight: 600;
    min-height: 36px;
    border-radius: {r};
}}
QLabel[muted="true"] {{
    color: {c['text_dim']};
    font-size: 11px;
    background: transparent;
}}
QLabel[status="running"] {{ color: {c['ok']}; font-weight: 600; }}
QLabel[status="stopped"] {{ color: {c['text_dim']}; }}

QGroupBox {{
    background-color: {c['surface']};
    border: 1px solid {c['border']};
    border-radius: {r};
    margin-top: 10px;
    padding: 12px 8px 8px 8px;
    font-weight: 600;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 6px;
    padding: 0 4px;
    color: {c['text_dim']};
}}

QLineEdit, QSpinBox, QComboBox, QTextEdit, QPlainTextEdit {{
    background-color: {c['input_bg']};
    border: 1px solid {c['border']};
    border-radius: {r};
    padding: 4px 8px;
    color: {c['text']};
    selection-background-color: {c['selection']};
}}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QTextEdit:focus, QPlainTextEdit:focus {{
    border: 1px solid {c['focus']};
}}
QComboBox {{ padding-right: 24px; min-height: 20px; }}
QComboBox::drop-down {{
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 20px;
    border-left: 1px solid {c['border']};
    background-color: {c['surface2']};
    border-top-right-radius: {r};
    border-bottom-right-radius: {r};
}}
QComboBox::down-arrow {{
    width: 0; height: 0;
    border-left: 3px solid transparent;
    border-right: 3px solid transparent;
    border-top: 4px solid {c['text_dim']};
}}
QComboBox QAbstractItemView {{
    background-color: {c['surface2']};
    border: 1px solid {c['border']};
    selection-background-color: {c['selection']};
    selection-color: {c['text']};
    outline: none;
    max-height: 320px;
}}
QSpinBox {{ padding-right: 18px; }}
QSpinBox::up-button, QSpinBox::down-button {{
    subcontrol-origin: border;
    background: {c['surface2']};
    border-left: 1px solid {c['border']};
    width: 16px;
}}
QSpinBox::up-button {{ subcontrol-position: top right; }}
QSpinBox::down-button {{ subcontrol-position: bottom right; }}
QSpinBox::up-arrow {{
    width: 0; height: 0;
    border-left: 3px solid transparent;
    border-right: 3px solid transparent;
    border-bottom: 4px solid {c['text_dim']};
}}
QSpinBox::down-arrow {{
    width: 0; height: 0;
    border-left: 3px solid transparent;
    border-right: 3px solid transparent;
    border-top: 4px solid {c['text_dim']};
}}

#codeEditor, QPlainTextEdit#codeEditor, QTextEdit#codeEditor {{
    background-color: {c['code_bg']};
    border: 1px solid {c['border']};
    border-radius: {r};
    padding: 10px 12px;
    font-family: "Cascadia Code", "Consolas", "Courier New", monospace;
    font-size: 12px;
    line-height: 1.45;
    color: {c['code_fg']};
    selection-background-color: {c['selection']};
    selection-color: {c['text']};
}}
#logView {{
    background-color: {c['code_bg']};
    border: 1px solid {c['border']};
    border-radius: {r};
    font-family: "Cascadia Code", "Consolas", "Courier New", monospace;
    font-size: 12px;
    color: {c['code_fg']};
    padding: 6px;
}}

QPushButton {{
    background-color: {c['surface2']};
    border: 1px solid {c['border']};
    border-radius: {r};
    padding: 4px 12px;
    color: {c['text']};
    min-height: 20px;
}}
QPushButton:hover {{
    background-color: {c['border']};
    border-color: {c['text_dim']};
}}
QPushButton:pressed {{ background-color: {c['input_bg']}; }}
QPushButton:disabled {{
    color: {c['text_dim']};
    background-color: {c['surface']};
    border-color: {c['border']};
}}
QPushButton[variant="primary"] {{
    background-color: {c['primary']};
    border: 1px solid {c['primary']};
    color: {c['primary_fg']};
    font-weight: 600;
}}
QPushButton[variant="primary"]:hover {{
    background-color: {c['text']};
    border-color: {c['text']};
    color: {c['bg']};
}}
QPushButton[variant="accent"] {{
    background-color: {c['accent']};
    border: 1px solid {c['accent']};
    color: {c['accent_fg']};
    font-weight: 600;
}}
QPushButton[variant="accent"]:hover {{
    background-color: {c['text']};
    border-color: {c['text']};
    color: {c['bg']};
}}
QPushButton[variant="warn"] {{
    background-color: {c['surface2']};
    border: 1px solid {c['warn']};
    color: {c['warn']};
}}
QPushButton[variant="warn"]:hover {{
    background-color: {c['surface']};
}}
QPushButton[variant="danger"] {{
    background-color: transparent;
    border: 1px solid {c['danger']};
    color: {c['danger']};
}}
QPushButton[variant="danger"]:hover {{
    background-color: {c['danger_hover_bg']};
}}
QPushButton[variant="danger_fill"] {{
    background-color: {c['danger']};
    border: 1px solid {c['danger']};
    color: #ffffff;
    font-weight: 600;
}}
QPushButton[variant="danger_fill"]:hover {{
    background-color: #9a554e;
    border-color: #9a554e;
}}
QPushButton[variant="danger_fill"]:disabled {{
    background-color: {c['surface2']};
    border-color: {c['border']};
    color: {c['text_dim']};
}}
QPushButton[variant="ghost"] {{
    background: transparent;
    border-color: {c['border']};
    color: {c['text_dim']};
}}
QPushButton[variant="ghost"]:hover {{
    color: {c['text']};
    background: {c['surface2']};
}}

QTabWidget::pane {{
    border: 1px solid {c['border']};
    border-radius: {r};
    background: {c['bg']};
    top: -1px;
    padding: 4px;
}}
QTabBar::tab {{
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    border-radius: 0;
    padding: 6px 12px;
    margin: 0 1px;
    color: {c['tab_text']};
    min-height: 18px;
}}
QTabBar::tab:selected {{
    background: transparent;
    border-bottom: 2px solid {c['text']};
    color: {c['tab_text_selected']};
    font-weight: 600;
}}
QTabBar::tab:hover:!selected {{
    color: {c['tab_text_selected']};
    background: {c['surface2']};
}}
QTabWidget#mainTabs::pane {{
    border: none;
    border-radius: 0;
    background: {c['bg']};
    padding: 10px 12px 12px 12px;
}}
QTabWidget#mainTabs QTabBar {{
    background: {c['surface']};
    border-bottom: 1px solid {c['border']};
}}
QTabWidget#mainTabs QTabBar::tab {{
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    border-radius: 0;
    padding: 10px 14px 8px 14px;
    margin: 0;
    color: {c['tab_text']};
    min-height: 18px;
}}
QTabWidget#mainTabs QTabBar::tab:selected {{
    background: transparent;
    border: none;
    border-bottom: 2px solid {c['text']};
    color: {c['tab_text_selected']};
    font-weight: 600;
}}
QTabWidget#mainTabs QTabBar::tab:hover:!selected {{
    background: transparent;
    color: {c['tab_text_selected']};
}}

QTreeWidget, QListWidget, QTableWidget {{
    background-color: {c['input_bg']};
    border: 1px solid {c['border']};
    border-radius: {r};
    outline: none;
    alternate-background-color: {c['surface']};
    padding: 1px;
}}
QTreeWidget::item, QListWidget::item {{
    padding: 3px 5px;
    border-radius: 0;
}}
QTreeWidget::item:hover, QListWidget::item:hover {{
    background-color: {c['surface2']};
}}
QTreeWidget::item:selected, QListWidget::item:selected {{
    background-color: {c['selection']};
    color: {c['text']};
}}
QHeaderView::section {{
    background: {c['surface2']};
    border: none;
    border-bottom: 1px solid {c['border']};
    padding: 5px 8px;
    color: {c['text_dim']};
    font-weight: 600;
}}

QScrollBar:vertical {{
    background: transparent;
    width: 8px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {c['border']};
    min-height: 24px;
    border-radius: 2px;
}}
QScrollBar::handle:vertical:hover {{ background: {c['text_dim']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}
QScrollBar:horizontal {{
    background: transparent;
    height: 8px;
    margin: 0;
}}
QScrollBar::handle:horizontal {{
    background: {c['border']};
    min-width: 24px;
    border-radius: 2px;
}}
QScrollBar::handle:horizontal:hover {{ background: {c['text_dim']}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{ background: transparent; }}

QSplitter::handle {{ background: {c['border']}; }}
QSplitter::handle:hover {{ background: {c['text_dim']}; }}
QSplitter::handle:horizontal {{ width: 1px; margin: 0; }}
QSplitter::handle:vertical {{ height: 1px; margin: 0; }}

QMenu {{
    background: {c['surface2']};
    border: 1px solid {c['border']};
    border-radius: {r};
    padding: 2px;
}}
QMenu::item {{
    padding: 6px 18px;
    border-radius: 0;
}}
QMenu::item:selected {{ background: {c['selection']}; }}
QMenu::separator {{
    height: 1px;
    background: {c['border']};
    margin: 3px 6px;
}}

QToolTip {{
    background-color: {c['surface2']};
    color: {c['text']};
    border: 1px solid {c['border']};
    padding: 6px 10px;
    border-radius: {r};
    font-size: 11px;
    opacity: 255;
}}

QToolButton {{
    background-color: {c['surface2']};
    border: 1px solid {c['border']};
    border-radius: {r};
    padding: 3px 8px;
    color: {c['text']};
    min-height: 18px;
}}
QToolButton:hover {{ background-color: {c['border']}; }}
QToolButton::menu-indicator {{ image: none; width: 0; }}

QCheckBox {{
    spacing: 6px;
    background: transparent;
}}
QCheckBox::indicator {{
    width: 13px;
    height: 13px;
    border-radius: 2px;
    border: 1px solid {c['border']};
    background: {c['input_bg']};
}}
QCheckBox::indicator:checked {{
    background: {c['accent']};
    border-color: {c['accent']};
}}
QCheckBox::indicator:hover {{
    border-color: {c['text_dim']};
}}

QPushButton[sidebarAux="true"] {{
    padding: 2px 6px;
    min-height: 16px;
    font-size: 11px;
    background: transparent;
    border-color: {c['border']};
    color: {c['text_dim']};
}}
QPushButton[sidebarAux="true"]:hover {{
    color: {c['text']};
    background: {c['surface2']};
}}

QFrame[card="true"] {{
    background: {c['surface']};
    border: 1px solid {c['border']};
    border-radius: {r};
    margin: 1px 0;
}}
QLabel[stepTitle="true"] {{
    font-weight: 600;
    background: transparent;
    font-size: 12px;
}}
QPushButton[compact="true"] {{
    padding: 1px 5px;
    min-height: 14px;
    min-width: 22px;
    max-width: 26px;
    font-size: 11px;
    border-radius: {r};
}}

QLabel[feedbackBox="true"] {{
    padding: 6px 8px;
    font-size: 11px;
    border-radius: {r};
    background: {c['input_bg']};
    border: 1px solid {c['border']};
}}
QLabel[feedbackKind="error"] {{ color: {c['danger']}; border-color: {c['danger']}; }}

#homeHeroTitle {{
    font-size: 18px;
    font-weight: 600;
    background: transparent;
}}
#homeHeroSub {{
    font-size: 12px;
    color: {c['text_dim']};
    background: transparent;
}}
#homeSectionTitle {{
    font-size: 11px;
    font-weight: 600;
    color: {c['text_dim']};
    background: transparent;
    padding-top: 2px;
    text-transform: none;
}}
#homeStatStrip {{
    background: {c['surface']};
    border: 1px solid {c['border']};
    border-radius: {r};
}}
#homeStatSep {{
    background-color: {c['border']};
    max-width: 1px;
    border: none;
}}
#homeStatCard {{
    background: transparent;
    border: none;
    border-radius: 0;
}}
#homeNavCard, #homeWorkflow {{
    background: transparent;
    border: none;
    border-radius: 0;
}}
#homeNavCard:hover {{
    background: {c['surface2']};
}}
#homeStatValue, #homeCardTitle {{
    font-size: 12px;
    font-weight: 600;
    background: transparent;
}}
#homeStepBadge {{
    background: transparent;
    border: none;
    border-radius: 0;
    color: {c['text_dim']};
    font-weight: 600;
    font-size: 11px;
    font-family: "Cascadia Code", "Consolas", monospace;
}}
#homeTopology {{
    background: transparent;
    border: none;
    padding: 2px 0;
}}
#homeEmptyHint {{
    background: transparent;
    border: none;
    border-left: 2px solid {c['warn']};
    border-radius: 0;
    padding: 4px 0 4px 10px;
    color: {c['text_dim']};
}}
#projectEmptyHint {{
    color: {c['warn']};
    font-size: 11px;
    background: transparent;
}}
QDialogButtonBox QPushButton {{
    min-width: 72px;
}}
"""


def _activate_palette(theme: str) -> None:
    global C, THEME_QSS, LOG_COLORS, HTTP_LOG_COLORS, _current_theme
    _current_theme = theme if theme in PALETTES else "dark"
    C.clear()
    C.update(PALETTES[_current_theme])
    THEME_QSS = build_theme_qss(C)
    # 日志/代码区均为深色底，语义色固定用亮色系，避免浅色主题正文色渗入
    LOG_COLORS.clear()
    LOG_COLORS.update({
        "ERROR": "#f48771",
        "WARNING": "#dcdcaa",
        "INFO": C["code_fg"],
    })
    HTTP_LOG_COLORS.clear()
    HTTP_LOG_COLORS.update({"request": C.get("ok", "#7a9a78"), "response": C.get("accent", "#8a9aab")})


_activate_palette("dark")


def configure_combo_popup(combo: QComboBox, max_visible: int = 12, max_height: int = 320) -> None:
    """限制下拉列表高度，超出部分滚动."""
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QListView

    combo.setMaxVisibleItems(max_visible)
    view = combo.view()
    if view is None or not isinstance(view, QListView):
        view = QListView()
        combo.setView(view)
    view.setMaximumHeight(max_height)
    view.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)


def pick_from_list(
    parent,
    title: str,
    items: list[str] | None = None,
    sections: list[tuple[str, list[str]]] | None = None,
    max_height: int = 360,
) -> str | None:
    """滚动列表选择对话框，用于选项较多时替代超长菜单."""
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import (
        QDialog, QVBoxLayout, QListWidget, QListWidgetItem,
        QDialogButtonBox,
    )

    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setMinimumWidth(440)
    layout = QVBoxLayout(dlg)

    list_w = QListWidget()
    list_w.setMaximumHeight(max_height)

    def add_section(section_title: str, names: list[str], with_header: bool) -> None:
        if with_header and section_title:
            header = QListWidgetItem(f"── {section_title} ──")
            header.setFlags(Qt.ItemFlag.NoItemFlags)
            header.setForeground(QColor(C["text_dim"]))
            list_w.addItem(header)
        for name in names:
            list_w.addItem(name)

    if sections:
        for i, (section_title, names) in enumerate(sections):
            add_section(section_title, names, with_header=True)
    elif items:
        for name in items:
            list_w.addItem(name)

    chosen: dict[str, str | None] = {"value": None}

    def accept_item(item: QListWidgetItem | None) -> None:
        if item and (item.flags() & Qt.ItemFlag.ItemIsSelectable):
            chosen["value"] = item.text()
            dlg.accept()

    list_w.itemDoubleClicked.connect(accept_item)
    layout.addWidget(list_w)

    buttons = QDialogButtonBox(
        QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
    )
    buttons.accepted.connect(lambda: accept_item(list_w.currentItem()))
    buttons.rejected.connect(dlg.reject)
    layout.addWidget(buttons)

    if dlg.exec() == QDialog.DialogCode.Accepted:
        return chosen["value"]
    return None


def _install_combo_scroll_limit(max_visible: int = 12, max_height: int = 320) -> None:
    if getattr(QComboBox, "_scroll_limit_installed", False):
        return

    _orig_show = QComboBox.showPopup

    def show_popup(self: QComboBox) -> None:
        if self.count() > max_visible:
            configure_combo_popup(self, max_visible, max_height)
        _orig_show(self)

    QComboBox.showPopup = show_popup  # type: ignore[method-assign]
    QComboBox._scroll_limit_installed = True  # type: ignore[attr-defined]


def _repolish(widget: QWidget) -> None:
    widget.style().unpolish(widget)
    widget.style().polish(widget)


repolish_widget = _repolish


def refresh_widget_tree(root: QWidget) -> None:
    """主题切换后刷新控件样式."""
    if root is None:
        return
    root.style().unpolish(root)
    root.style().polish(root)
    for child in root.findChildren(QWidget):
        child.style().unpolish(child)
        child.style().polish(child)


class CollapsibleBox(QFrame):
    """可折叠面板 — 点击标题展开/收起."""

    def __init__(self, title: str, collapsed: bool = True, parent=None):
        super().__init__(parent)
        self._title = title
        self._collapsed = collapsed
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setProperty("card", True)
        repolish_widget(self)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.toggle_btn = QPushButton()
        self.toggle_btn.setFlat(True)
        self.toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle_btn.clicked.connect(lambda: self.set_collapsed(not self._collapsed))
        outer.addWidget(self.toggle_btn)

        self.body = QWidget()
        self.body_layout = QVBoxLayout(self.body)
        self.body_layout.setContentsMargins(10, 6, 10, 10)
        self.body_layout.setSpacing(6)
        outer.addWidget(self.body)

        self.set_collapsed(collapsed)

    def set_collapsed(self, collapsed: bool) -> None:
        self._collapsed = collapsed
        self.body.setVisible(not collapsed)
        arrow = "▶" if collapsed else "▼"
        self.toggle_btn.setText(f"{arrow}  {self._title}")

    def is_collapsed(self) -> bool:
        return self._collapsed


def style_button(btn, variant: str = "default") -> None:
    """variant: default | primary | danger | danger_fill | accent | warn | ghost"""
    btn.setProperty("variant", "" if variant == "default" else variant)
    _repolish(btn)


def style_muted_label(label: QLabel) -> None:
    label.setProperty("muted", True)
    _repolish(label)


def style_status_label(label: QLabel, running: bool = False) -> None:
    label.setProperty("status", "running" if running else "stopped")
    _repolish(label)


def setup_code_editor(widget) -> None:
    """标记为代码编辑器并挂语法高亮；配色走全局 QSS，随主题切换。"""
    widget.setObjectName("codeEditor")
    # 勿写死内联样式，否则切主题后背景/字色不会更新
    widget.setStyleSheet("")
    from core.syntax_highlighter import attach_python_highlighter
    attach_python_highlighter(widget)


def build_logo_header(parent_layout, icon_path: str | None = None) -> None:
    """侧边栏品牌区 — 扁平一行：图标 + 名，署名收成 tip."""
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QPixmap
    from PyQt6.QtWidgets import QFrame, QHBoxLayout, QVBoxLayout, QLabel
    from core.icon_loader import MAIN_ICON
    from core.brand import (
        APP_NAME, APP_NAME_EN, APP_SUBTITLE, APP_VERSION,
        APP_CREDIT_AUTHOR, APP_TAGLINE,
    )

    card = QFrame()
    card.setObjectName("sidebarBrandCard")
    repolish_widget(card)

    outer = QVBoxLayout(card)
    outer.setContentsMargins(2, 2, 2, 8)
    outer.setSpacing(4)

    row = QHBoxLayout()
    row.setSpacing(8)
    row.setAlignment(Qt.AlignmentFlag.AlignVCenter)

    logo = QLabel()
    logo.setObjectName("sidebarBrandLogo")
    logo.setFixedSize(28, 28)
    logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
    img = icon_path or MAIN_ICON
    if img:
        pm = QPixmap(img).scaled(
            28, 28, Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        if not pm.isNull():
            logo.setPixmap(pm)
    row.addWidget(logo)

    text_col = QVBoxLayout()
    text_col.setSpacing(0)
    name_cn = QLabel(f"{APP_NAME}  {APP_NAME_EN}  {APP_VERSION}")
    name_cn.setObjectName("sidebarBrandNameCn")
    text_col.addWidget(name_cn)
    subtitle = QLabel(APP_SUBTITLE)
    subtitle.setObjectName("sidebarBrandSub")
    subtitle.setWordWrap(True)
    text_col.addWidget(subtitle)
    row.addLayout(text_col, 1)
    outer.addLayout(row)

    credit = QLabel(APP_TAGLINE)
    credit.setObjectName("sidebarBrandCreditMuted")
    credit.setWordWrap(True)
    credit.setToolTip(f"作者：{APP_CREDIT_AUTHOR}")
    outer.addWidget(credit)

    parent_layout.addWidget(card)


def style_feedback(label: QLabel, kind: str = "success") -> None:
    """状态文字 — 仅改字色，不加边框."""
    label.setProperty("feedbackBox", False)
    colors = {
        "success": C["primary"],
        "error": C["danger"],
        "warn": C["warn"],
        "info": C["accent"],
        "muted": C["text_dim"],
    }
    label.setStyleSheet(
        f"color:{colors.get(kind, C['text'])}; background:transparent; border:none;"
    )


def style_feedback_box(label: QLabel, kind: str = "neutral") -> None:
    label.setProperty("feedbackBox", True)
    label.setProperty("feedbackKind", kind if kind != "neutral" else "")
    _repolish(label)


def style_step_title(label: QLabel) -> None:
    label.setProperty("stepTitle", True)
    _repolish(label)


def style_compact_button(btn, variant: str = "default") -> None:
    btn.setProperty("compact", True)
    style_button(btn, variant)


def style_sidebar_aux_button(btn) -> None:
    """侧栏次要操作 — 小字、浅色，不抢主按钮视觉."""
    btn.setProperty("sidebarAux", True)
    _repolish(btn)


def setup_main_tabs(tab_widget) -> None:
    """主界面 Tab — 底线选中，图标同色."""
    from PyQt6.QtCore import QSize
    tab_widget.setObjectName("mainTabs")
    tab_widget.setIconSize(QSize(16, 16))
    tab_widget.setDocumentMode(True)
    bar = tab_widget.tabBar()
    bar.setExpanding(False)
    bar.setUsesScrollButtons(True)
    bar.setDrawBase(False)


def setup_log_view(widget) -> None:
    widget.setObjectName("logView")


def apply_theme(app: QApplication, theme: str | None = None) -> str:
    """应用主题，返回实际使用的 theme 名 (dark/light)."""
    from core.app_settings import get_theme

    name = theme or get_theme()
    if name not in PALETTES:
        name = "dark"

    _activate_palette(name)
    try:
        from core.icon_loader import clear_icon_cache
        clear_icon_cache()
    except ImportError:
        pass

    app.setStyle("Fusion")
    app.setFont(QFont("Microsoft YaHei UI", 10))
    app.setStyleSheet(THEME_QSS)
    _install_combo_scroll_limit()
    p = QPalette()
    p.setColor(QPalette.ColorRole.Window, QColor(C["bg"]))
    p.setColor(QPalette.ColorRole.WindowText, QColor(C["text"]))
    p.setColor(QPalette.ColorRole.Base, QColor(C["input_bg"]))
    p.setColor(QPalette.ColorRole.AlternateBase, QColor(C["surface"]))
    p.setColor(QPalette.ColorRole.Text, QColor(C["text"]))
    p.setColor(QPalette.ColorRole.Button, QColor(C["surface2"]))
    p.setColor(QPalette.ColorRole.ButtonText, QColor(C["text"]))
    p.setColor(QPalette.ColorRole.Highlight, QColor(C["selection"]))
    p.setColor(QPalette.ColorRole.HighlightedText, QColor(C["text"]))
    p.setColor(QPalette.ColorRole.ToolTipBase, QColor(C["surface2"]))
    p.setColor(QPalette.ColorRole.ToolTipText, QColor(C["text"]))
    for group in (
        QPalette.ColorGroup.Active,
        QPalette.ColorGroup.Inactive,
        QPalette.ColorGroup.Disabled,
    ):
        p.setColor(group, QPalette.ColorRole.ToolTipBase, QColor(C["surface2"]))
        p.setColor(group, QPalette.ColorRole.ToolTipText, QColor(C["text"]))
        p.setColor(group, QPalette.ColorRole.WindowText, QColor(C["text"]))
        p.setColor(group, QPalette.ColorRole.Text, QColor(C["text"]))
    app.setPalette(p)
    try:
        from core.syntax_highlighter import refresh_all_highlighters
        refresh_all_highlighters()
    except ImportError:
        pass
    return name
