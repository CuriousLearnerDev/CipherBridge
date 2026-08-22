"""密桥全局主题 — 浅色冷灰工具台 / 深色灰蓝工作区。

少渐变、少阴影、少色条卡片；主色实心，ghost 安静。
"""

from __future__ import annotations

import os
from PyQt6.QtGui import QFont, QPalette, QColor
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QLabel, QWidget, QComboBox, QPushButton, QVBoxLayout, QFrame

PALETTES: dict[str, dict[str, str]] = {
    "dark": {
        "bg": "#0d1117",
        "surface": "#161b22",
        "surface2": "#21262d",
        "border": "#30363d",
        "text": "#e6edf3",
        "text_dim": "#8b949e",
        "accent": "#58a6ff",
        "primary": "#388bfd",
        "primary_hover": "#58a6ff",
        "primary_pressed": "#1f6feb",
        "primary_grad_a": "#4493f8",
        "primary_grad_b": "#388bfd",
        "danger": "#f85149",
        "warn": "#d29922",
        "ok": "#3fb950",
        "purple": "#a371f7",
        "teal": "#39d353",
        "input_bg": "#0d1117",
        "selection": "#1f3a5f",
        "code_bg": "#0a0e14",
        "code_fg": "#c9d1d9",
        "tab_text": "#8b949e",
        "tab_text_selected": "#e6edf3",
        "danger_hover_bg": "#3d1214",
        "primary_fg": "#ffffff",
        "accent_fg": "#0d1117",
        "focus": "#388bfd",
        "badge_bg": "#21262d",
        "pane": "#0d1117",
        "overlay": "#010409",
        "ghost_hover": "#21262d",
        "tab_active_bg": "#161b22",
        "tab_active_grad_a": "#161b22",
        "tab_active_grad_b": "#161b22",
        "accent_soft": "#13233a",
        "sidebar_header": "#8b949e",
        "chip_bg": "#21262d",
        "input_focus_bg": "#0d1117",
        "sidebar_bg": "#010409",
        "line_soft": "#21262d",
        "kpi_bg": "#161b22",
    },
    "light": {
        # 浅色工具台：冷灰 + 蓝，避免 terracotta / 卡片墙
        "bg": "#f0f2f5",
        "surface": "#ffffff",
        "surface2": "#e8ebf0",
        "border": "#d0d7de",
        "text": "#1f2328",
        "text_dim": "#656d76",
        "accent": "#0969da",
        "primary": "#1f2328",
        "primary_hover": "#32383f",
        "primary_pressed": "#0d1117",
        "primary_grad_a": "#32383f",
        "primary_grad_b": "#1f2328",
        "danger": "#cf222e",
        "warn": "#9a6700",
        "ok": "#1a7f37",
        "purple": "#8250df",
        "teal": "#1a7f37",
        "input_bg": "#ffffff",
        "selection": "#ddf4ff",
        "code_bg": "#1f2328",
        "code_fg": "#e6edf3",
        "tab_text": "#656d76",
        "tab_text_selected": "#1f2328",
        "danger_hover_bg": "#ffebe9",
        "primary_fg": "#ffffff",
        "accent_fg": "#ffffff",
        "focus": "#0969da",
        "badge_bg": "#eaeef2",
        "pane": "#f0f2f5",
        "overlay": "#e8ebf0",
        "ghost_hover": "#eaeef2",
        "tab_active_bg": "#ddf4ff",
        "tab_active_grad_a": "#ddf4ff",
        "tab_active_grad_b": "#ddf4ff",
        "accent_soft": "#ddf4ff",
        "sidebar_header": "#656d76",
        "chip_bg": "#eaeef2",
        "input_focus_bg": "#ffffff",
        "sidebar_bg": "#f6f8fa",
        "line_soft": "#e4e8ec",
        "kpi_bg": "#fafbfc",
    },
}

_current_theme = "light"
C: dict[str, str] = dict(PALETTES["light"])
THEME_QSS = ""
LOG_COLORS: dict[str, str] = {}
HTTP_LOG_COLORS: dict[str, str] = {}


def current_theme() -> str:
    return _current_theme


def build_theme_qss(c: dict[str, str]) -> str:
    # 产品风：10px 圆角；侧栏更深
    r = "10px"
    pane = c.get("pane", c["surface"])
    sidebar_bg = c.get("sidebar_bg", c["surface"])
    return f"""
QWidget {{
    background-color: {c['bg']};
    color: {c['text']};
    font-family: "Segoe UI Variable", "Segoe UI", "Microsoft YaHei UI", "PingFang SC", sans-serif;
    font-size: 12.5px;
}}
QMainWindow {{ background-color: {c['bg']}; }}
QDialog {{
    background-color: {c['surface']};
    border: 1px solid {c['border']};
    border-radius: 10px;
}}
QToolTip {{
    background-color: {c['surface2']};
    color: {c['text']};
    border: 1px solid {c['border']};
    padding: 6px 10px;
    border-radius: 6px;
    font-size: 12px;
}}
QMessageBox {{
    background-color: {c['surface']};
}}
QMessageBox QLabel {{
    color: {c['text']};
    font-size: 13px;
}}

#sidebar {{
    background-color: {sidebar_bg};
    border-right: 1px solid {c['border']};
}}
#sidebarSection {{
    color: {c['text_dim']};
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.3px;
    background: transparent;
    padding: 2px 2px 0 2px;
}}
#proxyRail {{
    background-color: {c['surface']};
    border: 1px solid {c.get('line_soft', c['border'])};
    border-radius: 10px;
}}
#proxyStatusText {{
    font-size: 12.5px;
    font-weight: 600;
    background: transparent;
}}
#proxyFieldLabel {{
    color: {c['text_dim']};
    font-size: 11px;
    font-weight: 500;
    background: transparent;
}}
#proxyCertHint {{
    font-size: 11px;
    background: transparent;
}}
#sidebar QGroupBox {{
    background-color: transparent;
    border: none;
    border-top: 1px solid {c.get('line_soft', c['border'])};
    border-radius: 0;
    margin-top: 6px;
    padding: 14px 2px 8px 2px;
    font-weight: 600;
    font-size: 11px;
    color: {c['text_dim']};
}}
#sidebar QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 2px;
    padding: 0;
    color: {c['text_dim']};
    font-weight: 600;
    font-size: 11px;
    letter-spacing: 0.2px;
    background-color: transparent;
}}
#sidebar QPushButton {{
    min-height: 28px;
    padding: 4px 10px;
    border-radius: 6px;
    font-weight: 600;
    font-size: 12px;
}}
#sidebar QPushButton[variant="primary"],
#sidebar QPushButton[variant="danger"],
#sidebar QPushButton[variant="danger_fill"] {{
    min-width: 0;
}}
#sidebar QComboBox, #sidebar QSpinBox {{
    min-height: 26px;
    padding: 2px 6px;
    border-radius: 5px;
    background-color: {c['input_bg']};
    border: 1px solid {c['border']};
    font-size: 12px;
}}
#sidebarPortLabel {{
    min-width: 28px;
    color: {c['text_dim']};
    background: transparent;
    font-size: 12px;
}}
#statusDot {{
    min-width: 8px;
    max-width: 8px;
    min-height: 8px;
    max-height: 8px;
    border-radius: 4px;
    background: {c['text_dim']};
    border: none;
}}
#statusDot[running="true"] {{
    background: {c['ok']};
}}
#statusDot[running="false"] {{
    background: {c['text_dim']};
}}
#workspacePane {{
    background-color: {pane};
    border: none;
    border-radius: 0;
}}
#appTitle {{
    font-size: 14px;
    font-weight: 700;
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
    padding: 4px 0 6px 0;
}}
#sidebarBrandLogoWell {{
    background: transparent;
    border: none;
}}
#sidebarBrandLogo {{
    background: {c.get('accent_soft', c.get('surface2', c['surface']))};
    border: 1px solid {c['border']};
    border-radius: 8px;
    padding: 2px;
}}
#sidebarBrandNameCn {{
    font-size: 15px;
    font-weight: 800;
    letter-spacing: 0.2px;
    color: {c['text']};
    background: transparent;
}}
#sidebarBrandNameEn {{
    font-size: 12px;
    font-weight: 600;
    color: {c.get('accent', c['primary'])};
    background: transparent;
}}
#sidebarBrandAuthor {{
    font-size: 11px;
    font-weight: 600;
    color: {c['text_dim']};
    background: transparent;
}}
#sidebarBrandVersion {{
    font-size: 10px;
    font-weight: 600;
    color: {c['text_dim']};
    background: transparent;
    border: none;
    padding: 0;
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
    padding-top: 6px;
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
#aiLabPage {{
    background: transparent;
}}
#aiPane {{
    background: {c['surface']};
    border: 1px solid {c['border']};
    border-radius: 14px;
}}
#aiToolbar {{
    background: transparent;
    border: none;
    border-bottom: 1px solid {c['border']};
    padding-bottom: 8px;
}}
#aiCaptureBar {{
    background: transparent;
    border: none;
    border-bottom: 1px solid {c['border']};
    border-radius: 0;
    min-height: 40px;
    padding-bottom: 8px;
}}
#aiActionBar, #aiComposer {{
    background: transparent;
    border: none;
    border-radius: 0;
    min-height: 0;
}}
#aiComposer {{
    border-top: 1px solid {c['border']};
    padding-top: 8px;
}}
#aiReadyChip {{
    border-radius: 999px;
    padding: 5px 12px;
    font-size: 11px;
    font-weight: 600;
    background: {c['accent_soft']};
    border: 1px solid {c['border']};
    color: {c['accent']};
}}
#aiNextHint {{
    background: transparent;
    border: none;
    padding: 0;
    color: {c['text_dim']};
    font-size: 12px;
}}
#aiTargetPanel {{
    background: transparent;
    border: none;
    border-radius: 0;
    min-height: 0;
}}
#aiTargetPanelTitle {{
    font-size: 11px;
    font-weight: 700;
    color: {c['text_dim']};
    background: transparent;
    letter-spacing: 0.4px;
}}
#aiTargetStatus {{
    font-size: 12px;
    color: {c['text_dim']};
    background: transparent;
    border: none;
    padding: 0;
}}
#aiTargetStatus[ready="true"] {{
    color: {c['ok']};
}}
#aiAgentToolbar {{
    background: transparent;
}}
#aiHeroBtn {{
    font-size: 12px;
    font-weight: 600;
    min-height: 28px;
    border-radius: {r};
}}
#fieldTargetDialog #ftDialogTitle {{
    font-size: 13px;
    font-weight: 600;
    color: {c['text']};
    background: transparent;
}}
#fieldTargetDialog #ftDialogSub {{
    font-size: 11px;
    color: {c['text_dim']};
    background: transparent;
}}
#fieldTargetDialog #ftStatusChip {{
    font-size: 10px;
    color: {c['text']};
    background: {c['surface2']};
    border: 1px solid {c['border']};
    border-radius: 8px;
    padding: 1px 6px;
}}
#fieldTargetDialog #ftPanel {{
    background: {c['surface']};
    border: 1px solid {c['border']};
    border-radius: 4px;
}}
#fieldTargetDialog #ftPanelTitle {{
    font-size: 11px;
    font-weight: 600;
    background: transparent;
}}
#fieldTargetDialog #ftStepBadge {{
    font-size: 10px;
    font-weight: 700;
    font-family: "Cascadia Code", "Consolas", monospace;
    color: {c['primary_fg']};
    background: {c['primary']};
    border-radius: 8px;
}}
#fieldTargetDialog #ftSegBar {{
    background: {c['surface2']};
    border: 1px solid {c['border']};
    border-radius: 4px;
}}
#fieldTargetDialog QPushButton#ftSegBtn {{
    background: transparent;
    border: none;
    border-radius: 3px;
    color: {c['text_dim']};
    font-size: 11px;
    font-weight: 500;
    padding: 2px 6px;
    min-height: 0;
}}
#fieldTargetDialog QPushButton#ftSegBtn:hover {{
    color: {c['text']};
    background: {c['bg']};
}}
#fieldTargetDialog QPushButton#ftSegBtn:checked {{
    color: {c['primary_fg']};
    background: {c['primary']};
    font-weight: 600;
}}
#fieldTargetDialog #ftFlowList {{
    background: {c['input_bg']};
    border: 1px solid {c['border']};
    border-radius: 3px;
    padding: 0;
    font-size: 11px;
}}
#fieldTargetDialog #ftFlowList::item {{
    padding: 3px 6px;
    border-radius: 2px;
    margin: 0;
}}
#fieldTargetDialog #ftFlowList::item:selected {{
    background: {c['selection']};
    color: {c['text']};
}}
#fieldTargetDialog #ftFieldTree {{
    background: {c['input_bg']};
    border: 1px solid {c['border']};
    border-radius: 3px;
    font-size: 11px;
}}
#fieldTargetDialog #ftFieldTree::item {{
    padding: 1px 0;
}}
#fieldTargetDialog #ftPickedList {{
    background: {c['input_bg']};
    border: 1px solid {c['border']};
    border-radius: 3px;
    font-size: 11px;
}}
#fieldTargetDialog #ftPickedList::item {{
    padding: 2px 6px;
    border-radius: 2px;
}}
#fieldTargetDialog #ftEmptyHint {{
    color: {c['warn']};
    background: {c['surface2']};
    border: 1px solid {c['border']};
    border-radius: 3px;
    padding: 4px 8px;
    font-size: 11px;
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
    border-radius: 8px;
    margin-top: 14px;
    padding: 16px 14px 14px 14px;
    font-weight: 600;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px;
    padding: 0 8px;
    color: {c['text_dim']};
    background-color: {c['surface']};
    font-weight: 700;
    font-size: 11px;
    letter-spacing: 0.4px;
}}
#cryptoWorkbench {{
    background-color: transparent;
}}
#cryptoSidePanel {{
    background-color: {c['surface']};
    border: none;
    border-right: 1px solid {c['border']};
    border-radius: 0;
}}
#cryptoSidePanel QLabel {{
    background: transparent;
}}
#cryptoPanelTitle {{
    font-size: 12px;
    font-weight: 600;
    color: {c['text']};
    background: transparent;
    padding: 0 0 2px 0;
}}
#cryptoFieldLabel {{
    font-size: 11px;
    font-weight: 500;
    color: {c['text_dim']};
    background: transparent;
    padding: 0 0 2px 0;
}}
#analyzerEmptyHint {{
    color: {c['text_dim']};
    font-size: 12px;
    background: transparent;
    padding: 20px 12px;
}}

QLineEdit, QSpinBox, QComboBox, QTextEdit, QPlainTextEdit {{
    background-color: {c['input_bg']};
    border: 1px solid {c['border']};
    border-radius: {r};
    padding: 7px 10px;
    color: {c['text']};
    selection-background-color: {c['selection']};
    min-height: 20px;
}}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QTextEdit:focus, QPlainTextEdit:focus {{
    border: 1px solid {c['focus']};
    background-color: {c['input_focus_bg']};
}}
QComboBox {{ padding-right: 22px; min-height: 26px; max-height: 26px; }}
QComboBox::drop-down {{
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 24px;
    border-left: 1px solid {c['border']};
    background-color: {c['surface2']};
    border-top-right-radius: {r};
    border-bottom-right-radius: {r};
}}
QComboBox::drop-down:hover {{ background-color: {c['primary']}; }}
QComboBox::down-arrow {{
    width: 0; height: 0;
    border-left: 3px solid transparent;
    border-right: 3px solid transparent;
    border-top: 4px solid {c['text_dim']};
}}
QComboBox::drop-down:hover::down-arrow {{ border-top-color: {c['primary_fg']}; }}
QComboBox QAbstractItemView {{
    background-color: {c['surface2']};
    border: 1px solid {c['border']};
    border-radius: {r};
    padding: 4px;
    selection-background-color: {c['selection']};
    selection-color: {c['text']};
    outline: none;
    max-height: 320px;
}}
QComboBox QAbstractItemView::item {{
    padding: 4px 8px;
    border-radius: 4px;
    margin: 1px;
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
    padding: 8px;
}}
#monoField, QPlainTextEdit#monoField, QTextEdit#monoField, QLineEdit#monoField {{
    background-color: {c['code_bg']};
    border: 1px solid {c['border']};
    border-radius: {r};
    padding: 8px 10px;
    font-family: "Cascadia Code", "Consolas", "Courier New", monospace;
    font-size: 12px;
    color: {c['code_fg']};
    selection-background-color: {c['selection']};
}}
#monoField:focus, QPlainTextEdit#monoField:focus, QLineEdit#monoField:focus {{
    border: 1px solid {c['focus']};
}}
QTabWidget#subTabs::pane {{
    border: none;
    border-radius: 0;
    background: transparent;
    padding: 10px 8px 8px 8px;
}}
QTabWidget#subTabs QTabBar {{
    background: transparent;
    border-bottom: 1px solid {c['border']};
}}
QTabWidget#subTabs {{
    background: transparent;
}}
QTabWidget#subTabs QTabBar::tab {{
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    border-radius: 0;
    padding: 4px 8px 3px 8px;
    margin: 0;
    color: {c['tab_text']};
    min-height: 16px;
    font-size: 12px;
}}
QTabWidget#subTabs QTabBar::tab:selected {{
    background: transparent;
    border-bottom: 2px solid {c['primary']};
    color: {c['tab_text_selected']};
    font-weight: 600;
}}
QTabWidget#subTabs QTabBar::tab:hover:!selected {{
    background: {c['surface2']};
    color: {c['tab_text_selected']};
}}
#aiPane QTabWidget#subTabs QTabBar {{
    background: transparent;
}}
#aiPane QTabWidget#subTabs::pane {{
    padding: 8px 0 0 0;
}}

/* 按钮体系：紧凑但不裁切中文；不用死锁 max-height */
QPushButton {{
    background-color: {c['surface2']};
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 4px 10px;
    color: {c['text']};
    min-height: 26px;
    min-width: 0;
    font-weight: 500;
    font-size: 12px;
}}
QPushButton:hover {{
    background-color: {c['ghost_hover']};
}}
QPushButton:pressed {{ background-color: {c['input_bg']}; }}
QPushButton:disabled {{
    color: {c['text_dim']};
    background-color: {c['surface']};
    border-color: transparent;
}}
QPushButton[btnSize="sm"] {{
    min-height: 24px;
    padding: 2px 8px;
    font-size: 12px;
}}
QPushButton[btnSize="lg"] {{
    min-height: 30px;
    padding: 5px 12px;
    font-weight: 600;
}}
QPushButton[variant="primary"] {{
    background-color: {c['primary']};
    border: 1px solid {c['primary']};
    color: {c['primary_fg']};
    font-weight: 600;
}}
QPushButton[variant="primary"]:hover {{
    background: {c['primary_hover']};
    border-color: {c['primary_hover']};
    color: {c['primary_fg']};
}}
QPushButton[variant="primary"]:pressed {{
    background: {c['primary_pressed']};
    border-color: {c['primary_pressed']};
    color: {c['primary_fg']};
}}
/* accent：轻描边，不当成第二主色 */
QPushButton[variant="accent"] {{
    background-color: transparent;
    border: 1px solid {c['border']};
    color: {c['text']};
    font-weight: 500;
}}
QPushButton[variant="accent"]:hover {{
    border-color: {c['accent']};
    background-color: {c['accent_soft']};
    color: {c['accent']};
}}
/* warn 降级为 ghost，避免工具栏变彩虹 */
QPushButton[variant="warn"] {{
    background: transparent;
    border: 1px solid transparent;
    color: {c['text_dim']};
}}
QPushButton[variant="warn"]:hover {{
    color: {c['text']};
    background: {c['ghost_hover']};
}}
QPushButton[variant="danger"] {{
    background-color: transparent;
    border: 1px solid {c['border']};
    color: {c['danger']};
}}
QPushButton[variant="danger"]:hover {{
    background-color: {c['danger_hover_bg']};
    border-color: {c['danger']};
}}
QPushButton[variant="danger_fill"] {{
    background-color: {c['danger']};
    border: 1px solid {c['danger']};
    color: #ffffff;
    font-weight: 600;
}}
QPushButton[variant="danger_fill"]:hover {{
    background-color: #e05a62;
    border-color: #e05a62;
}}
QPushButton[variant="danger_fill"]:disabled {{
    background-color: {c['surface2']};
    border-color: {c['border']};
    color: {c['text_dim']};
}}
QPushButton[variant="ghost"] {{
    background: transparent;
    border: 1px solid transparent;
    color: {c['text_dim']};
}}
QPushButton[variant="ghost"]:hover {{
    color: {c['text']};
    background: {c['ghost_hover']};
    border-color: transparent;
}}

QTabWidget::pane {{
    border: none;
    border-radius: 0;
    background: transparent;
    top: -1px;
    padding: 8px 0 0 0;
}}
QTabBar {{
    background: {c['surface']};
    border-bottom: 1px solid {c['border']};
}}
QTabBar::tab {{
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    border-radius: 0;
    padding: 5px 10px 4px 10px;
    margin: 0 1px;
    color: {c['tab_text']};
    min-height: 15px;
    font-size: 12px;
}}
QTabBar::tab:selected {{
    background: transparent;
    border-bottom: 2px solid {c['primary']};
    color: {c['tab_text_selected']};
    font-weight: 600;
}}
QTabBar::tab:hover:!selected {{
    color: {c['tab_text_selected']};
    background: {c['surface2']};
}}
QTabBar::scroller {{
    width: 20px;
    background: {c['surface']};
    border: none;
}}
QTabBar QToolButton {{
    background: {c['surface']};
    border: 1px solid {c['border']};
    border-radius: {r};
    padding: 2px;
}}
QTabBar QToolButton:hover {{
    background: {c['surface2']};
}}
QTabWidget#mainTabs::pane {{
    border: none;
    border-radius: 0;
    background: transparent;
    padding: 10px 12px 12px 12px;
}}
QTabWidget#mainTabs {{
    background: transparent;
}}
QTabWidget#mainTabs QTabBar {{
    background: {c['surface']};
    border: none;
    border-bottom: 1px solid {c['border']};
    min-height: 38px;
    padding-left: 8px;
}}
QTabWidget#mainTabs QTabBar::tab {{
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    border-radius: 0;
    padding: 7px 12px 6px 12px;
    margin: 0 1px;
    color: {c['tab_text']};
    min-height: 18px;
    font-weight: 600;
    font-size: 12px;
}}
QTabWidget#mainTabs QTabBar::tab:selected {{
    background: transparent;
    border: none;
    border-bottom: 2px solid {c['primary']};
    color: {c['tab_text_selected']};
    font-weight: 700;
}}
QTabWidget#mainTabs QTabBar::tab:hover:!selected {{
    background: {c['ghost_hover']};
    color: {c['tab_text_selected']};
    border-radius: 6px 6px 0 0;
}}

QTreeWidget, QListWidget, QTableWidget {{
    background-color: {c['input_bg']};
    border: none;
    border-radius: {r};
    outline: none;
    alternate-background-color: {c['surface']};
    padding: 2px;
}}
QTreeWidget::item, QListWidget::item {{
    padding: 3px 6px;
    border-radius: 4px;
    margin: 0px 1px;
}}
QTreeWidget::item:hover, QListWidget::item:hover {{
    background-color: {c['ghost_hover']};
}}
QTreeWidget::item:selected, QListWidget::item:selected {{
    background-color: {c['selection']};
    color: {c['text']};
}}
QHeaderView::section {{
    background: {c['surface2']};
    border: none;
    border-bottom: 1px solid {c['border']};
    padding: 6px 8px;
    color: {c['text_dim']};
    font-weight: 600;
}}

QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 2px;
}}
QScrollBar::handle:vertical {{
    background: {c['border']};
    min-height: 28px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical:hover {{ background: {c['text_dim']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}
QScrollBar:horizontal {{
    background: transparent;
    height: 10px;
    margin: 2px;
}}
QScrollBar::handle:horizontal {{
    background: {c['border']};
    min-width: 28px;
    border-radius: 4px;
}}
QScrollBar::handle:horizontal:hover {{ background: {c['text_dim']}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{ background: transparent; }}

QSplitter::handle {{ background: {c['border']}; }}
QSplitter::handle:hover {{ background: {c['primary']}; }}
QSplitter::handle:horizontal {{ width: 1px; margin: 0; }}
QSplitter::handle:vertical {{ height: 1px; margin: 0; }}
#cryptoWorkbench QSplitter::handle:horizontal {{
    width: 1px;
    margin: 0;
    background: {c['border']};
}}
#cryptoWorkbench QSplitter::handle:vertical {{
    height: 1px;
    margin: 0;
    background: {c['border']};
}}

QMenu {{
    background: {c['surface2']};
    border: 1px solid {c['border']};
    border-radius: {r};
    padding: 4px;
}}
QMenu::item {{
    padding: 7px 20px;
    border-radius: 4px;
}}
QMenu::item:selected {{ background: {c['selection']}; }}
QMenu::separator {{
    height: 1px;
    background: {c['border']};
    margin: 4px 8px;
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
    background-color: {c['surface']};
    border: 1px solid {c['border']};
    border-radius: {r};
    padding: 4px 8px;
    color: {c['text']};
    min-height: 18px;
}}
QToolButton:hover {{ background-color: {c['surface2']}; }}
QToolButton::menu-indicator {{ image: none; width: 0; }}

QCheckBox {{
    spacing: 6px;
    background: transparent;
    min-height: 22px;
    color: {c['text']};
    font-size: 12px;
}}
QCheckBox::indicator {{
    width: 14px;
    height: 14px;
    border-radius: 3px;
    border: 1px solid {c['border']};
    background: {c['input_bg']};
}}
QCheckBox::indicator:checked {{
    background: {c['accent']};
    border-color: {c['accent']};
}}
QCheckBox::indicator:hover {{
    border-color: {c['accent']};
}}

QPushButton[sidebarAux="true"],
QToolButton[sidebarAux="true"] {{
    padding: 3px 8px;
    min-height: 24px;
    font-size: 12px;
    background: transparent;
    border: 1px solid transparent;
    border-radius: 5px;
    color: {c['text']};
}}
QPushButton[sidebarAux="true"]:hover,
QToolButton[sidebarAux="true"]:hover {{
    color: {c['text']};
    background: {c['ghost_hover']};
    border-color: {c['border']};
}}
/* 仅图标小钮：固定方块 */
QPushButton[sidebarAux="true"][iconOnly="true"],
QToolButton[sidebarAux="true"][iconOnly="true"] {{
    min-width: 24px;
    max-width: 24px;
    min-height: 24px;
    max-height: 24px;
    padding: 2px;
}}

/* ── 企业版：顶部应用工具栏 ───────────────────────── */
#appToolbar {{
    background-color: {c['surface']};
    border-bottom: 1px solid {c['border']};
}}
#appToolbarBrandName {{
    font-size: 14px;
    font-weight: 700;
    color: {c['text']};
    background: transparent;
}}
#appToolbarBrandSub {{
    font-size: 10px;
    color: {c['text_dim']};
    background: transparent;
}}
#appToolbarChip {{
    background: {c['chip_bg']};
    border: 1px solid {c['border']};
    border-radius: 6px;
    padding: 3px 8px;
    font-size: 11px;
    color: {c['text']};
}}
#appToolbarChipLabel {{
    font-size: 10px;
    color: {c['text_dim']};
    background: transparent;
    padding-right: 4px;
}}
#appToolbarBtn {{
    background: transparent;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 5px 12px;
    min-height: 20px;
    color: {c['text']};
    font-size: 12px;
}}
#appToolbarBtn:hover {{ background: {c['ghost_hover']}; border-color: {c['border']}; }}
#appToolbarBtn[active="true"] {{ color: {c['primary']}; font-weight: 600; }}
#appToolbarSep {{
    background-color: {c['border']};
    max-width: 1px;
    min-height: 22px;
}}

/* ── 企业版：底部状态栏 ───────────────────────────── */
QStatusBar {{
    background-color: {c['surface']};
    border-top: 1px solid {c['border']};
    color: {c['text_dim']};
    font-size: 11px;
}}
QStatusBar::item {{ border: none; }}
#statusBarSegment {{
    background: transparent;
    border: none;
    padding: 3px 12px;
    color: {c['text_dim']};
    font-size: 11px;
}}
#statusBarSegment QLabel {{ background: transparent; }}
#statusBarProjectName {{ color: {c['text']}; font-weight: 600; }}
#statusBarValue {{ color: {c['text']}; }}
#statusBarVersion {{ color: {c['text_dim']}; font-size: 10px; }}

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
    padding: 0;
    min-height: 22px;
    max-height: 22px;
    min-width: 22px;
    max-width: 22px;
    font-size: 11px;
    border-radius: 5px;
}}

QLabel[feedbackBox="true"] {{
    padding: 8px 10px;
    font-size: 11px;
    border-radius: {r};
    background: {c['input_bg']};
    border: 1px solid {c['border']};
}}
QLabel[feedbackKind="error"] {{ color: {c['danger']}; border-color: {c['danger']}; }}

#homePage, #homeBody {{
    background: transparent;
}}
#homeHead {{
    background: transparent;
    border: none;
}}
#homeTitle {{
    font-size: 20px;
    font-weight: 700;
    color: {c['text']};
    background: transparent;
    letter-spacing: -0.3px;
}}
#homeSub {{
    font-size: 12.5px;
    color: {c['text_dim']};
    background: transparent;
}}
#homeStatusStrip {{
    background: {c['surface']};
    border: 1px solid {c.get('line_soft', c['border'])};
    border-radius: 8px;
}}
#homeStatusCell {{
    background: transparent;
    border: none;
}}
#homeStatusSep {{
    background-color: {c.get('line_soft', c['border'])};
    border: none;
    max-width: 1px;
}}
#homeMetaLabel {{
    font-size: 11px;
    font-weight: 500;
    color: {c['text_dim']};
    background: transparent;
}}
#homeMetaValue {{
    font-size: 13px;
    font-weight: 600;
    color: {c['text']};
    background: transparent;
}}
#homeMetaValue[state="running"] {{
    color: {c['ok']};
}}
#homeMetaValue[state="stopped"] {{
    color: {c['text_dim']};
}}
#homeStepsBar {{
    background: transparent;
    border: none;
}}
#homeStepCard {{
    background: {c['surface']};
    border: 1px solid {c.get('line_soft', c['border'])};
    border-radius: 8px;
}}
#homeStepNum {{
    background: {c.get('badge_bg', c['surface2'])};
    border: none;
    border-radius: 6px;
    color: {c['text_dim']};
    font-size: 11px;
    font-weight: 700;
}}
#homeStepTitle {{
    font-size: 12.5px;
    font-weight: 600;
    color: {c['text']};
    background: transparent;
}}
#homeStepDesc {{
    font-size: 11px;
    color: {c['text_dim']};
    background: transparent;
}}
#homeTopoPanel {{
    background: {c['surface']};
    border: 1px solid {c.get('line_soft', c['border'])};
    border-radius: 10px;
}}
#homeCaption {{
    font-size: 11px;
    font-weight: 700;
    color: {c['text_dim']};
    background: transparent;
    letter-spacing: 0.3px;
}}
#homeTopoPath {{
    font-size: 11.5px;
    color: {c['text_dim']};
    background: transparent;
}}
#homeTopology {{
    background: {c.get('badge_bg', c['surface2'])};
    border: 1px solid {c.get('line_soft', c['border'])};
    border-radius: 8px;
    padding: 8px;
}}
#homeEmptyHint {{
    background: transparent;
    border: none;
    padding: 4px 0;
    color: {c['text_dim']};
}}
#projectEmptyHint {{
    color: {c['text_dim']};
    font-size: 11px;
    background: transparent;
}}
QDialogButtonBox QPushButton {{
    min-width: 64px;
    min-height: 26px;
    max-height: 26px;
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


def style_button(btn, variant: str = "default", *, size: str = "md") -> None:
    """统一按钮外观。

    variant:
      - primary: 本栏唯一主操作（启动/保存/解析）
      - default: 次要实心灰底
      - accent: 轻描边次强调（少用）
      - ghost / warn: 弱操作（撤销/清空/复制）
      - danger / danger_fill: 停止/删除
    size: sm(26) | md(30) | lg(34)
    """
    # 旧 warn 与 ghost 同级，避免工具栏变色块墙
    if variant == "warn":
        variant = "ghost"
    btn.setProperty("variant", "" if variant == "default" else variant)
    btn.setProperty("btnSize", size if size in ("sm", "md", "lg") else "md")
    # 清掉各处散落的 FixedHeight，交给 QSS 管齐
    try:
        btn.setMinimumHeight(0)
        btn.setMaximumHeight(16777215)
    except Exception:
        pass
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


def setup_mono_field(widget) -> None:
    """密文/明文等等宽输入区，随主题切换，不加语法高亮。"""
    widget.setObjectName("monoField")
    widget.setStyleSheet("")


def setup_sub_tabs(tab_widget) -> None:
    """设置内页等二级 Tab — 不截断文字，过窄时出滚动箭头。"""
    from PyQt6.QtCore import QSize
    tab_widget.setObjectName("subTabs")
    tab_widget.setDocumentMode(True)
    tab_widget.setMovable(False)
    tab_widget.setIconSize(QSize(14, 14))
    bar = tab_widget.tabBar()
    bar.setExpanding(False)
    bar.setUsesScrollButtons(True)
    bar.setDrawBase(False)
    bar.setElideMode(Qt.TextElideMode.ElideNone)
    bar.setIconSize(QSize(14, 14))
    repolish_widget(tab_widget)


def build_logo_header(parent_layout, icon_path: str | None = None) -> None:
    """侧边栏品牌区 — 图标与标题略突出。"""
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QPixmap
    from PyQt6.QtWidgets import QFrame, QHBoxLayout, QVBoxLayout, QLabel
    from core.icon_loader import MAIN_ICON
    from core.brand import APP_NAME, APP_NAME_EN, APP_VERSION, APP_CREDIT_AUTHOR, APP_TAGLINE

    card = QFrame()
    card.setObjectName("sidebarBrandCard")
    repolish_widget(card)

    outer = QVBoxLayout(card)
    outer.setContentsMargins(2, 4, 2, 12)
    outer.setSpacing(0)

    row = QHBoxLayout()
    row.setSpacing(10)
    row.setAlignment(Qt.AlignmentFlag.AlignVCenter)

    logo = QLabel()
    logo.setObjectName("sidebarBrandLogo")
    logo.setFixedSize(42, 42)
    logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
    img = icon_path or MAIN_ICON
    if img:
        pm = QPixmap(img).scaled(
            34, 34, Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        if not pm.isNull():
            logo.setPixmap(pm)
    row.addWidget(logo)

    text_col = QVBoxLayout()
    text_col.setSpacing(2)
    name_cn = QLabel(f"{APP_NAME} {APP_NAME_EN} {APP_VERSION}")
    name_cn.setObjectName("sidebarBrandNameCn")
    text_col.addWidget(name_cn)
    author = QLabel(f"作者：{APP_CREDIT_AUTHOR}")
    author.setObjectName("sidebarBrandAuthor")
    text_col.addWidget(author)
    row.addLayout(text_col, 1)
    outer.addLayout(row)

    tip = f"{APP_NAME} {APP_NAME_EN} {APP_VERSION}\n{APP_TAGLINE}"
    name_cn.setToolTip(tip)
    author.setToolTip(tip)
    logo.setToolTip(tip)

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
    """步骤卡 ↑↓× 等方块小按钮."""
    btn.setProperty("compact", True)
    style_button(btn, variant, size="sm")
    btn.setFixedSize(22, 22)


def style_sidebar_aux_button(btn, *, icon_only: bool = False) -> None:
    """侧栏次要操作。icon_only=True 仅用于纯图标钮（固定方块）。"""
    btn.setProperty("sidebarAux", True)
    btn.setProperty("iconOnly", "true" if icon_only else "")
    try:
        if not icon_only:
            btn.setMaximumWidth(16777215)
            btn.setMinimumWidth(0)
    except Exception:
        pass
    _repolish(btn)


def apply_soft_shadow(
    widget: QWidget,
    *,
    blur: int = 14,
    x: int = 0,
    y: int = 0,
    alpha: int = 45,
) -> None:
    """轻阴影（参考 TrafficEye），透明度低，避免糊成卡片墙."""
    from PyQt6.QtWidgets import QGraphicsDropShadowEffect

    effect = QGraphicsDropShadowEffect(widget)
    effect.setBlurRadius(blur)
    effect.setOffset(x, y)
    effect.setColor(QColor(0, 0, 0, max(0, min(255, alpha))))
    widget.setGraphicsEffect(effect)


def setup_main_tabs(tab_widget) -> None:
    """主界面 Tab — 主色底线选中；文字不省略。"""
    from PyQt6.QtCore import QSize
    tab_widget.setObjectName("mainTabs")
    tab_widget.setIconSize(QSize(18, 18))
    tab_widget.setDocumentMode(True)
    tab_widget.setMovable(False)
    bar = tab_widget.tabBar()
    bar.setExpanding(False)
    bar.setUsesScrollButtons(True)
    bar.setDrawBase(False)
    bar.setElideMode(Qt.TextElideMode.ElideNone)
    bar.setIconSize(QSize(18, 18))
    repolish_widget(tab_widget)


def setup_log_view(widget) -> None:
    widget.setObjectName("logView")


def apply_theme(app: QApplication, theme: str | None = None) -> str:
    """应用主题，返回实际使用的 theme 名 (dark/light)."""
    from core.app_settings import get_theme

    name = theme or get_theme()
    if name not in PALETTES:
        name = "light"

    _activate_palette(name)
    try:
        from core.icon_loader import clear_icon_cache
        clear_icon_cache()
    except ImportError:
        pass

    app.setStyle("Fusion")
    font = QFont()
    font.setFamilies(["Segoe UI", "Microsoft YaHei UI", "PingFang SC", "Arial"])
    font.setPointSize(10)
    app.setFont(font)
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
