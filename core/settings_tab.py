"""设置中心 Tab — 通用设置 + 加解密测试 / 日志."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication, QComboBox, QFormLayout, QLabel, QPushButton,
    QTabWidget, QVBoxLayout, QWidget,
)

from core.app_settings import get_theme, set_theme
from core.brand import APP_REPO_URL
from core.theme import (
    apply_theme, configure_combo_popup, refresh_widget_tree,
    style_button, style_muted_label,
)


class GeneralSettingsPage(QWidget):
    """主题 / 加载方式 / 证书 — 原设置对话框内容."""

    def __init__(self, control, parent=None):
        super().__init__(parent)
        self.control = control
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        hint = QLabel("界面与代理加载相关选项。保存后立即生效。")
        hint.setWordWrap(True)
        style_muted_label(hint)
        layout.addWidget(hint)

        form = QFormLayout()
        self.theme_combo = QComboBox()
        self.theme_combo.addItem("浅色（白色）", "light")
        self.theme_combo.addItem("深色", "dark")
        configure_combo_popup(self.theme_combo)
        current = get_theme()
        idx = self.theme_combo.findData(current)
        if idx >= 0:
            self.theme_combo.setCurrentIndex(idx)
        self.theme_combo.currentIndexChanged.connect(self._on_theme_changed)
        form.addRow("界面主题:", self.theme_combo)

        self.mode_combo = QComboBox()
        self.mode_combo.addItem("plugin.py 直接", "plugin")
        self.mode_combo.addItem("main.py 框架", "main")
        self.mode_combo.setToolTip(
            "plugin.py 直接: mitmdump -s plugins/.../plugin.py，改代码后重启即生效\n"
            "main.py 框架: mitmdump -s main.py + PROFILE，含匹配/日志/响应钩子"
        )
        configure_combo_popup(self.mode_combo)
        if hasattr(self.control, "load_mode_combo"):
            idx = self.control.load_mode_combo.currentIndex()
            if idx >= 0:
                self.mode_combo.setCurrentIndex(idx)
        form.addRow("加载方式:", self.mode_combo)
        layout.addLayout(form)

        cert_hint = QLabel(
            "HTTPS 抓包需安装 mitmproxy 根证书。\n"
            "证书状态仍在左侧解密端区域显示；启动解密时也会自动检查。"
        )
        cert_hint.setWordWrap(True)
        layout.addWidget(cert_hint)

        self.cert_btn = QPushButton("安装 HTTPS 证书")
        self.cert_btn.setToolTip("Windows 一键自动安装；macOS/Linux 打开证书文件")
        self.cert_btn.clicked.connect(self._install_cert)
        style_button(self.cert_btn, "accent")
        layout.addWidget(self.cert_btn)

        repo_label = QLabel(
            f'项目地址: <a href="{APP_REPO_URL}">{APP_REPO_URL}</a>'
        )
        repo_label.setOpenExternalLinks(True)
        repo_label.setWordWrap(True)
        repo_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextBrowserInteraction
        )
        layout.addWidget(repo_label)

        save_btn = QPushButton("保存设置")
        save_btn.clicked.connect(self._save)
        style_button(save_btn, "primary")
        layout.addWidget(save_btn)
        layout.addStretch()

    def _install_cert(self) -> None:
        if hasattr(self.control, "_install_https_cert"):
            self.control._install_https_cert()

    def sync_from_control(self) -> None:
        if hasattr(self.control, "load_mode_combo"):
            idx = self.control.load_mode_combo.currentIndex()
            if idx >= 0:
                self.mode_combo.setCurrentIndex(idx)
        idx = self.theme_combo.findData(get_theme())
        if idx >= 0:
            self.theme_combo.blockSignals(True)
            self.theme_combo.setCurrentIndex(idx)
            self.theme_combo.blockSignals(False)

    def _apply_theme_now(self, theme: str) -> None:
        set_theme(theme)
        app = QApplication.instance()
        if app is None:
            return
        apply_theme(app, theme)
        win = self.window()
        if win is not None:
            refresh_widget_tree(win)
            if hasattr(win, "refresh_tab_icons"):
                win.refresh_tab_icons()
            if hasattr(win, "refresh_window_frame"):
                win.refresh_window_frame()
            if hasattr(win, "control"):
                win.control._update_project_ui_state()

    def _on_theme_changed(self, _index: int = 0) -> None:
        theme = self.theme_combo.currentData() or "dark"
        self._apply_theme_now(theme)

    def _save(self) -> None:
        if hasattr(self.control, "load_mode_combo"):
            self.control.load_mode_combo.setCurrentIndex(self.mode_combo.currentIndex())
        theme = self.theme_combo.currentData() or "dark"
        self._apply_theme_now(theme)


class SettingsHubTab(QWidget):
    """主界面「设置」— 内含通用 / 加解密测试 / 日志."""

    PAGE_GENERAL = 0
    PAGE_CRYPTO = 1
    PAGE_LOG = 2

    def __init__(self, control, crypto_tab, log_tab, parent=None):
        super().__init__(parent)
        self.control = control
        self.crypto_tab = crypto_tab
        self.log_tab = log_tab

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(0)

        self.inner_tabs = QTabWidget()
        self.general_page = GeneralSettingsPage(control)
        self.inner_tabs.addTab(self.general_page, "通用")
        self.inner_tabs.addTab(crypto_tab, "加解密测试")
        self.inner_tabs.addTab(log_tab, "日志")
        layout.addWidget(self.inner_tabs)

    def show_page(self, page: int) -> None:
        if 0 <= page < self.inner_tabs.count():
            self.inner_tabs.setCurrentIndex(page)
            if page == self.PAGE_GENERAL:
                self.general_page.sync_from_control()
