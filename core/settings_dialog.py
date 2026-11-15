"""应用设置对话框."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QLabel,
    QPushButton, QVBoxLayout,
)

from core.app_settings import get_theme, set_theme
from core.brand import APP_REPO_URL
from core.theme import apply_theme, configure_combo_popup, refresh_widget_tree


class SettingsDialog(QDialog):
    """加载方式、主题、证书安装等全局设置."""

    def __init__(self, control, parent=None):
        super().__init__(parent)
        self.control = control
        self.setWindowTitle("设置")
        self.setMinimumWidth(400)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        form = QFormLayout()

        self.theme_combo = QComboBox()
        self.theme_combo.addItem("浅色（白色）", "light")
        self.theme_combo.addItem("深色", "dark")
        configure_combo_popup(self.theme_combo)
        current = get_theme()
        idx = self.theme_combo.findData(current)
        if idx >= 0:
            self.theme_combo.setCurrentIndex(idx)
        form.addRow("界面主题:", self.theme_combo)

        self.mode_combo = QComboBox()
        self.mode_combo.addItem("plugin.py 直接", "plugin")
        self.mode_combo.addItem("main.py 框架", "main")
        self.mode_combo.setToolTip(
            "plugin.py 直接: mitmdump -s plugins/.../plugin.py，改代码后重启即生效\n"
            "main.py 框架: mitmdump -s main.py + PROFILE，含匹配/日志/响应钩子"
        )
        configure_combo_popup(self.mode_combo)
        idx = self.control.load_mode_combo.currentIndex()
        if idx >= 0:
            self.mode_combo.setCurrentIndex(idx)
        form.addRow("加载方式:", self.mode_combo)
        layout.addLayout(form)

        cert_hint = QLabel(
            "HTTPS 抓包需安装 mitmproxy 根证书。\n"
            "证书状态仍在解密端区域显示；启动解密时也会自动检查。"
        )
        cert_hint.setWordWrap(True)
        layout.addWidget(cert_hint)

        self.cert_btn = QPushButton("安装 HTTPS 证书")
        self.cert_btn.setToolTip("Windows 一键自动安装；macOS/Linux 打开证书文件")
        self.cert_btn.clicked.connect(self._install_cert)
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

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel,
        )
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("保存")
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _install_cert(self) -> None:
        self.control._install_https_cert()

    def _save(self) -> None:
        self.control.load_mode_combo.setCurrentIndex(self.mode_combo.currentIndex())
        theme = self.theme_combo.currentData() or "dark"
        set_theme(theme)
        app = QApplication.instance()
        if app is not None:
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
        self.accept()
