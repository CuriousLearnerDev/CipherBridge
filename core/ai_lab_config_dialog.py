"""AI 实验室 — AI / 高级配置对话框."""

from __future__ import annotations

from PyQt6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QGroupBox, QLabel,
    QLineEdit, QMessageBox, QPushButton, QSpinBox, QTabWidget, QVBoxLayout, QWidget,
)

from core.ai_analyzer import test_ai_config
from core.brand import APP_TITLE
from core.theme import style_button, style_muted_label, style_sidebar_aux_button


class AILabConfigDialog(QDialog):
    """AI 与 API 代理、高级选项 — 弹窗填写."""

    def __init__(self, parent=None, *, initial_tab: str = "ai"):
        super().__init__(parent)
        self.setWindowTitle("AI自动化分析配置")
        self.setMinimumWidth(440)
        self._initial_tab = initial_tab
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        self.tabs = QTabWidget()

        # ---- AI 与 API ----
        ai_page = QWidget()
        ai_form = QFormLayout(ai_page)
        ai_form.setSpacing(8)
        self.api_key_edit = QLineEdit()
        self.api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_edit.setPlaceholderText("OpenAI 兼容 API Key")
        self.base_url_edit = QLineEdit()
        self.base_url_edit.setPlaceholderText("https://api.deepseek.com/v1")
        self.model_edit = QLineEdit()
        self.model_edit.setPlaceholderText("deepseek-chat")
        self.proxy_check = QCheckBox("API 请求走 HTTP 代理")
        self.http_proxy_edit = QLineEdit()
        self.http_proxy_edit.setPlaceholderText("127.0.0.1:7897")
        ai_form.addRow("API Key:", self.api_key_edit)
        ai_form.addRow("Base URL:", self.base_url_edit)
        ai_form.addRow("模型:", self.model_edit)
        ai_form.addRow(self.proxy_check)
        ai_form.addRow("HTTP 代理:", self.http_proxy_edit)
        self.test_btn = QPushButton("测试连接")
        self.test_btn.setToolTip("发送最小请求验证 API Key、Base URL、模型与代理")
        self.test_btn.clicked.connect(self._test_config)
        style_sidebar_aux_button(self.test_btn)
        ai_form.addRow("", self.test_btn)
        hint = QLabel(
            "配置保存至 config/ai.yaml（已在 .gitignore 中）。"
            "Agent 对话使用 Anthropic Messages + tools"
            "（DeepSeek 会自动映射到 /anthropic）。"
        )
        style_muted_label(hint)
        hint.setWordWrap(True)
        ai_form.addRow(hint)
        self.tabs.addTab(ai_page, "AI 与 API")

        # ---- 高级 ----
        adv_page = QWidget()
        adv_layout = QVBoxLayout(adv_page)
        adv_grp = QGroupBox("浏览器代理")
        adv_form = QFormLayout(adv_grp)
        self.mitm_check = QCheckBox(f"经 {APP_TITLE} 解密端转发（一般不需要）")
        self.mitm_port = QSpinBox()
        self.mitm_port.setRange(1024, 65535)
        self.mitm_port.setValue(8080)
        self.mitm_port.setEnabled(False)
        self.mitm_check.toggled.connect(self.mitm_port.setEnabled)
        adv_form.addRow(self.mitm_check)
        adv_form.addRow("代理端口:", self.mitm_port)
        adv_layout.addWidget(adv_grp)
        adv_layout.addStretch()
        self.tabs.addTab(adv_page, "高级")

        if self._initial_tab == "advanced":
            self.tabs.setCurrentIndex(1)

        layout.addWidget(self.tabs)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel,
        )
        save_btn = buttons.button(QDialogButtonBox.StandardButton.Save)
        save_btn.setText("保存")
        style_button(save_btn, "primary")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def load_from(self, cfg: dict) -> None:
        self.api_key_edit.setText(cfg.get("api_key", ""))
        self.base_url_edit.setText(cfg.get("base_url", ""))
        self.model_edit.setText(cfg.get("model", ""))
        self.proxy_check.setChecked(bool(cfg.get("use_http_proxy")))
        self.http_proxy_edit.setText(cfg.get("http_proxy", "127.0.0.1:7897"))
        browser = cfg.get("browser", {})
        self.mitm_check.setChecked(bool(browser.get("use_mitm_proxy", False)))
        self.mitm_port.setValue(int(browser.get("mitm_port", 8080)))
        self.mitm_port.setEnabled(self.mitm_check.isChecked())

    def collect(self, *, hook_enabled: bool) -> dict:
        return {
            "api_key": self.api_key_edit.text().strip(),
            "base_url": self.base_url_edit.text().strip(),
            "model": self.model_edit.text().strip(),
            "use_http_proxy": self.proxy_check.isChecked(),
            "http_proxy": self.http_proxy_edit.text().strip(),
            "browser": {
                "hook_enabled": hook_enabled,
                "headless": False,
                "use_mitm_proxy": self.mitm_check.isChecked(),
                "mitm_port": self.mitm_port.value(),
            },
        }

    def _test_config(self) -> None:
        cfg = {
            "api_key": self.api_key_edit.text().strip(),
            "base_url": self.base_url_edit.text().strip(),
            "model": self.model_edit.text().strip(),
            "use_http_proxy": self.proxy_check.isChecked(),
            "http_proxy": self.http_proxy_edit.text().strip(),
        }
        self.test_btn.setEnabled(False)
        self.test_btn.setText("测试中…")
        try:
            ok, msg = test_ai_config(cfg)
        finally:
            self.test_btn.setEnabled(True)
            self.test_btn.setText("测试连接")
        if ok:
            QMessageBox.information(self, "测试成功", msg)
        else:
            QMessageBox.warning(self, "测试失败", msg)
