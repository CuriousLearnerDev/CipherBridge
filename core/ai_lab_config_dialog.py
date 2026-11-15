"""AI 实验室 — AI / 高级配置对话框."""

from __future__ import annotations

from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QGroupBox, QLabel,
    QLineEdit, QMessageBox, QPushButton, QSpinBox, QTabWidget, QVBoxLayout, QWidget,
)

from core.ai_analyzer import test_ai_config
from core.ai_config import resolve_agent_base_url
from core.brand import APP_TITLE
from core.theme import style_button, style_muted_label


# (yaml 值, 显示名)
_API_FORMAT_ITEMS = (
    ("deepseek", "DeepSeek（Agent → /anthropic）"),
    ("newapi", "New API / One API（Agent → /v1/messages）"),
    ("custom", "自定义 Agent 端点"),
)


class AILabConfigDialog(QDialog):
    """AI 与 API 代理、高级选项 — 弹窗填写."""

    def __init__(self, parent=None, *, initial_tab: str = "ai"):
        super().__init__(parent)
        self.setWindowTitle("AI自动化分析配置")
        self.setMinimumWidth(480)
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
        self.api_format_combo = QComboBox()
        for value, label in _API_FORMAT_ITEMS:
            self.api_format_combo.addItem(label, value)
        self.api_format_combo.currentIndexChanged.connect(self._on_api_format_changed)
        self.base_url_edit = QLineEdit()
        self.base_url_edit.setPlaceholderText("https://api.deepseek.com/v1 或 http://host:port/v1")
        self.agent_base_url_edit = QLineEdit()
        self.agent_base_url_edit.setPlaceholderText("http://host:port（Agent 会再拼 /v1/messages）")
        self.model_edit = QLineEdit()
        self.model_edit.setPlaceholderText("deepseek-chat / deepseek-v4-flash")
        self.proxy_check = QCheckBox("API 请求走 HTTP 代理")
        self.http_proxy_edit = QLineEdit()
        self.http_proxy_edit.setPlaceholderText("127.0.0.1:7897")
        ai_form.addRow("API Key:", self.api_key_edit)
        ai_form.addRow("API 格式:", self.api_format_combo)
        ai_form.addRow("Base URL:", self.base_url_edit)
        ai_form.addRow("Agent Base URL:", self.agent_base_url_edit)
        ai_form.addRow("模型:", self.model_edit)
        ai_form.addRow(self.proxy_check)
        ai_form.addRow("HTTP 代理:", self.http_proxy_edit)
        self.test_btn = QPushButton("测试连接")
        self.test_btn.setToolTip("发送最小请求验证 API Key、Base URL、模型与代理（OpenAI chat）")
        self.test_btn.clicked.connect(self._test_config)
        style_button(self.test_btn, "ghost", size="sm")
        ai_form.addRow("", self.test_btn)
        self.format_hint = QLabel("")
        style_muted_label(self.format_hint)
        self.format_hint.setWordWrap(True)
        ai_form.addRow(self.format_hint)
        self.tabs.addTab(ai_page, "AI 与 API")

        # ---- 高级 ----
        adv_page = QWidget()
        adv_layout = QVBoxLayout(adv_page)
        adv_grp = QGroupBox("浏览器代理")
        adv_form = QFormLayout(adv_grp)
        self.mitm_check = QCheckBox(f"经 {APP_TITLE} 解密端转发（与左侧监听端口一致，默认 8083）")
        self.mitm_port = QSpinBox()
        self.mitm_port.setRange(1024, 65535)
        self.mitm_port.setValue(8083)
        self.mitm_port.setEnabled(False)
        self.mitm_check.toggled.connect(self.mitm_port.setEnabled)
        adv_form.addRow(self.mitm_check)
        adv_form.addRow("解密端端口:", self.mitm_port)
        self.record_mode_check = QCheckBox(
            "记录模式（固定持久 Profile，类似 Burp 浏览器）"
        )
        self.record_mode_check.setChecked(True)
        self.record_mode_check.setToolTip(
            "勾选后复用 data/browser_profile（Cookie/登录态长期保留）；"
            "取消则每次临时会话，关闭后清理。"
        )
        adv_form.addRow(self.record_mode_check)
        self.browser_channel_combo = QComboBox()
        self.browser_channel_combo.addItem("Chromium（内置）", "chromium")
        self.browser_channel_combo.addItem("本机 Chrome", "chrome")
        self.browser_channel_combo.addItem("本机 Edge", "msedge")
        self.browser_channel_combo.setToolTip(
            "本机 Chrome/Edge 需已安装；真实浏览器模式优先用它们。"
            "仍使用密桥独立 Profile，不占用日常浏览用户目录。"
        )
        adv_form.addRow("浏览器引擎:", self.browser_channel_combo)
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
        self._on_api_format_changed()

    def _current_api_format(self) -> str:
        data = self.api_format_combo.currentData()
        return str(data or "deepseek")

    def _on_api_format_changed(self, *_args) -> None:
        fmt = self._current_api_format()
        custom = fmt == "custom"
        self.agent_base_url_edit.setEnabled(custom)
        if fmt == "deepseek":
            self.format_hint.setText(
                "分析用 OpenAI /v1/chat/completions；"
                "Agent 自动映射到 {host}/anthropic/v1/messages。"
                "配置保存在 config/ai.yaml。"
            )
            self.base_url_edit.setPlaceholderText("https://api.deepseek.com/v1")
        elif fmt == "newapi":
            self.format_hint.setText(
                "适用于 New API / One API 等网关。"
                "Base URL 填 http://主机:端口/v1（未写 /v1 会自动补）；"
                "Agent 走同主机 /v1/messages。模型名须与后台通道一致。"
            )
            self.base_url_edit.setPlaceholderText("http://127.0.0.1:3000/v1")
        else:
            self.format_hint.setText(
                "自定义：Base URL 仍用于分析（OpenAI chat）；"
                "Agent Base URL 填 Anthropic 根地址（程序会再拼 /v1/messages）。"
                "例如填 http://host:port 则请求 http://host:port/v1/messages。"
            )
            self.base_url_edit.setPlaceholderText("http://host:port/v1")
            self.agent_base_url_edit.setPlaceholderText("http://host:port 或 https://api.xxx.com/anthropic")

    def load_from(self, cfg: dict) -> None:
        self.api_key_edit.setText(cfg.get("api_key", ""))
        fmt = str(cfg.get("api_format") or "").strip().lower()
        if not fmt:
            # 兼容旧配置：有手写 agent_base_url → custom；非 deepseek 主机 → newapi
            agent = str(cfg.get("agent_base_url") or "").strip()
            base = str(cfg.get("base_url") or "").lower()
            if agent:
                fmt = "custom"
            elif "deepseek.com" in base or not base:
                fmt = "deepseek"
            else:
                fmt = "newapi"
        idx = self.api_format_combo.findData(fmt)
        self.api_format_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self.base_url_edit.setText(cfg.get("base_url", ""))
        self.agent_base_url_edit.setText(cfg.get("agent_base_url", ""))
        self.model_edit.setText(cfg.get("model", ""))
        self.proxy_check.setChecked(bool(cfg.get("use_http_proxy")))
        self.http_proxy_edit.setText(cfg.get("http_proxy", "127.0.0.1:7897"))
        browser = cfg.get("browser", {})
        self.mitm_check.setChecked(bool(browser.get("use_mitm_proxy", False)))
        self.mitm_port.setValue(int(browser.get("mitm_port", 8083)))
        self.mitm_port.setEnabled(self.mitm_check.isChecked())
        self.record_mode_check.setChecked(bool(browser.get("record_mode", True)))
        if hasattr(self, "browser_channel_combo"):
            from core.ai_config import normalize_browser_channel

            ch = normalize_browser_channel(browser.get("browser_channel"))
            idx = self.browser_channel_combo.findData(ch)
            self.browser_channel_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self._on_api_format_changed()

    def collect(
        self,
        *,
        hook_enabled: bool,
        anti_debug: bool = False,
        cdp_skip_pauses: bool = True,
        inject_opts: dict | None = None,
    ) -> dict:
        browser = {
            "hook_enabled": hook_enabled,
            "anti_debug": anti_debug,
            "cdp_skip_pauses": cdp_skip_pauses,
            "headless": False,
            "use_mitm_proxy": self.mitm_check.isChecked(),
            "mitm_port": self.mitm_port.value(),
            "record_mode": self.record_mode_check.isChecked(),
            "browser_channel": str(
                self.browser_channel_combo.currentData() or "chromium"
            ),
        }
        if inject_opts is not None:
            browser["inject_opts"] = inject_opts
        fmt = self._current_api_format()
        agent_base = self.agent_base_url_edit.text().strip() if fmt == "custom" else ""
        return {
            "api_key": self.api_key_edit.text().strip(),
            "api_format": fmt,
            "provider": "deepseek" if fmt == "deepseek" else "openai",
            "base_url": self.base_url_edit.text().strip(),
            "agent_base_url": agent_base,
            "model": self.model_edit.text().strip(),
            "use_http_proxy": self.proxy_check.isChecked(),
            "http_proxy": self.http_proxy_edit.text().strip(),
            "browser": browser,
        }

    def _test_config(self) -> None:
        cfg = {
            "api_key": self.api_key_edit.text().strip(),
            "api_format": self._current_api_format(),
            "base_url": self.base_url_edit.text().strip(),
            "agent_base_url": self.agent_base_url_edit.text().strip(),
            "model": self.model_edit.text().strip(),
            "use_http_proxy": self.proxy_check.isChecked(),
            "http_proxy": self.http_proxy_edit.text().strip(),
        }
        self.test_btn.setEnabled(False)
        self.test_btn.setText("测试中…")
        try:
            ok, msg = test_ai_config(cfg)
            agent = resolve_agent_base_url(cfg)
            msg = f"{msg}\n\nAgent 端点: {agent}/v1/messages"
        finally:
            self.test_btn.setEnabled(True)
            self.test_btn.setText("测试连接")
        if ok:
            QMessageBox.information(self, "测试成功", msg)
        else:
            QMessageBox.warning(self, "测试失败", msg)
