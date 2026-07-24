"""AI 实验室 Tab — 浏览器 + Hook + AI 分析 (参考 AI_JS_DEBUGGER)."""

from __future__ import annotations

import json
import os

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QTextCursor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QPlainTextEdit, QSpinBox, QCheckBox, QSplitter,
    QListWidget, QListWidgetItem, QMessageBox, QFormLayout, QTabWidget,
    QDialog, QDialogButtonBox, QToolButton, QMenu, QSizePolicy,
)

from core.ai_config import load_ai_config, save_ai_config
from core.ai_lab_config_dialog import AILabConfigDialog
from core.ai_analyzer import AIAnalysisWorker, build_initial_messages, _extract_json, _clean_steps
from core.agent_runner import (
    AgentWorker,
    GENERATE_DECRYPT_GOAL,
    GENERATE_ENCRYPT_GOAL,
    RECOGNIZE_GOAL,
)
from core.agent_tools import SessionData
from core.ai_project_writer import (
    save_ai_project, guess_project_name, guess_match_rules, detect_body_format,
    PROFILES_DIR,
)
from core.browser_lab import BrowserLabWorker
from core.miniprogram_tab import MiniprogramPanel
# from core.app_tab import AppReversePanel  # App 页暂隐藏
from core.project_name import normalize_project_name
from core.icon_loader import set_btn_icon
from core.theme import (
    C, style_button, style_muted_label, setup_code_editor, style_sidebar_aux_button,
)
from codegen import codegen_for_pipeline


class _ReadyChip(QLabel):
    """采集计数（兼容旧引用；界面已改用单行状态）."""

    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self._title = title
        self.setObjectName("aiReadyChip")
        self.hide()

    def set_count(self, n: int) -> None:
        self.setText(f"{self._title}  {n}")


class AILabTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._flows: list[dict] = []
        self._flow_keys: dict[str, int] = {}
        self._hooks: list[str] = []
        self._scripts: dict[str, str] = {}
        self._worker: BrowserLabWorker | None = None
        self._analysis_worker: AIAnalysisWorker | None = None
        self._agent_worker: AgentWorker | None = None
        self._last_result: dict | None = None
        self._last_plugin_code: str = ""
        self._auto_generate_after_analysis = False
        self._pending_generate_role: str | None = None
        self._chat_history: list[dict] = []
        self._analysis_stream_pos = 0
        self._analysis_role = "decrypt"
        self._hook_buf: list[str] = []
        self._log_buf: list[str] = []
        self._ui_flush_timer = QTimer(self)
        self._ui_flush_timer.setInterval(80)
        self._ui_flush_timer.timeout.connect(self._flush_ui_buffers)
        self._busy = False
        self._btn_labels = {
            "decrypt": "生成解密",
            "encrypt": "生成加密",
            "recognize": "AI识别加解密",
        }
        self._build_ui()
        self._load_config()
        self._refresh_api_status()
        self._sync_action_buttons()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 8)
        layout.setSpacing(4)

        # 兼容旧代码引用（不加入布局，零占位）
        self.chip_flow = _ReadyChip("流量", self)
        self.chip_hook = _ReadyChip("Hook", self)
        self.chip_js = _ReadyChip("JS", self)
        self.hook_stats = QLabel("", self)
        self.chip_flow.hide()
        self.chip_hook.hide()
        self.chip_js.hide()
        self.hook_stats.hide()

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        # —— 左：采集 ——
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(4)
        self.source_tabs = QTabWidget()
        self.source_tabs.addTab(self._build_browser_source(), "网页")
        self.miniprogram_panel = MiniprogramPanel(compact=True)
        self.miniprogram_panel.scripts_ready.connect(self.load_miniprogram_scripts)
        self.miniprogram_panel.request_ai_analyze.connect(self._run_miniprogram_ai)
        self.miniprogram_panel.flow_captured.connect(self._on_miniprogram_flow)
        self.miniprogram_panel.flow_updated.connect(self._on_miniprogram_flow_updated)
        self.miniprogram_panel.flow_selected.connect(self._show_external_flow)
        self.miniprogram_panel.capture_log.connect(self._log)
        self.source_tabs.addTab(self.miniprogram_panel, "小程序")
        # App 反编译页暂不展示（需要时取消注释）
        # self.app_panel = AppReversePanel(compact=True)
        # self.app_panel.scripts_ready.connect(self.load_app_scripts)
        # self.app_panel.request_ai_analyze.connect(self._run_recognize)
        # self.app_panel.capture_log.connect(self._log)
        # self.source_tabs.addTab(self.app_panel, "App")
        ll.addWidget(self.source_tabs, 1)
        splitter.addWidget(left)

        # —— 右：识别并生成 ——
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(8, 0, 0, 0)
        rl.setSpacing(6)

        self.next_hint = QLabel()
        self.next_hint.setObjectName("aiNextHint")
        self.next_hint.setWordWrap(True)
        style_muted_label(self.next_hint)
        rl.addWidget(self.next_hint)

        sec_row = QHBoxLayout()
        sec_row.setSpacing(6)
        clear_btn = QPushButton("清空")
        clear_btn.setToolTip("清空流量 / Hook / JS（保留分析结果）")
        clear_btn.clicked.connect(self._clear_capture)
        style_sidebar_aux_button(clear_btn)
        set_btn_icon(clear_btn, "clear", size=12)
        sec_row.addWidget(clear_btn)

        more_btn = QToolButton()
        more_btn.setText("更多")
        more_btn.setToolTip("Hook 分析、加载到构建器等")
        more_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        more_menu = QMenu(self)
        self._act_hook_analyze = more_menu.addAction("分析 Hook + JS", self._run_hook_analysis)
        more_menu.addSeparator()
        more_menu.addAction("加载到构建器", self._load_to_builder)
        more_menu.addAction("加载到解析器", self._load_fields_to_parser)
        more_btn.setMenu(more_menu)
        sec_row.addWidget(more_btn)
        sec_row.addStretch()
        self.api_status = QLabel()
        self.api_status.setObjectName("aiReadyChip")
        self.api_status.setCursor(Qt.CursorShape.PointingHandCursor)
        self.api_status.installEventFilter(self)
        sec_row.addWidget(self.api_status)
        self.ai_cfg_btn = QPushButton("配置")
        self.ai_cfg_btn.setToolTip("API Key、模型（首次使用必填）")
        self.ai_cfg_btn.clicked.connect(self._on_open_ai_config)
        style_sidebar_aux_button(self.ai_cfg_btn)
        set_btn_icon(self.ai_cfg_btn, "setting", size=12)
        sec_row.addWidget(self.ai_cfg_btn)
        self.adv_cfg_btn = QPushButton("高级")
        self.adv_cfg_btn.setToolTip("浏览器经解密端转发等")
        self.adv_cfg_btn.clicked.connect(self._on_open_adv_config)
        style_sidebar_aux_button(self.adv_cfg_btn)
        sec_row.addWidget(self.adv_cfg_btn)
        rl.addLayout(sec_row)

        self.result_tabs = QTabWidget()
        self.result_view = QPlainTextEdit()
        setup_code_editor(self.result_view)
        self.result_view.setReadOnly(True)
        self.result_view.setPlaceholderText("点 Agent 页「AI识别加解密 / 生成解密」后，结果会显示在这里")
        self.plugin_view = QPlainTextEdit()
        setup_code_editor(self.plugin_view)
        self.plugin_view.setReadOnly(True)
        self.plugin_view.setPlaceholderText("生成成功后的 plugin.py")
        self.flow_detail_view = QPlainTextEdit()
        setup_code_editor(self.flow_detail_view)
        self.flow_detail_view.setReadOnly(True)
        self.flow_detail_view.setPlaceholderText("在左侧点选一条流量查看请求/响应")
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(800)
        self.log_view.setPlaceholderText("运行日志")
        # Agent 为主力页
        self.result_tabs.addTab(self._build_agent_page(), "Agent")
        self.result_tabs.addTab(self.result_view, "分析结果")
        self.result_tabs.addTab(self.plugin_view, "代理脚本")
        self.result_tabs.addTab(self.flow_detail_view, "请求详情")
        self.result_tabs.addTab(self.log_view, "日志")
        rl.addWidget(self.result_tabs, 1)

        chat_row = QHBoxLayout()
        chat_row.setSpacing(6)
        self.followup_edit = QLineEdit()
        self.followup_edit.setPlaceholderText("追问补充，例如：密钥是 your-16-byte-key!")
        self.followup_edit.returnPressed.connect(self._continue_chat)
        self.continue_btn = QPushButton("发送")
        self.continue_btn.setEnabled(False)
        self.continue_btn.clicked.connect(self._continue_chat)
        style_sidebar_aux_button(self.continue_btn)
        chat_row.addWidget(self.followup_edit, 1)
        chat_row.addWidget(self.continue_btn)
        rl.addLayout(chat_row)

        splitter.addWidget(right)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 5)
        splitter.setSizes([400, 600])
        layout.addWidget(splitter, 1)
        self._update_flow_empty_hint()
        self._update_next_hint()

    def _build_agent_page(self) -> QWidget:
        """Agent 主力：识别/生成 + ReAct 对话（只读查流量/Hook/JS）."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(6)

        act = QHBoxLayout()
        act.setSpacing(6)
        self.recognize_btn = QPushButton(self._btn_labels["recognize"])
        self.recognize_btn.setToolTip("Agent 查阅流量/Hook/JS，识别加解密线索（不写 plugin）")
        self.recognize_btn.clicked.connect(self._run_recognize)
        style_button(self.recognize_btn, "accent")
        set_btn_icon(self.recognize_btn, "code", size=14)
        self.gen_decrypt_btn = QPushButton(self._btn_labels["decrypt"])
        self.gen_decrypt_btn.setToolTip("Agent 分析并写出解密端 plugin.py")
        self.gen_decrypt_btn.clicked.connect(lambda: self._run_analyze_and_generate("decrypt"))
        style_button(self.gen_decrypt_btn, "primary")
        set_btn_icon(self.gen_decrypt_btn, "decrypt", size=14)
        self.gen_encrypt_btn = QPushButton(self._btn_labels["encrypt"])
        self.gen_encrypt_btn.setToolTip("Agent 分析并写出加密端 plugin.py")
        self.gen_encrypt_btn.clicked.connect(lambda: self._run_analyze_and_generate("encrypt"))
        style_button(self.gen_encrypt_btn, "primary")
        set_btn_icon(self.gen_encrypt_btn, "encrypt", size=14)
        for btn in (self.recognize_btn, self.gen_decrypt_btn, self.gen_encrypt_btn):
            btn.setFixedHeight(30)
            btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            act.addWidget(btn, 1)
        layout.addLayout(act)

        tip = QLabel(
            "上方三按钮与下方对话均走 Agent（工具: flow / hook / script）。"
            "「生成解密/加密」结束后会解析 steps 并写 plugin。"
        )
        style_muted_label(tip)
        tip.setWordWrap(True)
        layout.addWidget(tip)

        self.agent_view = QPlainTextEdit()
        setup_code_editor(self.agent_view)
        self.agent_view.setReadOnly(True)
        self.agent_view.setPlaceholderText(
            "在下方输入目标，例如：\n"
            "· Hook 里有没有 AES Key？\n"
            "· 哪个 JS 在做 encrypt？\n"
            "· 列出含 login 的请求并推测算法"
        )
        layout.addWidget(self.agent_view, 1)

        row = QHBoxLayout()
        row.setSpacing(6)
        self.agent_edit = QLineEdit()
        self.agent_edit.setPlaceholderText("向 Agent 下达任务…")
        self.agent_edit.returnPressed.connect(self._run_agent)
        self.agent_send_btn = QPushButton("发送")
        self.agent_send_btn.clicked.connect(self._run_agent)
        style_button(self.agent_send_btn, "primary")
        self.agent_stop_btn = QPushButton("停止")
        self.agent_stop_btn.setEnabled(False)
        self.agent_stop_btn.clicked.connect(self._stop_agent)
        style_sidebar_aux_button(self.agent_stop_btn)
        row.addWidget(self.agent_edit, 1)
        row.addWidget(self.agent_send_btn)
        row.addWidget(self.agent_stop_btn)
        layout.addLayout(row)
        return page

    def _focus_agent_tab(self) -> None:
        for i in range(self.result_tabs.count()):
            if self.result_tabs.tabText(i) == "Agent":
                self.result_tabs.setCurrentIndex(i)
                break

    def _focus_result_tab(self) -> None:
        self.result_tabs.setCurrentWidget(self.result_view)

    def _agent_session(self) -> SessionData:
        return SessionData(
            flows_provider=lambda: self._flows,
            hooks_provider=lambda: self._hooks,
            scripts_provider=lambda: self._scripts,
        )

    def _run_agent(self):
        goal = self.agent_edit.text().strip()
        if not goal:
            QMessageBox.information(self, "提示", "请输入 Agent 任务")
            return
        self.agent_edit.clear()
        self._start_agent_task(goal, mode="chat")

    def _pause_capture_for_ai(self) -> None:
        """AI 请求前停掉小程序抓包，避免系统代理劫持导致 API 发不出去。"""
        panel = getattr(self, "miniprogram_panel", None)
        if panel is None:
            return
        capture = getattr(panel, "_capture", None)
        was_running = bool(capture and getattr(capture, "running", False))
        if hasattr(panel, "stop_capture_if_running"):
            panel.stop_capture_if_running()
        if was_running:
            self._log("已自动停止抓包并恢复系统代理，以便 AI API 正常出网")

    def _start_agent_task(
        self,
        goal: str,
        *,
        mode: str = "chat",
        auto_generate_role: str | None = None,
    ) -> None:
        if self._agent_worker and self._agent_worker.isRunning():
            self._log("Agent 运行中，请先停止或等待完成")
            return
        if self._analysis_worker and self._analysis_worker.isRunning():
            self._log("旧版分析仍在运行，请稍候…")
            return
        if not goal.strip():
            return
        if mode != "chat" and not self._has_capture_data():
            QMessageBox.warning(
                self, "提示",
                "请先在左侧采集：网页 / 小程序。",
            )
            return
        self._pause_capture_for_ai()
        cfg = self._get_ai_cfg()
        if not cfg:
            return

        self._auto_generate_after_analysis = bool(auto_generate_role)
        self._pending_generate_role = auto_generate_role
        self._analysis_role = auto_generate_role or "decrypt"

        self.agent_view.appendPlainText(f"\n—— 你 ——\n{goal}\n")
        self.agent_view.appendPlainText("—— Agent ——\n")
        self._focus_agent_tab()
        self._set_analysis_buttons_enabled(False)
        self.agent_stop_btn.setEnabled(True)

        self._agent_worker = AgentWorker(
            goal, self._agent_session(), cfg=cfg, mode=mode, parent=self,
        )
        self._agent_worker.log.connect(self._on_agent_log)
        self._agent_worker.finished_ok.connect(self._on_agent_ok)
        self._agent_worker.failed.connect(self._on_agent_fail)
        self._agent_worker.start()
        self._log(f"Agent 启动[{mode}]: {goal[:80]}")

    def _stop_agent(self):
        if self._agent_worker and self._agent_worker.isRunning():
            self._agent_worker.cancel()
            self._log("正在停止 Agent…")
            self.agent_view.appendPlainText("\n（请求停止…）\n")

    def _on_agent_log(self, msg: str):
        self.agent_view.appendPlainText(msg)
        self.agent_view.moveCursor(QTextCursor.MoveOperation.End)

    def _on_agent_ok(self, text: str):
        self.agent_view.appendPlainText(f"\n✅ {text}\n")
        self.agent_view.moveCursor(QTextCursor.MoveOperation.End)
        self._reset_agent_buttons()
        self._set_analysis_buttons_enabled(True)
        self._agent_worker = None
        self._log("Agent 完成")

        result = None
        try:
            parsed = _extract_json(text)
            result = _clean_steps(parsed, self._pending_generate_role or self._analysis_role or "decrypt")
        except Exception:
            result = None

        if result and (result.get("steps") or result.get("summary")):
            self._last_result = result
            try:
                formatted = json.dumps(result, ensure_ascii=False, indent=2)
                self.result_view.setPlainText(formatted)
            except Exception:
                self.result_view.setPlainText(text)
            if self._auto_generate_after_analysis:
                self._focus_result_tab()
            self._update_next_hint()

        if self._auto_generate_after_analysis:
            self._auto_generate_after_analysis = False
            gen_role = self._pending_generate_role or "decrypt"
            self._pending_generate_role = None
            if result and result.get("steps"):
                self._log("Agent 已产出步骤，正在生成脚本…")
                self._generate_plugin(silent=False, code_role=gen_role)
            else:
                self._log("Agent 完成但未解析到有效 steps，已跳过生成（可查看 Agent 原文）")
                QMessageBox.warning(
                    self, "未得到步骤",
                    "Agent 已结束，但回复里没有可用的 steps JSON。\n"
                    "可在 Agent 页追问，或检查 Hook/流量后重试「生成解密/加密」。",
                )
        elif result and result.get("steps"):
            self._log(f"识别到 {len(result['steps'])} 个步骤，可再点「生成解密/加密」落地")

    def _on_agent_fail(self, err: str):
        self.agent_view.appendPlainText(f"\n❌ {err}\n")
        self.agent_view.moveCursor(QTextCursor.MoveOperation.End)
        self._reset_agent_buttons()
        self._set_analysis_buttons_enabled(True)
        self._agent_worker = None
        self._auto_generate_after_analysis = False
        self._pending_generate_role = None
        self._log(f"Agent 失败: {err}")
        if err != "已取消":
            QMessageBox.warning(self, "Agent 失败", err)

    def _reset_agent_buttons(self):
        self.agent_send_btn.setEnabled(True)
        self.agent_stop_btn.setEnabled(False)

    def _build_browser_source(self) -> QWidget:
        """网页采集：URL + 启动 + 流量/Hook."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 2, 0, 0)
        layout.setSpacing(6)

        bar = QHBoxLayout()
        bar.setSpacing(6)
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://example.com  （回车启动）")
        self.url_edit.setMinimumHeight(28)
        self.url_edit.returnPressed.connect(self._start_browser)
        bar.addWidget(self.url_edit, 1)
        self.hook_check = QCheckBox("Hook")
        self.hook_check.setChecked(True)
        self.hook_check.setToolTip("注入 crypto_hook.js，抓 CryptoJS / RSA 等密钥")
        bar.addWidget(self.hook_check)
        self.start_btn = QPushButton("启动")
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setEnabled(False)
        self.start_btn.clicked.connect(self._start_browser)
        self.stop_btn.clicked.connect(self._stop_browser)
        style_button(self.start_btn, "primary")
        style_sidebar_aux_button(self.stop_btn)
        set_btn_icon(self.start_btn, "play", size=14)
        set_btn_icon(self.stop_btn, "stop", size=12)
        self.start_btn.setFixedHeight(28)
        self.stop_btn.setFixedHeight(28)
        self.stop_btn.setFixedWidth(56)
        bar.addWidget(self.start_btn)
        bar.addWidget(self.stop_btn)
        layout.addLayout(bar)

        capture_tabs = QTabWidget()
        flow_page = QWidget()
        fl = QVBoxLayout(flow_page)
        fl.setContentsMargins(0, 2, 0, 0)
        fl.setSpacing(2)
        self.flow_empty_hint = QLabel()
        self.flow_empty_hint.setObjectName("homeEmptyHint")
        self.flow_empty_hint.setWordWrap(True)
        fl.addWidget(self.flow_empty_hint)
        flow_bar = QHBoxLayout()
        flow_bar.setSpacing(4)
        flow_hint = QLabel("勾选后只分析选中项；不勾选则自动挑")
        style_muted_label(flow_hint)
        flow_bar.addWidget(flow_hint, 1)
        for text, slot in (
            ("全选", lambda: self._set_list_checked(self.flow_list, True)),
            ("全不选", lambda: self._set_list_checked(self.flow_list, False)),
        ):
            b = QPushButton(text)
            style_sidebar_aux_button(b)
            b.clicked.connect(slot)
            flow_bar.addWidget(b)
        fl.addLayout(flow_bar)
        self.flow_list = QListWidget()
        self.flow_list.setToolTip("勾选要送入 AI 的流量；未勾选任何项时自动挑选")
        self.flow_list.itemClicked.connect(self._on_flow_selected)
        fl.addWidget(self.flow_list, 1)
        capture_tabs.addTab(flow_page, "流量")

        hook_page = QWidget()
        hl = QVBoxLayout(hook_page)
        hl.setContentsMargins(0, 2, 0, 0)
        self.hook_view = QPlainTextEdit()
        self.hook_view.setReadOnly(True)
        self.hook_view.setMaximumBlockCount(3000)
        self.hook_view.setPlaceholderText("启动后操作页面，密钥 / 算法会出现在这里")
        hl.addWidget(self.hook_view)
        capture_tabs.addTab(hook_page, "Hook")

        js_page = QWidget()
        jl = QVBoxLayout(js_page)
        jl.setContentsMargins(0, 2, 0, 0)
        jl.setSpacing(2)
        js_bar = QHBoxLayout()
        js_bar.setSpacing(4)
        js_hint = QLabel("勾选要分析的 JS；不勾选则按相关度自动挑")
        style_muted_label(js_hint)
        js_bar.addWidget(js_hint, 1)
        for text, slot in (
            ("全选", lambda: self._set_list_checked(self.js_list, True)),
            ("全不选", lambda: self._set_list_checked(self.js_list, False)),
        ):
            b = QPushButton(text)
            style_sidebar_aux_button(b)
            b.clicked.connect(slot)
            js_bar.addWidget(b)
        jl.addLayout(js_bar)
        self.js_list = QListWidget()
        self.js_list.setToolTip("网页 / 小程序反编译代码，勾选后优先送入")
        self.js_list.itemClicked.connect(self._on_js_selected)
        jl.addWidget(self.js_list, 1)
        capture_tabs.addTab(js_page, "JS")
        layout.addWidget(capture_tabs, 1)
        return page

    @staticmethod
    def _make_check_item(text: str, data, *, checked: bool = True) -> QListWidgetItem:
        item = QListWidgetItem(text)
        item.setFlags(
            item.flags()
            | Qt.ItemFlag.ItemIsUserCheckable
            | Qt.ItemFlag.ItemIsEnabled
            | Qt.ItemFlag.ItemIsSelectable
        )
        item.setCheckState(
            Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        )
        item.setData(Qt.ItemDataRole.UserRole, data)
        return item

    @staticmethod
    def _set_list_checked(list_w: QListWidget, checked: bool) -> None:
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        for i in range(list_w.count()):
            item = list_w.item(i)
            if item is not None:
                item.setCheckState(state)

    def _checked_flow_indices(self) -> list[int]:
        out: list[int] = []
        for i in range(self.flow_list.count()):
            item = self.flow_list.item(i)
            if item and item.checkState() == Qt.CheckState.Checked:
                idx = item.data(Qt.ItemDataRole.UserRole)
                if isinstance(idx, int):
                    out.append(idx)
        return out

    def _checked_script_urls(self) -> list[str]:
        out: list[str] = []
        for i in range(self.js_list.count()):
            item = self.js_list.item(i)
            if item and item.checkState() == Qt.CheckState.Checked:
                url = item.data(Qt.ItemDataRole.UserRole)
                if url:
                    out.append(str(url))
        return out

    def _analysis_payload(self) -> tuple[list[dict], dict[str, str], bool, bool]:
        """返回 (flows, scripts, user_selected_flows, user_selected_scripts).

        - 列表为空：无素材
        - 有条目且勾选了若干：只送勾选，user_selected=True
        - 有条目但全不勾：送空列表且 user_selected=True（表示刻意不送这类）
        """
        has_flow_items = self.flow_list.count() > 0
        checked_idx = self._checked_flow_indices()
        if has_flow_items:
            flows = [self._flows[i] for i in checked_idx if 0 <= i < len(self._flows)]
            user_flows = True
        else:
            flows = list(self._flows)
            user_flows = False

        has_js_items = self.js_list.count() > 0
        checked_urls = self._checked_script_urls()
        if has_js_items:
            scripts = {
                u: self._scripts[u] for u in checked_urls if u in self._scripts
            }
            user_scripts = True
        else:
            scripts = dict(self._scripts)
            user_scripts = False
        return flows, scripts, user_flows, user_scripts

    def _refresh_js_list(self) -> None:
        if not hasattr(self, "js_list"):
            return
        prev_checked = set(self._checked_script_urls())
        had_items = self.js_list.count() > 0
        self.js_list.clear()
        for url in self._scripts:
            short = url if len(url) <= 90 else ("…" + url[-87:])
            # 新出现的默认勾选；已有列表时保留勾选状态
            checked = (url in prev_checked) if had_items else True
            if not had_items and url.startswith("miniprogram://"):
                checked = True
            self.js_list.addItem(self._make_check_item(short, url, checked=checked))

    def _on_js_selected(self, item: QListWidgetItem) -> None:
        url = item.data(Qt.ItemDataRole.UserRole) if item else None
        if not url or url not in self._scripts:
            return
        content = self._scripts[url]
        preview = content if len(content) <= 8000 else content[:8000] + "\n…(截断)"
        self.flow_detail_view.setPlainText(f"// {url}\n\n{preview}")
        self.result_tabs.setCurrentWidget(self.flow_detail_view)

    def _pick_steps_dialog(self, steps: list[dict], *, title: str = "选择要写入的步骤") -> list[dict] | None:
        """勾选分析结果中的步骤，取消返回 None."""
        if not steps:
            return []
        dlg = QDialog(self)
        dlg.setWindowTitle(title)
        dlg.setMinimumWidth(480)
        dlg.setMinimumHeight(360)
        layout = QVBoxLayout(dlg)
        hint = QLabel("取消勾选不需要的步骤，避免一键覆盖整份项目。默认全选。")
        hint.setWordWrap(True)
        style_muted_label(hint)
        layout.addWidget(hint)
        bar = QHBoxLayout()
        list_w = QListWidget()
        for i, step in enumerate(steps):
            stype = step.get("type", "?")
            params = step.get("params") or {}
            field = params.get("field") or params.get("target") or params.get("source") or ""
            algo = params.get("algo") or params.get("encode_type") or ""
            detail = " · ".join(x for x in (str(field), str(algo)) if x)
            label = f"{i + 1}. {stype}" + (f"  ({detail})" if detail else "")
            list_w.addItem(self._make_check_item(label, i, checked=True))
        for text, checked in (("全选", True), ("全不选", False)):
            b = QPushButton(text)
            style_sidebar_aux_button(b)
            b.clicked.connect(lambda _=False, c=checked: self._set_list_checked(list_w, c))
            bar.addWidget(b)
        bar.addStretch()
        layout.addLayout(bar)
        layout.addWidget(list_w, 1)
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(dlg.accept)
        btns.rejected.connect(dlg.reject)
        layout.addWidget(btns)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return None
        picked: list[dict] = []
        for i in range(list_w.count()):
            item = list_w.item(i)
            if item and item.checkState() == Qt.CheckState.Checked:
                idx = item.data(Qt.ItemDataRole.UserRole)
                if isinstance(idx, int) and 0 <= idx < len(steps):
                    picked.append(dict(steps[idx]))
        if not picked:
            QMessageBox.information(self, "提示", "请至少勾选一个步骤")
            return None
        return picked

    def _on_open_ai_config(self) -> None:
        self._open_config_dialog("ai")

    def _on_open_adv_config(self) -> None:
        self._open_config_dialog("advanced")

    def eventFilter(self, obj, event):
        from PyQt6.QtCore import QEvent
        if obj is getattr(self, "api_status", None) and event.type() == QEvent.Type.MouseButtonPress:
            self._open_config_dialog("ai")
            return True
        return super().eventFilter(obj, event)

    def _open_config_dialog(self, section: str = "ai") -> bool:
        """打开配置弹窗，保存成功返回 True."""
        dlg = AILabConfigDialog(self, initial_tab=section)
        dlg.load_from(load_ai_config())
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return False
        cfg = load_ai_config()
        updates = dlg.collect(hook_enabled=self.hook_check.isChecked())
        for key, val in updates.items():
            if key == "browser" and isinstance(cfg.get("browser"), dict):
                cfg["browser"] = {**cfg["browser"], **val}
            else:
                cfg[key] = val
        save_ai_config(cfg)
        self._load_config()
        self._log("配置已保存到 config/ai.yaml")
        self._refresh_api_status()
        return True

    def _load_config(self):
        cfg = load_ai_config()
        browser = cfg.get("browser", {})
        self.hook_check.setChecked(bool(browser.get("hook_enabled", True)))
        last_url = (browser.get("last_url") or "").strip()
        if last_url and not self.url_edit.text().strip():
            self.url_edit.setText(last_url)

    def _browser_cfg(self) -> dict:
        return load_ai_config().get("browser", {})

    def _save_config(self):
        """从当前 Hook 勾选同步 browser.hook_enabled / last_url 到配置文件."""
        cfg = load_ai_config()
        browser = cfg.get("browser", {})
        if not isinstance(browser, dict):
            browser = {}
        browser["hook_enabled"] = self.hook_check.isChecked()
        url = self.url_edit.text().strip()
        if url:
            browser["last_url"] = url
        cfg["browser"] = browser
        save_ai_config(cfg)

    def _refresh_api_status(self):
        if not hasattr(self, "api_status"):
            return
        cfg = load_ai_config()
        ok = bool(cfg.get("api_key"))
        model = (cfg.get("model") or "").strip() or "未选模型"
        if ok:
            self.api_status.setText(model)
            fg = C.get("ok", C.get("primary", "#7a9a78"))
        else:
            self.api_status.setText("未配置 API")
            fg = C.get("warn", "#b89a5a")
        self.api_status.setStyleSheet(
            f"QLabel#aiReadyChip {{ background:transparent; color:{fg};"
            f" border:none; padding:0 4px; font-size:11px; }}"
        )
        self.api_status.setToolTip(
            "已配置，可直接生成代理" if ok else "点击「AI 配置」填写 API Key"
        )

    def _has_capture_data(self) -> bool:
        return bool(self._flows or self._hooks or self._scripts)

    def _sync_action_buttons(self):
        """无素材时禁用生成按钮，并给出明确提示."""
        if self._busy:
            return
        ready = self._has_capture_data()
        for btn in (self.recognize_btn, self.gen_decrypt_btn, self.gen_encrypt_btn):
            btn.setEnabled(ready)
        self._act_hook_analyze.setEnabled(ready)
        tip = (
            "已有采集数据"
            if ready
            else "请先在左侧「网页 / 小程序」采集或反编译"
        )
        self.recognize_btn.setToolTip(f"识别加解密线索（不写文件）— {tip}")
        self.gen_decrypt_btn.setToolTip(f"写出解密端 plugin.py — {tip}")
        self.gen_encrypt_btn.setToolTip(f"写出加密端 plugin.py — {tip}")

    def _log(self, msg: str):
        self._log_buf.append(msg)
        if not self._ui_flush_timer.isActive():
            self._ui_flush_timer.start()

    def _flush_ui_buffers(self):
        if self._log_buf:
            self.log_view.appendPlainText("\n".join(self._log_buf))
            self._log_buf.clear()
        if self._hook_buf:
            self.hook_view.appendPlainText("\n".join(self._hook_buf))
            self._hook_buf.clear()
        if self._hook_buf or self._log_buf:
            return
        self._ui_flush_timer.stop()
        self._refresh_capture_stats()

    @staticmethod
    def _clean_flow(flow: dict) -> dict:
        return {k: v for k, v in flow.items() if not str(k).startswith("_")}

    def _start_browser(self):
        url = self.url_edit.text().strip()
        if not url:
            QMessageBox.warning(self, "提示", "请输入目标 URL")
            self.url_edit.setFocus()
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            self.url_edit.setText(url)
        if self._worker and self._worker.isRunning():
            QMessageBox.information(self, "提示", "浏览器已在运行")
            return
        browser = self._browser_cfg()
        self._save_config()
        self._worker = BrowserLabWorker(
            url=url,
            hook_enabled=self.hook_check.isChecked(),
            use_mitm_proxy=bool(browser.get("use_mitm_proxy", False)),
            mitm_port=int(browser.get("mitm_port", 8080)),
        )
        self._worker.log.connect(self._log)
        self._worker.flow_captured.connect(self._on_flow)
        self._worker.flow_updated.connect(self._on_flow_updated)
        self._worker.hook_line.connect(self._on_hook)
        self._worker.script_captured.connect(self._on_script)
        self._worker.stopped.connect(self._on_browser_stopped)
        self._worker.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.start_btn.setText("采集中…")
        self._update_flow_empty_hint()
        self._set_hint(
            "浏览器已启动，请在页面操作以产生流量；采到数据后即可生成代理。",
            kind="info",
        )
        self.result_tabs.setCurrentWidget(self.log_view)

    def _stop_browser(self):
        if self._worker and self._worker.isRunning():
            self._worker.stop()

    def _on_browser_stopped(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.start_btn.setText("启动")
        set_btn_icon(self.start_btn, "play", size=14)
        self._worker = None
        self._clear_session_capture()
        self._update_next_hint()

    def _on_flow(self, flow: dict):
        """浏览器采集 → 写入 _flows 并显示在「浏览器 → 流量」列表."""
        self._ingest_flow(flow, show_in_browser_list=True)

    def _on_miniprogram_flow(self, flow: dict):
        """小程序抓包 → 写入 _flows，并出现在可勾选流量列表."""
        self._ingest_flow(flow, show_in_browser_list=True, list_prefix="[小] ")

    def _ingest_flow(self, flow: dict, *, show_in_browser_list: bool, list_prefix: str = ""):
        clean = self._clean_flow(flow)
        idx = len(self._flows)
        self._flows.append(clean)
        key = flow.get("_key") or flow.get("key")
        if key is not None and str(key):
            self._flow_keys[str(key)] = idx
        if show_in_browser_list:
            pending = clean.get("status") == 0 and clean.get("response_body") == "(等待响应…)"
            prefix = list_prefix + ("… " if pending else "")
            item = self._make_check_item(
                f"{prefix}{clean.get('method')} {clean.get('url', '')[:78]}",
                idx,
                checked=True,
            )
            self.flow_list.addItem(item)
            self._update_flow_empty_hint()
        self._refresh_capture_stats()

    def _on_flow_updated(self, flow: dict):
        """浏览器流量更新（同步列表项）."""
        self._update_ingested_flow(flow, update_browser_list=True)

    def _on_miniprogram_flow_updated(self, flow: dict):
        """小程序流量更新（不碰浏览器列表）."""
        self._update_ingested_flow(flow, update_browser_list=False)

    def _update_ingested_flow(self, flow: dict, *, update_browser_list: bool):
        key = flow.get("_key") or flow.get("key")
        idx = None
        if key is not None and str(key) in self._flow_keys:
            idx = self._flow_keys[str(key)]
        else:
            idx = flow.get("_index")
        if idx is None or idx < 0 or idx >= len(self._flows):
            return
        clean = self._clean_flow(flow)
        self._flows[idx] = clean
        if update_browser_list:
            for i in range(self.flow_list.count()):
                item = self.flow_list.item(i)
                if item and item.data(Qt.ItemDataRole.UserRole) == idx:
                    item.setText(
                        f"[{clean.get('status')}] {clean.get('method')} "
                        f"{clean.get('url', '')[:75]}"
                    )
                    break
            cur = self.flow_list.currentItem()
            if cur is not None and cur.data(Qt.ItemDataRole.UserRole) == idx:
                self.flow_detail_view.setPlainText(self._format_flow_detail(clean))
        self._refresh_capture_stats()

    def _on_hook(self, line: str):
        self._hooks.append(line)
        self._hook_buf.append(line)
        if not self._ui_flush_timer.isActive():
            self._ui_flush_timer.start()

    def _on_script(self, item: dict):
        url = item.get("url", "")
        content = item.get("content", "")
        if url and content:
            self._scripts[url] = content
            self._refresh_js_list()
            self._refresh_capture_stats()

    def load_miniprogram_scripts(self, scripts: dict[str, str], meta: dict | None = None) -> None:
        """由「小程序」子页注入反编译 JS，供本页右侧 AI 分析."""
        if not scripts:
            return
        self._scripts.update(scripts)
        self._refresh_js_list()
        self._refresh_capture_stats()
        info = ""
        if meta:
            aid = meta.get("appid") or ""
            out = meta.get("out_dir") or ""
            info = f"（AppID={aid} 目录={out}）" if aid or out else ""
        self._log(f"已载入小程序反编译脚本 {len(scripts)} 个{info}")
        if hasattr(self, "hook_view"):
            self.hook_view.appendPlainText(
                f"[miniprogram] loaded {len(scripts)} scripts{info}"
            )
        self.result_tabs.setCurrentWidget(self.result_view)
        self._set_hint(
            f"已载入小程序脚本 {len(scripts)} 个。请到右侧 Agent 页「AI识别加解密」或「生成解密」。",
            kind="ready",
        )
        self._sync_action_buttons()

    def load_app_scripts(self, scripts: dict[str, str], meta: dict | None = None) -> None:
        """由「App」子页注入 APK 加解密候选代码，供 Agent 参考."""
        if not scripts:
            return
        # 替换旧的 app:// 素材，避免多次导入堆叠
        self._scripts = {
            k: v for k, v in self._scripts.items() if not str(k).startswith("app://")
        }
        self._scripts.update(scripts)
        self._refresh_js_list()
        self._refresh_capture_stats()
        info = ""
        if meta:
            pkg = meta.get("package") or ""
            out = meta.get("out_dir") or ""
            info = f"（package={pkg} 目录={out}）" if pkg or out else ""
        self._log(f"已载入 App 加解密候选 {len(scripts)} 个{info}")
        self._focus_agent_tab()
        self._set_hint(
            f"已载入 App 代码 {len(scripts)} 个。请在 Agent 页「AI识别加解密」或对话追问算法。",
            kind="ready",
        )
        self._sync_action_buttons()

    def _refresh_capture_stats(self):
        n_flow = len(self._flows)
        n_hook = len(self._hooks)
        n_js = len(self._scripts)
        if hasattr(self, "chip_flow"):
            self.chip_flow.set_count(n_flow)
            self.chip_hook.set_count(n_hook)
            self.chip_js.set_count(n_js)
        self._update_next_hint()

    def _set_hint(self, text: str, *, kind: str = "info"):
        """更新右侧引导；单行淡字，不占大块."""
        if not hasattr(self, "next_hint"):
            return
        self.next_hint.setText(text)
        colors = {
            "empty": C.get("text_dim", "#7a7c80"),
            "warn": C.get("warn", "#b89a5a"),
            "info": C.get("text_dim", "#7a7c80"),
            "ready": C.get("text", "#c8c9cb"),
            "ok": C.get("ok", "#7a9a78"),
            "busy": C.get("text_dim", "#7a7c80"),
        }
        fg = colors.get(kind, C.get("text_dim", "#7a7c80"))
        self.next_hint.setStyleSheet(
            f"QLabel#aiNextHint {{ background:transparent; color:{fg};"
            f" border:none; padding:0; font-size:11px; }}"
        )

    def _update_next_hint(self):
        if not hasattr(self, "next_hint"):
            return
        if getattr(self, "_busy", False):
            return
        has_data = self._has_capture_data()
        api_ok = bool(load_ai_config().get("api_key"))
        if self._last_plugin_code:
            self._set_hint("已生成 →「代理脚本」查看，或「更多 → 加载到构建器」", kind="ok")
        elif self._last_result:
            self._set_hint("分析完成 → Agent 页点「生成解密/加密」写出 plugin.py", kind="ready")
        elif has_data:
            parts = []
            if self._flows:
                parts.append(f"流量{len(self._flows)}")
            if self._hooks:
                parts.append(f"Hook{len(self._hooks)}")
            if self._scripts:
                parts.append(f"JS{len(self._scripts)}")
            extra = "" if api_ok else " · 先点右上角配置 API"
            self._set_hint(
                f"已采集 {'/'.join(parts)} → 在 Agent 页「AI识别」或「生成解密/加密」{extra}",
                kind="ready" if api_ok else "warn",
            )
        else:
            self._set_hint(
                "左侧采集后，到 Agent 页识别或生成代理",
                kind="empty",
            )
        self._sync_action_buttons()

    def _update_flow_empty_hint(self):
        if self._flows:
            self.flow_empty_hint.hide()
            return
        self.flow_empty_hint.show()
        if self.stop_btn.isEnabled():
            self.flow_empty_hint.setText("等待流量…在页面里登录或点几下触发请求即可。")
        else:
            self.flow_empty_hint.setText(
                "1. 填入目标 URL（可回车启动）\n"
                "2. 勾选 Hook 密钥（推荐）\n"
                "3. 点「启动采集」后在页面操作"
            )

    @staticmethod
    def _format_headers_text(hdrs: dict | None) -> str:
        if not hdrs or not isinstance(hdrs, dict):
            return "(无)"
        lines = []
        for k, v in hdrs.items():
            try:
                lines.append(f"  {k}: {v}")
            except Exception:
                lines.append(f"  {k}: ?")
        return "\n".join(lines) if lines else "(无)"

    @staticmethod
    def _safe_flow_text(val) -> str:
        if val is None:
            return ""
        if isinstance(val, (dict, list)):
            try:
                return json.dumps(val, ensure_ascii=False, indent=2)
            except Exception:
                return str(val)
        return str(val)

    def _format_flow_detail(self, f: dict) -> str:
        req_body = self._safe_flow_text(f.get("request_body", ""))[:8000]
        resp_body = self._safe_flow_text(f.get("response_body", ""))[:8000]
        return (
            f"{f.get('method')} {f.get('url')}\n\n"
            f"--- Request Headers ---\n"
            f"{self._format_headers_text(f.get('request_headers'))}\n\n"
            f"--- Request Body ---\n{req_body}\n\n"
            f"--- Response Headers ---\n"
            f"{self._format_headers_text(f.get('response_headers'))}\n\n"
            f"--- Response ({f.get('status')}) ---\n{resp_body}"
        )

    def _on_flow_selected(self, item: QListWidgetItem):
        if item is None:
            return
        try:
            idx = item.data(Qt.ItemDataRole.UserRole)
            if idx is None:
                idx = self.flow_list.row(item)
            if not isinstance(idx, int) or idx < 0 or idx >= len(self._flows):
                return
            f = self._flows[idx]
            self.flow_detail_view.setPlainText(self._format_flow_detail(f))
            self.result_tabs.setCurrentWidget(self.flow_detail_view)
        except Exception as e:
            self._log(f"显示流量详情失败: {e}")

    def _show_external_flow(self, flow: dict):
        """小程序页流量列表点选 → 右侧详情."""
        clean = self._clean_flow(flow)
        self.flow_detail_view.setPlainText(self._format_flow_detail(clean))
        self.result_tabs.setCurrentWidget(self.flow_detail_view)

    def _clear_session_capture(self):
        """关闭浏览器时清空本次捕获数据（保留 AI 分析结果与已生成脚本）."""
        self._flows.clear()
        self._flow_keys.clear()
        self._hooks.clear()
        self._scripts.clear()
        self.flow_list.clear()
        if hasattr(self, "js_list"):
            self.js_list.clear()
        self.hook_view.clear()
        self.log_view.clear()
        self._hook_buf.clear()
        self._log_buf.clear()
        self._ui_flush_timer.stop()
        panel = getattr(self, "miniprogram_panel", None)
        if panel is not None and hasattr(panel, "clear_local_flows"):
            panel.clear_local_flows()
        self._refresh_capture_stats()
        self._update_flow_empty_hint()
        self.flow_detail_view.clear()
        if not self._last_result:
            self.result_view.clear()

    def _reset_chat(self):
        self._chat_history.clear()
        self.continue_btn.setEnabled(False)
        self.followup_edit.clear()

    def _clear_capture(self):
        self._clear_session_capture()
        self._last_result = None
        self._last_plugin_code = ""
        self.result_view.clear()
        self.plugin_view.clear()
        self.flow_detail_view.clear()
        self._reset_chat()
        if self._analysis_worker and self._analysis_worker.isRunning():
            self._analysis_worker.requestInterruption()

    def _set_analysis_buttons_enabled(self, enabled: bool):
        self._busy = not enabled
        if not enabled:
            self.recognize_btn.setText("识别中…")
            self.gen_decrypt_btn.setText("分析中…")
            self.gen_encrypt_btn.setText("分析中…")
            self.recognize_btn.setEnabled(False)
            self.gen_decrypt_btn.setEnabled(False)
            self.gen_encrypt_btn.setEnabled(False)
            self._act_hook_analyze.setEnabled(False)
            self.agent_send_btn.setEnabled(False)
            self._set_hint(
                "Agent 正在分析，请稍候…过程在「Agent」页，结果也会写入「分析结果」。",
                kind="busy",
            )
        else:
            self.recognize_btn.setText(self._btn_labels["recognize"])
            self.gen_decrypt_btn.setText(self._btn_labels["decrypt"])
            self.gen_encrypt_btn.setText(self._btn_labels["encrypt"])
            set_btn_icon(self.recognize_btn, "code", size=14)
            set_btn_icon(self.gen_decrypt_btn, "decrypt", size=14)
            set_btn_icon(self.gen_encrypt_btn, "encrypt", size=14)
            self.agent_send_btn.setEnabled(True)
            self._sync_action_buttons()
            self._update_next_hint()

    def _run_analyze_and_generate(self, role: str):
        """一键：Agent 分析并生成 plugin.py."""
        goal = GENERATE_DECRYPT_GOAL if role == "decrypt" else GENERATE_ENCRYPT_GOAL
        self._start_agent_task(
            goal,
            mode="generate",
            auto_generate_role=role,
        )

    def _ask_project_options(self, code_role: str = "decrypt") -> dict | None:
        default_name = guess_project_name(self.url_edit.text().strip(), self._flows)
        match = guess_match_rules(self._flows, self.url_edit.text().strip())
        type_label = "解密脚本" if code_role == "decrypt" else "加密脚本"

        dlg = QDialog(self)
        dlg.setWindowTitle(f"生成{type_label}")
        dlg.setMinimumWidth(420)
        form = QFormLayout(dlg)
        name_edit = QLineEdit(default_name)
        name_edit.setPlaceholderText("小写字母/数字/下划线（会自动修正）")
        form.addRow("项目名称:", name_edit)
        form.addRow("脚本类型:", QLabel(type_label))
        match_label = QLabel(
            f"Host: {', '.join(match['host'])}\n"
            f"Path: {', '.join(match['path'])}\n"
            f"Methods: {', '.join(match['methods'])}"
        )
        match_label.setWordWrap(True)
        style_muted_label(match_label)
        form.addRow("匹配规则:", match_label)
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(dlg.accept)
        btns.rejected.connect(dlg.reject)
        form.addRow(btns)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return None

        return {
            "name": normalize_project_name(name_edit.text().strip()),
            "roles": [code_role],
            "match": match,
            "code_role": code_role,
        }

    def _generate_plugin(self, *, silent: bool = False, code_role: str | None = None) -> bool:
        if not self._last_result or not self._last_result.get("steps"):
            if not silent:
                QMessageBox.information(self, "提示", "请先运行 AI 分析并得到有效步骤")
            return False

        role = code_role or self._pending_generate_role or self._analysis_role or "decrypt"
        opts = self._ask_project_options(role)
        if not opts:
            return False

        steps = self._pick_steps_dialog(
            self._last_result["steps"],
            title="选择要写入项目的步骤",
        )
        if steps is None:
            return False
        body_format = detect_body_format(self._flows)
        summary = self._last_result.get("summary", "")
        confidence = self._last_result.get("confidence", "")

        if confidence == "low" and not silent:
            reply = QMessageBox.question(
                self,
                "置信度较低",
                f"AI 分析置信度为 low：\n{summary}\n\n仍要写入选中的 {len(steps)} 个步骤吗？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return False

        profile_path = os.path.join(PROFILES_DIR, f"{opts['name']}.yaml")
        overwrite = False
        if os.path.exists(profile_path):
            reply = QMessageBox.question(
                self,
                "项目已存在",
                f"项目 '{opts['name']}' 已存在，是否覆盖？\n"
                f"（将写入勾选的 {len(steps)} 个步骤）",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return False
            overwrite = True

        try:
            name, code = save_ai_project(
                opts["name"],
                steps,
                roles=opts["roles"],
                code_role=opts.get("code_role"),
                match=opts["match"],
                body_format=body_format,
                description=summary,
                flows=self._flows,
                fallback_url=self.url_edit.text().strip(),
                overwrite=overwrite,
            )
        except Exception as e:
            if not silent:
                QMessageBox.critical(self, "生成失败", str(e))
            self._log(f"生成失败: {e}")
            return False

        self._last_plugin_code = code
        self.plugin_view.setPlainText(code)
        self.result_tabs.setCurrentWidget(self.plugin_view)
        self._log(f"已生成项目: {name} → plugins/{name}/plugin.py（{len(steps)} 步）")
        self._sync_to_main_window(name, steps, code, body_format)
        type_label = "加密" if opts.get("code_role") == "encrypt" else "解密"
        self._set_hint(
            f"已生成{type_label}脚本 plugins/{name}/plugin.py（{len(steps)} 步），"
            f"控制面板已切到「{name}」，可直接启动代理。",
            kind="ok",
        )
        return True

    def _sync_to_main_window(self, name: str, steps: list, code: str, body_format: str):
        import gui as gui_mod
        main = self.window()
        gui_mod.shared_pipeline.steps = [dict(s) for s in steps]
        gui_mod.shared_pipeline.body_format = body_format
        gui_mod.shared_pipeline._plugin_code = code
        gui_mod.shared_pipeline._notify()

        if hasattr(main, "control"):
            main.control._refresh_profiles()
            main.control.profile_combo.setCurrentText(name)

        if hasattr(main, "visual_builder_tab"):
            vb = main.visual_builder_tab
            vb._clear_all()
            for step in steps:
                vb._add_step(step["type"])
            for i, step in enumerate(steps):
                if i < len(gui_mod.shared_pipeline.steps):
                    gui_mod.shared_pipeline.steps[i]["params"].update(step.get("params", {}))
            vb._rebuild_steps()
            vb.code_preview.setPlainText(code)

        if hasattr(main, "parser_tab"):
            main.parser_tab.code_preview.setPlainText(code)

        if hasattr(gui_mod, "log_signal"):
            gui_mod.log_signal.append_log.emit("INFO", f"AI 实验室已生成项目: {name}")

    def _get_ai_cfg(self) -> dict | None:
        cfg = load_ai_config()
        if not cfg.get("api_key"):
            QMessageBox.warning(self, "提示", "请先点击「AI 配置」填写 API Key")
            self._open_config_dialog("ai")
            cfg = load_ai_config()
            if not cfg.get("api_key"):
                return None
        return cfg

    def _start_analysis_worker(
        self,
        cfg: dict,
        *,
        role: str = "decrypt",
        focus_hook: bool = False,
        focus_miniprogram: bool = False,
        require_hooks: bool = False,
    ):
        if require_hooks and not self._hooks and not self._scripts:
            QMessageBox.warning(
                self, "无 Hook/JS 数据",
                "Hook 日志与 JS 均为空。\n\n"
                "1. 勾选「JS Hook」\n"
                "2. 启动浏览器后在页面执行登录（触发加密）\n"
                "3. 确认左侧 Hook 日志出现 [debug] Key …",
            )
            return

        self._pause_capture_for_ai()
        self._reset_chat()
        if focus_miniprogram:
            title = "▶ 小程序静态分析中…\n\n"
            log_title = "—— 开始小程序加解密识别 ——"
        elif focus_hook:
            title = "▶ Hook+JS 分析中…\n\n"
            log_title = f"—— 开始{'解密' if role == 'decrypt' else '加密'}脚本分析 ——"
        else:
            title = "▶ AI 分析中，实时输出如下…\n\n"
            log_title = f"—— 开始 AI 分析 ({'解密' if role == 'decrypt' else '加密'}) ——"
        self.result_view.clear()
        self.result_view.setPlainText(title)
        self._analysis_stream_pos = len(self.result_view.toPlainText())
        self._set_analysis_buttons_enabled(False)
        self.continue_btn.setEnabled(False)
        self._log(log_title)
        flows, scripts, user_flows, user_scripts = self._analysis_payload()
        if not flows and not self._hooks and not scripts:
            QMessageBox.warning(
                self, "提示",
                "当前没有可送入的素材。\n\n"
                "请先采集流量 / Hook / JS，或勾选左侧列表中的项。",
            )
            return
        sel_bits = []
        if user_flows:
            sel_bits.append(f"勾选流量 {len(flows)}")
        else:
            sel_bits.append(f"流量 {len(flows)}（自动）")
        sel_bits.append(f"Hook {len(self._hooks)}")
        if user_scripts:
            sel_bits.append(f"勾选 JS {len(scripts)}")
        else:
            sel_bits.append(f"JS {len(scripts)}（自动）")
        self._log("送入: " + " · ".join(sel_bits))

        self._analysis_role = role
        self._chat_history = build_initial_messages(
            flows,
            list(self._hooks),
            role,
            scripts=scripts,
            focus_hook=focus_hook,
            focus_miniprogram=focus_miniprogram,
            user_selected_flows=user_flows,
            user_selected_scripts=user_scripts,
        )

        self._analysis_worker = AIAnalysisWorker(
            flows,
            list(self._hooks),
            cfg,
            role=role,
            scripts=scripts,
            focus_hook=focus_hook,
            focus_miniprogram=focus_miniprogram,
            user_selected_flows=user_flows,
            user_selected_scripts=user_scripts,
        )
        self._analysis_worker.log.connect(self._log)
        self._analysis_worker.chunk.connect(self._on_analysis_chunk)
        self._analysis_worker.finished_ok.connect(self._on_analysis_done)
        self._analysis_worker.failed.connect(self._on_analysis_failed)
        self._analysis_worker.start()

    def _run_recognize(self):
        """Agent 页「AI识别加解密」."""
        panel = getattr(self, "miniprogram_panel", None)
        if panel is not None and hasattr(panel, "_emit_scripts") and panel._last_result:
            panel._emit_scripts(silent=True)
        self._start_agent_task(RECOGNIZE_GOAL, mode="recognize")

    def _run_hook_analysis(self):
        """更多菜单：偏 Hook 的 Agent 识别."""
        goal = (
            "请优先用 hook.search / hook.list 查密钥与算法，再结合 script 与 flow，"
            "输出加解密结论；末尾尽量附带 steps JSON。"
        )
        self._start_agent_task(goal, mode="recognize")

    def _run_miniprogram_ai(self):
        """兼容旧信号：走 Agent 识别."""
        panel = getattr(self, "miniprogram_panel", None)
        if panel is not None and hasattr(panel, "_emit_scripts") and panel._last_result:
            panel._emit_scripts(silent=True)
        self._start_agent_task(RECOGNIZE_GOAL, mode="recognize")

    def _continue_chat(self):
        if self._analysis_worker and self._analysis_worker.isRunning():
            self._log("AI 回复中，请稍候…")
            return
        text = self.followup_edit.text().strip()
        if not text:
            QMessageBox.information(self, "提示", "请输入追问内容")
            return
        if not self._chat_history:
            QMessageBox.information(self, "提示", "请先运行一次「AI 分析」")
            return

        self._pause_capture_for_ai()
        cfg = load_ai_config()
        if not cfg.get("api_key"):
            QMessageBox.warning(self, "提示", "请先点击「AI 配置」填写 API Key")
            self._open_config_dialog("ai")
            cfg = load_ai_config()
            if not cfg.get("api_key"):
                return

        self._chat_history.append({"role": "user", "content": text})
        self.followup_edit.clear()

        sep = "\n\n—— 追问 ——\n你: " + text + "\n\nAI: "
        self.result_view.appendPlainText(sep)
        self._analysis_stream_pos = len(self.result_view.toPlainText())
        self.result_tabs.setCurrentWidget(self.result_view)

        self._set_analysis_buttons_enabled(False)
        self.continue_btn.setEnabled(False)
        self._log(f"—— 继续对话: {text[:60]}…")

        self._analysis_worker = AIAnalysisWorker(
            messages=list(self._chat_history),
            cfg=cfg,
        )
        self._analysis_worker.log.connect(self._log)
        self._analysis_worker.chunk.connect(self._on_analysis_chunk)
        self._analysis_worker.finished_ok.connect(self._on_analysis_done)
        self._analysis_worker.failed.connect(self._on_analysis_failed)
        self._analysis_worker.start()

    def _on_analysis_chunk(self, text: str):
        cursor = self.result_view.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        cursor.insertText(text)
        self.result_view.setTextCursor(cursor)
        self.result_view.ensureCursorVisible()

    def _on_analysis_done(self, result: dict, raw_text: str):
        self._last_result = result
        role = self._analysis_role
        self._set_analysis_buttons_enabled(True)
        self.continue_btn.setEnabled(True)
        self._analysis_worker = None
        self._update_next_hint()

        if self._chat_history and self._chat_history[-1].get("role") == "user":
            self._chat_history.append({"role": "assistant", "content": raw_text})

        try:
            formatted = json.dumps(result, ensure_ascii=False, indent=2)
            if len(self._chat_history) <= 2:
                self.result_view.setPlainText(formatted)
            else:
                cursor = self.result_view.textCursor()
                cursor.setPosition(self._analysis_stream_pos)
                cursor.movePosition(cursor.MoveOperation.End, cursor.MoveMode.KeepAnchor)
                cursor.removeSelectedText()
                self.result_view.appendPlainText(formatted)
            self.result_tabs.setCurrentWidget(self.result_view)
        except Exception:
            pass

        if self._auto_generate_after_analysis:
            self._auto_generate_after_analysis = False
            gen_role = self._pending_generate_role or role
            self._pending_generate_role = None
            if result.get("steps"):
                self._log("分析完成，正在生成脚本…")
                self._generate_plugin(silent=False, code_role=gen_role)
            else:
                self._log("分析完成但无有效步骤，已跳过生成")
            return

        if not result.get("steps"):
            self._log(
                f"未生成有效步骤（{'加密' if role == 'encrypt' else '解密'}端密钥未确认）。"
                "请 Hook 抓密钥后重试「分析 Hook+JS」"
            )
        elif result.get("confidence") == "low":
            self._log("置信度较低，建议核对 Hook 日志中的 Key 后再生成脚本")

    def _on_analysis_failed(self, err: str):
        self._set_analysis_buttons_enabled(True)
        self.continue_btn.setEnabled(bool(self._chat_history))
        self._analysis_worker = None
        self._auto_generate_after_analysis = False
        self._pending_generate_role = None
        if len(self._chat_history) > 2 and self._chat_history[-1].get("role") == "user":
            self._chat_history.pop()
        self._log(f"分析失败: {err}")
        QMessageBox.critical(self, "AI 分析失败", err)

    def _load_to_builder(self):
        if not self._last_result or not self._last_result.get("steps"):
            QMessageBox.information(self, "提示", "请先运行 AI 分析并得到有效步骤")
            return
        import gui as gui_mod
        steps = self._pick_steps_dialog(
            self._last_result["steps"],
            title="选择要加载到构建器的步骤",
        )
        if steps is None:
            return
        main = self.window()
        if not hasattr(main, "visual_builder_tab"):
            return
        vb = main.visual_builder_tab
        vb._clear_all()
        for step in steps:
            vb._add_step(step["type"])
        for i, step in enumerate(steps):
            if i < len(gui_mod.shared_pipeline.steps):
                gui_mod.shared_pipeline.steps[i]["params"].update(step.get("params", {}))
        vb._rebuild_steps()
        vb._preview_code()
        if hasattr(main, "parser_tab"):
            profile = ""
            if hasattr(main, "control"):
                profile = main.control.profile_combo.currentText()
            code = codegen_for_pipeline(
                gui_mod.shared_pipeline.steps, gui_mod.shared_pipeline.body_format, profile
            )
            main.parser_tab.code_preview.setPlainText(code)
        main.tabs.setCurrentWidget(vb)
        self._log(f"已加载 {len(steps)} 个步骤到可视化构建器")

    def _selected_flow(self) -> dict | None:
        item = self.flow_list.currentItem()
        if item:
            idx = item.data(Qt.ItemDataRole.UserRole)
            if idx is not None and 0 <= idx < len(self._flows):
                return self._flows[idx]
        for f in reversed(self._flows):
            body = (f.get("response_body") or "").strip()
            if body and body not in ("(等待响应…)", "(等待响应...)"):
                return f
        return self._flows[-1] if self._flows else None

    def _load_fields_to_parser(self):
        flow = self._selected_flow()
        if not flow:
            QMessageBox.information(self, "提示", "请先采集并点选一条流量")
            return
        resp = (flow.get("response_body") or "").strip()
        if not resp or resp in ("(等待响应…)", "(等待响应...)"):
            QMessageBox.warning(
                self, "提示",
                "当前流量尚无完整响应。\n请等待左侧列表出现 [200] 后再加载，或选中已完成的那条。",
            )
            return
        main = self.window()
        if not hasattr(main, "parser_tab"):
            QMessageBox.warning(self, "提示", "未找到请求解析器 Tab")
            return
        if not main.parser_tab.load_captured_flow(flow, keep_steps=True):
            QMessageBox.warning(self, "提示", "加载失败：流量数据不完整")
            return
        main.tabs.setCurrentWidget(main.parser_tab)
        self._log(f"已加载到请求解析器: {flow.get('method')} {flow.get('url', '')[:60]}")
