"""AI 浏览器绕过 Agent — 独立窗口（实时通用 BrowserAgent + 可选离线补丁）。"""

from __future__ import annotations

import json

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QTextCursor
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
)

from core.ai_analyzer import _extract_json
from core.ai_config import normalize_browser_channel
from core.browser_agent import BrowserAgentWorker, _DEFAULT_GOAL_TPL, agent_profile_dir_for_channel
from core.icon_loader import set_btn_icon
from core.theme import C, setup_code_editor, style_button


class BotBypassDialog(QDialog):
    """独立窗口：实时浏览器 Agent 通关；可选离线 JS 补丁分析。"""

    def __init__(self, lab_tab, parent=None):
        super().__init__(parent or lab_tab)
        self._lab = lab_tab
        self._worker = None
        self._mode = "live"  # live | offline
        self._parsed: dict | None = None
        self._raw_text = ""

        self.setWindowTitle("AI 浏览器绕过 Agent")
        self.setWindowFlag(Qt.WindowType.Window, True)
        self.setMinimumSize(820, 580)
        self.resize(940, 680)
        # 与主界面同色，避免弹窗默认底把输入框衬得发灰/发蓝
        self.setStyleSheet(
            f"QDialog {{ background:{C.get('surface')}; color:{C.get('text')}; }}"
        )

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        url_row = QHBoxLayout()
        url_row.setSpacing(6)
        url_lab = QLabel("目标 URL")
        url_lab.setStyleSheet(f"color:{C.get('text_dim')};")
        url_row.addWidget(url_lab)
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://example.com")
        self.url_edit.setObjectName("bypassUrlEdit")
        self.url_edit.setMinimumHeight(28)
        self.url_edit.setMaximumHeight(28)
        # 与主界面普通输入框一致（勿用 monoField/code_bg，会衬成另一块底色）
        self.url_edit.setStyleSheet(
            f"QLineEdit#bypassUrlEdit {{"
            f"background:{C.get('input_bg')};color:{C.get('text')};"
            f"border:1px solid {C.get('border')};border-radius:6px;"
            f"padding:4px 8px;selection-background-color:{C.get('selection')};"
            f"}}"
            f"QLineEdit#bypassUrlEdit:focus {{"
            f"border:1px solid {C.get('focus')};background:{C.get('input_focus_bg')};"
            f"}}"
        )
        url = ""
        if hasattr(lab_tab, "url_edit"):
            url = (lab_tab.url_edit.text() or "").strip()
        self.url_edit.setText(url)
        url_row.addWidget(self.url_edit, 1)
        root.addLayout(url_row)

        opt_row = QHBoxLayout()
        opt_row.setSpacing(10)
        opt_row.setContentsMargins(0, 0, 0, 0)
        # 选项弱化：小字 + 灰色，不抢主操作
        _opt_qss = (
            f"QCheckBox {{ color:{C.get('text_dim')}; font-size:11px; spacing:4px; }}"
            f"QCheckBox::indicator {{ width:12px; height:12px; }}"
        )
        self.headless_check = QCheckBox("无头")
        self.headless_check.setStyleSheet(_opt_qss)
        self.headless_check.setToolTip("无头看不到页面，无法手动点验证码；默认关闭")
        opt_row.addWidget(self.headless_check)
        self.stealth_check = QCheckBox("拟真环境")
        self.stealth_check.setStyleSheet(_opt_qss)
        self.stealth_check.setChecked(True)
        self.stealth_check.setToolTip(
            "初始是否拟真。通关中 AI 可用 browser_restart.reconfigure 自行开关"
            "（关拟真≈真实浏览器）"
        )
        opt_row.addWidget(self.stealth_check)
        self.mitm_check = QCheckBox("走解密代理")
        self.mitm_check.setStyleSheet(_opt_qss)
        self.mitm_check.setToolTip(
            "初始是否走解密端。卡住时 AI 也可通过 reconfigure 改 proxy"
        )
        opt_row.addWidget(self.mitm_check)
        self.sweep_check = QCheckBox("全量策略扫描")
        self.sweep_check.setStyleSheet(_opt_qss)
        self.sweep_check.setChecked(True)
        self.sweep_check.setToolTip(
            "按矩阵挨个测试：拟真开/关、反DevTools中和、换 Chrome/Edge、CDP、"
            "清档案、档案预热、直连/代理等。\n"
            "出现明确 pass 即提前结束（不跑完剩余组，也不再开 Agent）；"
            "仅 soft_pass 时才短跑 Agent 细测。"
            "关闭则仍为原来的「观测驱动」通关。"
        )
        opt_row.addWidget(self.sweep_check)
        opt_row.addStretch(1)
        root.addLayout(opt_row)

        self.status_label = QLabel("就绪")
        self.status_label.setWordWrap(False)
        self._apply_status_style(kind="idle")
        root.addWidget(self.status_label)

        self.log_view = QPlainTextEdit()
        setup_code_editor(self.log_view)
        self.log_view.setReadOnly(True)
        self.log_view.setPlaceholderText("Agent 过程会显示在这里…")
        self.log_view.setMinimumHeight(160)
        root.addWidget(self.log_view, 2)

        tabs = QTabWidget()
        self.summary_view = QPlainTextEdit()
        setup_code_editor(self.summary_view)
        self.summary_view.setReadOnly(True)
        self.summary_view.setPlaceholderText("结论摘要…")
        tabs.addTab(self.summary_view, "结论")

        self.json_view = QPlainTextEdit()
        setup_code_editor(self.json_view)
        self.json_view.setReadOnly(True)
        self.json_view.setPlaceholderText("完整 JSON…")
        tabs.addTab(self.json_view, "JSON")

        self.hook_view = QPlainTextEdit()
        setup_code_editor(self.hook_view)
        self.hook_view.setReadOnly(True)
        self.hook_view.setPlaceholderText("离线补丁分析才会生成 hook_js…")
        tabs.addTab(self.hook_view, "hook_js")
        root.addWidget(tabs, 3)

        follow = QHBoxLayout()
        follow.setSpacing(6)
        self.follow_edit = QLineEdit()
        self.follow_edit.setObjectName("bypassFollowEdit")
        self.follow_edit.setMinimumHeight(28)
        self.follow_edit.setMaximumHeight(28)
        self.follow_edit.setStyleSheet(
            f"QLineEdit#bypassFollowEdit {{"
            f"background:{C.get('input_bg')};color:{C.get('text')};"
            f"border:1px solid {C.get('border')};border-radius:6px;"
            f"padding:4px 8px;selection-background-color:{C.get('selection')};"
            f"}}"
            f"QLineEdit#bypassFollowEdit:focus {{"
            f"border:1px solid {C.get('focus')};background:{C.get('input_focus_bg')};"
            f"}}"
        )
        self.follow_edit.setPlaceholderText(
            "追问 / 自定义目标，例如：打开该页并等到主内容可见…"
        )
        self.follow_edit.returnPressed.connect(self._on_follow_send)
        follow.addWidget(self.follow_edit, 1)
        self.follow_btn = QPushButton("追问")
        style_button(self.follow_btn, "ghost", size="sm")
        self.follow_btn.clicked.connect(self._on_follow_send)
        follow.addWidget(self.follow_btn)
        root.addLayout(follow)

        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.start_btn = QPushButton("开始通关")
        style_button(self.start_btn, "primary", size="sm")
        set_btn_icon(self.start_btn, "browser", size=12)
        self.start_btn.setToolTip(
            "有头浏览器实时通关。勾选「全量策略扫描」时会先挨个测启动参数再验证。"
        )
        self.start_btn.clicked.connect(lambda: self.start_live())
        bar.addWidget(self.start_btn)

        self.sweep_only_btn = QPushButton("只扫策略")
        style_button(self.sweep_only_btn, "ghost", size="sm")
        self.sweep_only_btn.setToolTip(
            "只跑全量策略矩阵（拟真/真实/反DT/换通道/清档案/预热/直连），"
            "不做后续 Agent 通关；结果在结论/JSON。"
        )
        self.sweep_only_btn.clicked.connect(self.start_sweep_only)
        bar.addWidget(self.sweep_only_btn)

        self.offline_btn = QPushButton("离线补丁")
        style_button(self.offline_btn, "ghost", size="sm")
        self.offline_btn.setToolTip("不打开浏览器，用已采 JS/流量生成 hook_js（旧模式）")
        self.offline_btn.clicked.connect(self.start_offline)
        bar.addWidget(self.offline_btn)

        self.stop_btn = QPushButton("停止")
        style_button(self.stop_btn, "ghost", size="sm")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_analysis)
        bar.addWidget(self.stop_btn)

        bar.addStretch(1)

        self.apply_btn = QPushButton("应用方案")
        style_button(self.apply_btn, "accent", size="sm")
        self.apply_btn.setEnabled(False)
        self.apply_btn.setToolTip(
            "写入浏览器选项 + hook_js（离线补丁；实时通关成功后也会自动同步）"
        )
        self.apply_btn.clicked.connect(self._on_apply)
        bar.addWidget(self.apply_btn)

        close_btn = QPushButton("关闭")
        style_button(close_btn, "ghost", size="sm")
        close_btn.clicked.connect(self.close)
        bar.addWidget(close_btn)
        root.addLayout(bar)

    def _lab_channel(self) -> str:
        lab = self._lab
        if hasattr(lab, "_act_ch_chrome") and lab._act_ch_chrome.isChecked():
            return "chrome"
        browser = lab._browser_cfg() if hasattr(lab, "_browser_cfg") else {}
        return normalize_browser_channel(browser.get("browser_channel"))

    def _browser_proxy(self) -> str | None:
        if not self.mitm_check.isChecked():
            return None
        lab = self._lab
        port = 8083
        try:
            gui = lab.window() if hasattr(lab, "window") else None
            if gui is not None and hasattr(gui, "decrypt_port_spin"):
                port = int(gui.decrypt_port_spin.value())
        except Exception:
            pass
        return f"http://127.0.0.1:{port}"

    # ── live ────────────────────────────────────────────

    def start_live(self, goal: str | None = None) -> None:
        if self._worker and self._worker.isRunning():
            self._append_log("已在运行中…")
            return
        lab = self._lab
        url = (self.url_edit.text() or "").strip()
        if not url:
            QMessageBox.information(self, "提示", "请先填写目标 URL")
            return
        cfg = lab._get_ai_cfg()
        if not cfg:
            return
        if lab._agent_worker and lab._agent_worker.isRunning():
            QMessageBox.warning(self, "提示", "主界面 Agent 正在运行，请先停止。")
            return
        if hasattr(lab, "is_lab_browser_running") and lab.is_lab_browser_running():
            reply = QMessageBox.question(
                self,
                "实验室浏览器占用中",
                "实验室浏览器正在运行。\n"
                "绕过 Agent 使用独立档案，可并行；但若要共用 Cookie，请先停止实验室浏览器。\n\n"
                "仍要继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        # 同步 URL 回实验室输入框
        if hasattr(lab, "url_edit") and url:
            lab.url_edit.setText(url)

        lab._pause_capture_for_ai()
        self._mode = "live"
        self._parsed = None
        self._raw_text = ""
        self.apply_btn.setEnabled(False)
        self.summary_view.clear()
        self.json_view.clear()
        self.hook_view.clear()

        do_sweep = bool(getattr(self, "sweep_check", None) and self.sweep_check.isChecked())
        text_goal = (goal or "").strip() or _DEFAULT_GOAL_TPL.format(url=url)
        mode_tip = "全量策略扫描 + 通关" if do_sweep else "通关"
        self._append_log(f"\n—— 开始{mode_tip} ——\nURL: {url}\n{text_goal[:240]}\n")
        self._set_status(
            "策略扫描中…" if do_sweep else "通关中…（有头浏览器会弹出）",
            busy=True,
        )
        self._set_busy(True)

        ch = self._lab_channel()
        # 与实验室「反调试」勾选同步：开则中和反 DevTools
        anti_on = bool(
            getattr(lab, "_act_anti", None) and lab._act_anti.isChecked()
        )
        extra = (
            "【密桥实验室可选启动策略 — 由你决策，勿死磕默认】\n"
            "窗口勾选只是初始值。若页面疑似风控/挑战/空白，请用 "
            "browser_restart.reconfigure 主动换策略，例如：\n"
            "1) use_stealth=false：接近「真实浏览器」，关闭拟真注入"
            "（瑞数等强 JS 挑战/脚本完整性站常用；与「指纹扫描站」相反）\n"
            "2) use_stealth=true + browser_channel=chrome：通用拟真"
            "（含 CDP console / SwiftShader WebGL）+ 本机 Chrome；测指纹/Bot 用这个\n"
            "3) cdp_attach=true + browser_channel=msedge|chrome：系统浏览器+CDP"
            "（OS 起 Edge/Chrome 再 attach，无拟真；真实浏览器仍失败时优先试；"
            "与实验室「系统浏览器 + CDP」同款）\n"
            "4) fresh_profile=true：清空 Cookie/档案再试\n"
            "5) headless=false：有验证码必须有头\n"
            "6) proxy 设为空：取消解密代理直连；或设 http://127.0.0.1:端口 走代理\n"
            "7) neutralize_devtools=true：中和反 DevTools（闪一下变空白时打开；"
            "与实验室「反调试」勾选一致，也可在此重开）\n"
            "连续同策略失败 2～3 次必须换一组参数。观测结果里的 launch 字段即当前配置。\n"
            "最终 JSON 必须含 reason：reached=true 时写「为什么过了」；"
            "false 时写「为什么过不了」（对照观测与已试策略），禁止空原因。"
        )
        self._worker = BrowserAgentWorker(
            goal=text_goal,
            url=url,
            cfg=cfg,
            headless=self.headless_check.isChecked(),
            browser_channel=ch,
            use_stealth=self.stealth_check.isChecked(),
            browser_proxy=self._browser_proxy(),
            profile_dir=agent_profile_dir_for_channel(ch),
            extra_context=extra,
            neutralize_devtools=anti_on,
            strategy_sweep=do_sweep,
            sweep_then_agent=True,
            parent=self,
        )
        self._worker.log.connect(self._on_log)
        self._worker.finished_ok.connect(self._on_ok)
        self._worker.failed.connect(self._on_fail)
        self._worker.start()
        lab._log(
            f"浏览器绕过 Agent 启动: {url}"
            + (" · 全量策略扫描" if do_sweep else "")
            + ("（已开反 DevTools 中和）" if anti_on else "")
        )

    def start_sweep_only(self) -> None:
        """只跑策略矩阵，不做 Agent 通关。"""
        if hasattr(self, "sweep_check"):
            self.sweep_check.setChecked(True)
        # 复用 start_live 流程，但关掉后续 Agent
        if self._worker and self._worker.isRunning():
            self._append_log("已在运行中…")
            return
        lab = self._lab
        url = (self.url_edit.text() or "").strip()
        if not url:
            QMessageBox.information(self, "提示", "请先填写目标 URL")
            return
        cfg = lab._get_ai_cfg()
        if not cfg:
            return
        if lab._agent_worker and lab._agent_worker.isRunning():
            QMessageBox.warning(self, "提示", "主界面 Agent 正在运行，请先停止。")
            return

        if hasattr(lab, "url_edit") and url:
            lab.url_edit.setText(url)
        lab._pause_capture_for_ai()
        self._mode = "live"
        self._parsed = None
        self._raw_text = ""
        self.apply_btn.setEnabled(False)
        self.summary_view.clear()
        self.json_view.clear()
        self.hook_view.clear()
        self._append_log(f"\n—— 只扫策略（全量矩阵）——\nURL: {url}\n")
        self._set_status("全量策略扫描中…", busy=True)
        self._set_busy(True)

        ch = self._lab_channel()
        anti_on = bool(
            getattr(lab, "_act_anti", None) and lab._act_anti.isChecked()
        )
        self._worker = BrowserAgentWorker(
            goal=f"全量策略扫描: {url}",
            url=url,
            cfg=cfg,
            headless=self.headless_check.isChecked(),
            browser_channel=ch,
            use_stealth=self.stealth_check.isChecked(),
            browser_proxy=self._browser_proxy(),
            profile_dir=agent_profile_dir_for_channel(ch),
            extra_context="",
            neutralize_devtools=anti_on,
            strategy_sweep=True,
            sweep_then_agent=False,
            parent=self,
        )
        self._worker.log.connect(self._on_log)
        self._worker.finished_ok.connect(self._on_ok)
        self._worker.failed.connect(self._on_fail)
        self._worker.start()
        lab._log(f"全量策略扫描启动: {url}")

    def start_offline(self) -> None:
        """旧模式：离线分析已采 JS → hook_js。"""
        if self._worker and self._worker.isRunning():
            self._append_log("已在运行中…")
            return
        lab = self._lab
        if not lab._scripts and not lab._flows and not lab._hooks:
            QMessageBox.information(
                self,
                "提示",
                "离线补丁需要先采到流量或 JS。\n"
                "可先用「开始通关」实时过检，或实验室「启动」采集后再点。",
            )
            return
        cfg = lab._get_ai_cfg()
        if not cfg:
            return
        if lab._agent_worker and lab._agent_worker.isRunning():
            QMessageBox.warning(self, "提示", "主界面 Agent 正在运行，请先停止。")
            return

        from core.agent_runner import AgentWorker, BOT_BYPASS_GOAL

        lab._pause_capture_for_ai()
        self._mode = "offline"
        self._parsed = None
        self._raw_text = ""
        self.apply_btn.setEnabled(False)
        self.summary_view.clear()
        self.json_view.clear()
        self.hook_view.clear()
        self._append_log("\n—— 离线补丁分析 ——\n")
        self._set_status("离线分析中…", busy=True)
        self._set_busy(True)

        self._worker = AgentWorker(
            BOT_BYPASS_GOAL,
            lab._agent_session(),
            cfg=cfg,
            mode="bot_bypass",
            parent=self,
        )
        self._worker.log.connect(self._on_log)
        self._worker.finished_ok.connect(self._on_ok)
        self._worker.failed.connect(self._on_fail)
        self._worker.start()
        lab._log("AI绕过窗口：离线补丁分析")

    def stop_analysis(self) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._append_log("\n（正在停止…）\n")
            self.stop_btn.setText("停止中…")
            self.stop_btn.setEnabled(False)
            self._set_status("停止中…", busy=True)

    # ── slots ───────────────────────────────────────────

    def _on_follow_send(self) -> None:
        goal = self.follow_edit.text().strip()
        if not goal:
            return
        self.follow_edit.clear()
        url = (self.url_edit.text() or "").strip()
        if url and url not in goal:
            goal = f"{goal}\n目标地址: {url}"
        self.start_live(goal)

    def _on_log(self, msg: str) -> None:
        self._append_log(msg)

    def _on_ok(self, text: str) -> None:
        self._raw_text = text or ""
        last_launch: dict = {}
        if self._worker is not None:
            last_launch = dict(getattr(self._worker, "last_launch", None) or {})
        self._append_log("\n✅ 完成\n")
        if last_launch:
            self._append_log(
                "最终启动策略: "
                + f"拟真={last_launch.get('use_stealth')} · "
                + f"通道={last_launch.get('browser_channel')} · "
                + f"无头={last_launch.get('headless')} · "
                + f"模式={last_launch.get('mode')} · "
                + f"CDP={last_launch.get('cdp_attach')} · "
                + f"反DevTools中和={last_launch.get('neutralize_devtools')}\n"
            )
        self._set_busy(False)
        self._worker = None
        self._lab._log(
            "浏览器绕过 Agent 完成"
            if self._mode == "live"
            else "离线补丁分析完成"
        )

        parsed = None
        try:
            parsed = _extract_json(text)
        except Exception:
            parsed = None

        if not isinstance(parsed, dict):
            self._parsed = None
            self.summary_view.setPlainText(text or "(无内容)")
            self.json_view.setPlainText(text or "")
            self.hook_view.clear()
            self._set_status("完成（未解析到 JSON）", busy=False)
            self.apply_btn.setEnabled(False)
            # 即便无 JSON，实时通关仍可按最后启动策略回写勾选
            if self._mode == "live" and last_launch:
                self._sync_dialog_from_launch(last_launch)
            return

        self._parsed = parsed
        if last_launch and "launch" not in parsed:
            parsed = dict(parsed)
            parsed["launch"] = last_launch
            self._parsed = parsed
        self._show_parsed(parsed)
        can_apply = bool(parsed.get("browser_opts") or parsed.get("hook_js"))
        self.apply_btn.setEnabled(can_apply)
        reached = parsed.get("reached")
        # 状态栏只显示短句；完整说明在「结论」页
        reason = str(parsed.get("reason") or "").strip()
        label = self._status_strategy_label(parsed, reason)
        if reached is True:
            self._set_status(
                f"通关成功 · {label}" if label else "通关成功",
                busy=False,
            )
            if self._mode == "live":
                self._after_live_clearance(last_launch=last_launch)
        elif reached is False:
            self._set_status(
                f"未通关 · {label}" if label else "未通关",
                busy=False,
            )
            if self._mode == "live" and last_launch:
                self._sync_dialog_from_launch(last_launch)
        else:
            self._set_status(label or "分析完成", busy=False)
        try:
            self._lab.result_view.setPlainText(
                json.dumps(parsed, ensure_ascii=False, indent=2)
            )
        except Exception:
            pass

    def _sync_dialog_from_launch(self, launch: dict) -> None:
        """把 AI 最后选用的启动策略回写到通关窗口勾选。"""
        if not isinstance(launch, dict) or not launch:
            return
        if "use_stealth" in launch:
            self.stealth_check.setChecked(bool(launch.get("use_stealth")))
        if "headless" in launch:
            self.headless_check.setChecked(bool(launch.get("headless")))
        proxy = str(launch.get("proxy") or "").strip()
        self.mitm_check.setChecked(bool(proxy))
        ch = str(launch.get("browser_channel") or "").strip().lower()
        lab = self._lab
        if ch in ("chrome", "chromium", "msedge"):
            if hasattr(lab, "_set_browser_channel_ui"):
                try:
                    lab._set_browser_channel_ui(ch, persist=True)
                except Exception:
                    pass
            elif hasattr(lab, "_on_browser_channel_changed"):
                try:
                    lab._on_browser_channel_changed(ch)
                except Exception:
                    pass
        # 反 DevTools 中和 ↔ 实验室「反调试」
        if "neutralize_devtools" in launch and hasattr(lab, "_act_anti"):
            try:
                lab._act_anti.setChecked(bool(launch.get("neutralize_devtools")))
            except Exception:
                pass
        # 系统浏览器 + CDP ↔ 实验室同款开关
        if "cdp_attach" in launch and hasattr(lab, "_apply_cdp_browser"):
            try:
                if launch.get("cdp_attach"):
                    prefer = ch if ch in ("msedge", "chrome") else "msedge"
                    lab._apply_cdp_browser(prefer, persist=True)
                    self.stealth_check.setChecked(False)
                elif hasattr(lab, "_is_cdp_attach") and lab._is_cdp_attach():
                    lab._apply_cdp_browser("", persist=True)
            except Exception as e:
                self._append_log(f"回写 CDP 模式失败: {e}\n")
        self._append_log(
            f"已回写窗口勾选 ← AI 策略 use_stealth={launch.get('use_stealth')} "
            f"channel={launch.get('browser_channel')} headless={launch.get('headless')} "
            f"CDP={launch.get('cdp_attach')} "
            f"反DevTools中和={launch.get('neutralize_devtools')}\n"
        )

    def _after_live_clearance(self, *, last_launch: dict | None = None) -> None:
        """实时通关成功：同步拟真/选项，有 hook 则写入，再询问是否启动实验室浏览器。"""
        lab = self._lab
        parsed = dict(self._parsed or {})
        url = (self.url_edit.text() or "").strip()
        if url and hasattr(lab, "url_edit"):
            lab.url_edit.setText(url)

        launch = last_launch if isinstance(last_launch, dict) else {}
        if not launch and isinstance(parsed.get("launch"), dict):
            launch = dict(parsed.get("launch") or {})
        if launch:
            self._sync_dialog_from_launch(launch)

        opts = parsed.get("browser_opts") if isinstance(parsed.get("browser_opts"), dict) else {}
        opts = dict(opts)
        # 优先用 AI 最终策略，其次窗口勾选
        if "use_stealth" in launch:
            opts["prefer_stealth"] = bool(launch.get("use_stealth"))
        else:
            opts["prefer_stealth"] = bool(self.stealth_check.isChecked())
        ch = str(launch.get("browser_channel") or "").strip().lower()
        if ch in ("chrome", "chromium", "msedge"):
            opts["browser_channel"] = ch
        else:
            opts.setdefault("browser_channel", self._lab_channel())
        opts.setdefault("record_mode", True)
        # 反 DevTools 中和 ↔「反调试」勾选（通关成功后写回实验室）
        if "neutralize_devtools" in launch and hasattr(lab, "_act_anti"):
            try:
                on = bool(launch.get("neutralize_devtools"))
                lab._act_anti.setChecked(on)
                opts["anti_debug"] = on
                self._append_log(
                    f"AI neutralize_devtools={on} → 已同步实验室「反调试」\n"
                )
            except Exception:
                pass
        # CDP 优先于「真实浏览器」；否则关掉拟真 ≈ 实验室真实浏览器
        want_cdp = bool(launch.get("cdp_attach") or opts.get("cdp_attach"))
        if want_cdp and hasattr(lab, "_apply_cdp_browser"):
            try:
                prefer = ch if ch in ("msedge", "chrome") else "msedge"
                if opts.get("cdp_browser") in ("msedge", "chrome"):
                    prefer = str(opts.get("cdp_browser"))
                lab._apply_cdp_browser(prefer, persist=True)
                opts["prefer_stealth"] = False
                opts["cdp_attach"] = True
                opts["cdp_browser"] = prefer
                self._append_log(
                    f"AI 最终 cdp_attach=true → 已切实验室「系统浏览器 + CDP · {prefer}」\n"
                )
            except Exception as e:
                self._append_log(f"切换 CDP 失败: {e}\n")
        elif opts.get("prefer_stealth") is False and hasattr(lab, "_set_proxy_only"):
            try:
                if hasattr(lab, "_is_cdp_attach") and lab._is_cdp_attach():
                    lab._apply_cdp_browser("", persist=True)
                lab._set_proxy_only(True, persist=True)
                self._append_log("AI 最终 use_stealth=false → 已切实验室「真实浏览器」\n")
            except Exception:
                pass
        elif opts.get("prefer_stealth") and hasattr(lab, "_set_proxy_only"):
            try:
                if hasattr(lab, "_is_cdp_attach") and lab._is_cdp_attach():
                    lab._apply_cdp_browser("", persist=True)
                if lab._is_real_browser():
                    lab._set_proxy_only(False, persist=True)
            except Exception:
                pass
        parsed["browser_opts"] = opts

        hook_js = str(parsed.get("hook_js") or "").strip()
        # 同步实验室：有 hook 则写入（不自动重启）；拟真模式才开 Hook 通道
        try:
            if opts.get("prefer_stealth") is not False:
                if hasattr(lab, "_ensure_stealth_mode_for_bypass"):
                    lab._ensure_stealth_mode_for_bypass(ask=False)
            if hook_js or opts:
                # 真实浏览器模式下不要强行用 apply 打开暴力猴；仅写 opts
                if opts.get("prefer_stealth") is False and not hook_js:
                    if hasattr(lab, "_save_config"):
                        lab._save_config()
                else:
                    lab.apply_bot_bypass_result(parsed, parent=self, auto_restart=False)
            elif hasattr(lab, "_prepare_bypass_browser_opts"):
                lab._prepare_bypass_browser_opts(opts)
                if hasattr(lab, "_save_config"):
                    lab._save_config()
        except Exception as e:
            self._append_log(f"\n同步实验室选项失败: {e}\n")
            lab._log(f"通关后同步实验室失败: {e}")

        # 同步「走解密代理」偏好（启动时若端口未开仍会直连）
        try:
            from core.ai_config import load_ai_config, save_ai_config

            cfg = load_ai_config()
            browser = cfg.get("browser") if isinstance(cfg.get("browser"), dict) else {}
            browser = dict(browser)
            want_mitm = bool(self.mitm_check.isChecked())
            if launch and "proxy" in launch:
                want_mitm = bool(str(launch.get("proxy") or "").strip())
            browser["use_mitm_proxy"] = want_mitm
            if "neutralize_devtools" in launch:
                browser["anti_debug"] = bool(launch.get("neutralize_devtools"))
            elif hasattr(lab, "_act_anti"):
                browser["anti_debug"] = bool(lab._act_anti.isChecked())
            if url:
                browser["last_url"] = url
            if ch in ("chrome", "chromium", "msedge"):
                browser["browser_channel"] = ch
            if want_cdp:
                prefer = ch if ch in ("msedge", "chrome") else "msedge"
                if opts.get("cdp_browser") in ("msedge", "chrome"):
                    prefer = str(opts.get("cdp_browser"))
                browser["cdp_attach"] = True
                browser["cdp_browser"] = prefer
                browser["real_browser"] = False
                browser["proxy_only"] = False
            elif "cdp_attach" in launch:
                browser["cdp_attach"] = False
            cfg["browser"] = browser
            save_ai_config(cfg)
        except Exception:
            pass

        msg = "通关成功。\n\n"
        launch_line = self._human_launch_line(launch)
        if launch_line:
            msg += f"· 已把实验室浏览器切到：{launch_line}\n"
        else:
            msg += "· 已把当前通关用的浏览器选项同步到实验室\n"
        reason = str(parsed.get("reason") or "").strip()
        if reason:
            # 弹窗里给短句，完整说明在「结论」页
            short_reason = reason if len(reason) <= 160 else reason[:160] + "…"
            msg += f"· {short_reason}\n"
        if hook_js:
            msg += f"· 已写入 Hook 脚本（约 {len(hook_js)} 字），并打开密桥 Hook\n"
        else:
            msg += "· 本次没有生成 Hook 脚本，只同步了浏览器选项\n"
        if self.mitm_check.isChecked():
            msg += "· 启动时会尝试走解密代理（需解密端已开）\n"
        msg += "\n是否现在启动实验室浏览器，继续采集加密流量？"

        reply = QMessageBox.question(
            self,
            "启动实验室浏览器？",
            msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if reply != QMessageBox.StandardButton.Yes:
            self._set_status("通关成功 · 已同步选项（未启动浏览器）", busy=False)
            lab._log("通关成功：已同步实验室选项，用户选择稍后启动")
            return

        try:
            enable_vm = bool(hook_js) and opts.get("prefer_stealth") is not False
            if lab.is_lab_browser_running():
                if hasattr(lab, "_schedule_lab_browser_restart"):
                    lab._schedule_lab_browser_restart(
                        "通关成功后启动实验室浏览器",
                        enable_vm=enable_vm,
                    )
                else:
                    lab._stop_browser()
                    lab._start_browser()
            else:
                lab._start_browser()
            self._set_status("通关成功 · 正在启动实验室浏览器…", busy=False)
            lab._log("通关成功：用户确认 → 启动实验室浏览器")
        except Exception as e:
            QMessageBox.warning(self, "启动失败", str(e))
            lab._log(f"通关后启动实验室浏览器失败: {e}")

    def _on_fail(self, err: str) -> None:
        self._append_log(f"\n❌ {err}\n")
        self._set_busy(False)
        self._worker = None
        self._set_status(f"失败: {err}", busy=False)
        self._lab._log(f"浏览器绕过 Agent 失败: {err}")
        if err != "已取消":
            QMessageBox.warning(self, "失败", err)

    def _on_apply(self) -> None:
        if not self._parsed:
            QMessageBox.information(self, "提示", "还没有可应用的离线方案")
            return
        ok = self._lab.apply_bot_bypass_result(self._parsed, parent=self)
        if ok:
            self._set_status("方案已应用，正在自动重启浏览器…", busy=False)

    # ── helpers ─────────────────────────────────────────

    @staticmethod
    def _verdict_zh(verdict: str) -> str:
        return {
            "pass": "通过",
            "soft_pass": "勉强可用",
            "fail": "失败",
            "error": "出错",
        }.get((verdict or "").strip().lower(), (verdict or "未知").strip() or "未知")

    @classmethod
    def _human_launch_line(cls, launch: dict | None) -> str:
        if not isinstance(launch, dict) or not launch:
            return ""
        bits: list[str] = []
        if launch.get("cdp_attach"):
            ch = str(launch.get("browser_channel") or "msedge").lower()
            ch_zh = {"msedge": "Edge", "chrome": "Chrome"}.get(ch, ch)
            bits.append(f"系统浏览器 + CDP（{ch_zh}）")
        elif launch.get("use_stealth") is False:
            bits.append("真实浏览器")
        else:
            label = str(launch.get("label") or "").strip()
            mode = str(launch.get("mode") or "").strip().lower()
            if label:
                bits.append(label)
            elif "stealth" in mode or "拟真" in mode or not mode:
                bits.append("拟真注入（Chromium 内置）")
            else:
                bits.append(mode or "拟真浏览器")
            ch = str(launch.get("browser_channel") or "").strip().lower()
            if ch and ch not in ("", "chromium"):
                ch_zh = {"msedge": "Edge", "chrome": "Chrome", "chromium": "Chromium"}.get(
                    ch, ch
                )
                bits.append(f"通道 {ch_zh}")
        if "neutralize_devtools" in launch:
            bits.append(
                "反调试中和·开" if launch.get("neutralize_devtools") else "反调试中和·关"
            )
        return " · ".join(bits)

    @classmethod
    def _human_browser_opts(cls, opts: dict) -> list[str]:
        lines: list[str] = []
        if "prefer_stealth" in opts:
            lines.append(
                "  · 拟真模式：" + ("开" if opts.get("prefer_stealth") else "关（真实浏览器）")
            )
        ch = str(opts.get("browser_channel") or "").strip().lower()
        if ch:
            ch_zh = {"msedge": "Edge", "chrome": "Chrome", "chromium": "Chromium"}.get(
                ch, ch
            )
            lines.append(f"  · 浏览器通道：{ch_zh}")
        if opts.get("cdp_attach"):
            cdp_br = str(opts.get("cdp_browser") or ch or "msedge")
            cdp_zh = {"msedge": "Edge", "chrome": "Chrome"}.get(cdp_br, cdp_br)
            lines.append(f"  · 连接方式：系统浏览器 + CDP（{cdp_zh}）")
        if "anti_debug" in opts:
            lines.append("  · 反调试中和：" + ("开" if opts.get("anti_debug") else "关"))
        if opts.get("record_mode"):
            lines.append("  · 录制模式：开")
        # 其余未映射键折叠，避免抛一堆英文 key
        known = {
            "prefer_stealth",
            "browser_channel",
            "cdp_attach",
            "cdp_browser",
            "anti_debug",
            "record_mode",
        }
        extra = [k for k in opts.keys() if k not in known]
        if extra:
            lines.append("  · 其他：" + "、".join(str(k) for k in extra[:6]))
        return lines

    def _show_parsed(self, parsed: dict) -> None:
        lines: list[str] = []
        if "reached" in parsed:
            reached = parsed.get("reached")
            if reached is True:
                lines.append("结果：已通关")
            elif reached is False:
                lines.append("结果：未通关")
            else:
                lines.append("结果：待确认")
        goal = str(parsed.get("goal") or "").strip()
        if goal:
            # 去掉过「AI」的 goal 前缀
            g = goal
            for prefix in ("全量策略扫描目标页:", "全量策略扫描目标页：", "扫描目标页能否正常打开："):
                if g.startswith(prefix):
                    g = g[len(prefix) :].strip()
                    break
            if g:
                lines.append(f"目标：{g}")
        reason = str(parsed.get("reason") or "").strip()
        if reason:
            lines.append("")
            lines.append("说明")
            lines.append(reason)
        elif "reached" in parsed:
            lines.append("")
            lines.append("说明")
            lines.append("（本轮未给出通关/未通关的具体原因）")
        evidence = str(parsed.get("evidence") or "").strip()
        if evidence and evidence not in (reason or ""):
            lines.append("")
            lines.append("依据")
            lines.append(evidence)
        # 全量策略扫描表（顶层或嵌在 strategy_sweep）
        sweep = parsed.get("strategy_sweep") if isinstance(parsed.get("strategy_sweep"), dict) else None
        if parsed.get("mode") == "strategy_sweep":
            sweep = parsed
        if sweep:
            total = sweep.get("total")
            lines.append("")
            lines.append(f"策略试跑 · 共 {total} 组")
            for r in sweep.get("results") or []:
                if not isinstance(r, dict):
                    continue
                verd = self._verdict_zh(str(r.get("verdict") or ""))
                title = str(r.get("title") or "").strip() or "—"
                score = r.get("score")
                score_bit = f" · 匹配 {score}" if score is not None else ""
                lines.append(
                    f"  · {r.get('label') or '-'} — {verd}{score_bit} · 标题 {title}"
                )
            best = sweep.get("best") if isinstance(sweep.get("best"), dict) else {}
            if best:
                lines.append("")
                lines.append(
                    f"推荐：{best.get('label')}（{self._verdict_zh(str(best.get('verdict') or ''))}）"
                )
                launch = best.get("launch") if isinstance(best.get("launch"), dict) else None
                launch_line = self._human_launch_line(launch)
                if launch_line:
                    lines.append(f"启动方式：{launch_line}")
        summary = str(parsed.get("summary") or "").strip()
        if summary and not (sweep and summary == sweep.get("summary")):
            lines.append("")
            lines.append(summary)
        elif summary and not sweep:
            lines.append("")
            lines.append(summary)
        advice = str(parsed.get("advice") or "").strip()
        if advice:
            lines.append("")
            lines.append("建议")
            lines.append(advice)
        patterns = parsed.get("patterns") or []
        if patterns:
            lines.append("")
            lines.append("识别到：" + "、".join(str(p) for p in patterns[:12]))
        opts = parsed.get("browser_opts") if isinstance(parsed.get("browser_opts"), dict) else {}
        if opts:
            lines.append("")
            lines.append("浏览器选项")
            lines.extend(self._human_browser_opts(opts))
        launch = parsed.get("launch") if isinstance(parsed.get("launch"), dict) else None
        launch_line = self._human_launch_line(launch)
        if launch_line and not sweep:
            lines.append("")
            lines.append(f"启动方式：{launch_line}")
        attempts = parsed.get("attempts")
        if attempts is not None:
            lines.append("")
            lines.append(f"尝试轮次：{attempts}")
        hook_js = str(parsed.get("hook_js") or "").strip()
        if hook_js:
            lines.append("")
            lines.append(f"Hook 脚本：约 {len(hook_js)} 字（见「hook_js」页）")
        if self._mode == "live" and parsed.get("reached") is True:
            lines.append("")
            lines.append(
                "下一步：可确认是否启动实验室浏览器，继续采集加密流量。"
                "通关用的浏览器档案与实验室档案是分开的。"
            )
        elif self._mode == "live":
            lines.append("")
            lines.append(
                "下一步：可在实验室点「启动」，继续采集加密流量。"
            )
        self.summary_view.setPlainText("\n".join(lines) or "(空)")
        try:
            self.json_view.setPlainText(json.dumps(parsed, ensure_ascii=False, indent=2))
        except Exception:
            self.json_view.setPlainText(str(parsed))
        self.hook_view.setPlainText(
            hook_js
            or (
                "(无 hook_js — 实时通关默认不生成补丁；"
                "需要站点 Hook 可再点「离线补丁」)"
                if self._mode == "live"
                else "(无 hook_js)"
            )
        )

    def _append_log(self, msg: str) -> None:
        self.log_view.appendPlainText(msg.rstrip("\n") if msg.endswith("\n") else msg)
        self.log_view.moveCursor(QTextCursor.MoveOperation.End)

    @staticmethod
    def _status_strategy_label(parsed: dict | None, reason: str = "") -> str:
        """从结果里抽一个短标签，供状态栏使用。"""
        import re

        parsed = parsed if isinstance(parsed, dict) else {}
        sweep = parsed.get("strategy_sweep") if isinstance(parsed.get("strategy_sweep"), dict) else None
        if parsed.get("mode") == "strategy_sweep":
            sweep = parsed
        best = sweep.get("best") if isinstance(sweep, dict) else None
        if isinstance(best, dict):
            lab = str(best.get("label") or "").strip()
            if lab:
                return lab
        launch = parsed.get("launch") if isinstance(parsed.get("launch"), dict) else {}
        lab = str(launch.get("label") or "").strip()
        if lab:
            return lab
        m = re.search(r"「([^」]{1,20})」", reason or "")
        if m:
            return m.group(1)
        return ""

    def _apply_status_style(self, *, kind: str = "idle") -> None:
        """状态条：绿色字 + 普通底，去掉蓝色强调底。"""
        if kind == "busy":
            color = C.get("warn")
        elif kind == "err":
            color = C.get("danger")
        elif kind == "ok":
            color = C.get("ok")
        else:
            color = C.get("text_dim")
        self.status_label.setStyleSheet(
            f"font-weight:600;padding:2px 0;border:none;"
            f"background:transparent;color:{color};"
        )

    def _set_status(self, text: str, *, busy: bool) -> None:
        msg = (text or "").strip() or "就绪"
        # 状态栏控制长度，细节放结论页
        if len(msg) > 42:
            msg = msg[:42] + "…"
        self.status_label.setText(msg)
        low = msg.lower()
        if busy:
            kind = "busy"
        elif any(x in msg for x in ("失败", "未通关", "未达成", "取消", "请填写")):
            kind = "err"
        elif any(x in msg for x in ("通关成功", "完成", "已同步", "正在启动")):
            kind = "ok"
        elif "就绪" in msg:
            kind = "idle"
        else:
            kind = "ok" if not busy else "busy"
        if "soft_pass" in low or "建议人工" in msg:
            kind = "busy"
        self._apply_status_style(kind=kind)

    def _set_busy(self, busy: bool) -> None:
        self.start_btn.setEnabled(not busy)
        if hasattr(self, "sweep_only_btn"):
            self.sweep_only_btn.setEnabled(not busy)
        self.offline_btn.setEnabled(not busy)
        self.follow_btn.setEnabled(not busy)
        self.stop_btn.setEnabled(busy)
        self.stop_btn.setText("停止")

    def showEvent(self, event) -> None:
        super().showEvent(event)
        lab = self._lab
        if hasattr(lab, "url_edit"):
            cur = (lab.url_edit.text() or "").strip()
            if cur and not (self.url_edit.text() or "").strip():
                self.url_edit.setText(cur)

    def closeEvent(self, event) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
        super().closeEvent(event)


def open_bot_bypass_dialog(lab_tab, *, auto_start: bool = True) -> BotBypassDialog:
    """打开或唤起浏览器绕过 Agent 窗口。"""
    dlg = getattr(lab_tab, "_bot_bypass_dlg", None)
    if dlg is None or not isinstance(dlg, BotBypassDialog):
        dlg = BotBypassDialog(lab_tab, parent=lab_tab.window())
        lab_tab._bot_bypass_dlg = dlg
    dlg.show()
    dlg.raise_()
    dlg.activateWindow()
    if auto_start and not (dlg._worker and dlg._worker.isRunning()):
        # 有 URL 才自动开跑；否则只弹出窗口让用户填
        url = (dlg.url_edit.text() or "").strip()
        if url:
            dlg.start_live()
        else:
            dlg._set_status("请填写目标 URL 后点「开始通关」", busy=False)
    return dlg
