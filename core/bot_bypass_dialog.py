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

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        url_row = QHBoxLayout()
        url_row.setSpacing(6)
        url_row.addWidget(QLabel("目标 URL"))
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://example.com")
        url = ""
        if hasattr(lab_tab, "url_edit"):
            url = (lab_tab.url_edit.text() or "").strip()
        self.url_edit.setText(url)
        url_row.addWidget(self.url_edit, 1)
        root.addLayout(url_row)

        opt_row = QHBoxLayout()
        opt_row.setSpacing(12)
        self.headless_check = QCheckBox("无头")
        self.headless_check.setToolTip("无头看不到页面，无法手动点验证码；默认关闭")
        opt_row.addWidget(self.headless_check)
        self.stealth_check = QCheckBox("拟真环境")
        self.stealth_check.setChecked(True)
        self.stealth_check.setToolTip(
            "初始是否拟真。通关中 AI 可用 browser_restart.reconfigure 自行开关"
            "（关拟真≈真实浏览器）"
        )
        opt_row.addWidget(self.stealth_check)
        self.mitm_check = QCheckBox("走解密代理")
        self.mitm_check.setToolTip(
            "初始是否走解密端。卡住时 AI 也可通过 reconfigure 改 proxy"
        )
        opt_row.addWidget(self.mitm_check)
        opt_row.addStretch(1)
        root.addLayout(opt_row)

        self.status_label = QLabel("就绪")
        self.status_label.setStyleSheet(
            f"font-weight:600;padding:6px 8px;border-radius:6px;"
            f"background:{C.get('accent_soft', C.get('surface2'))};"
        )
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
        self.start_btn.clicked.connect(lambda: self.start_live())
        bar.addWidget(self.start_btn)

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

        text_goal = (goal or "").strip() or _DEFAULT_GOAL_TPL.format(url=url)
        self._append_log(f"\n—— 开始通关 ——\nURL: {url}\n{text_goal[:240]}\n")
        self._set_status("通关中…（有头浏览器会弹出）", busy=True)
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
            "3) fresh_profile=true：清空 Cookie/档案再试\n"
            "4) headless=false：有验证码必须有头\n"
            "5) proxy 设为空：取消解密代理直连；或设 http://127.0.0.1:端口 走代理\n"
            "6) neutralize_devtools=true：中和反 DevTools（闪一下变空白时打开；"
            "与实验室「反调试」勾选一致，也可在此重开）\n"
            "连续同策略失败 2～3 次必须换一组参数。观测结果里的 launch 字段即当前配置。"
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
            parent=self,
        )
        self._worker.log.connect(self._on_log)
        self._worker.finished_ok.connect(self._on_ok)
        self._worker.failed.connect(self._on_fail)
        self._worker.start()
        lab._log(
            f"浏览器绕过 Agent 启动: {url}"
            + ("（已开反 DevTools 中和）" if anti_on else "")
        )

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
        # 状态栏只给短提示；完整证据已在「结论」页，勿把 evidence 长串贴上来
        short = str(parsed.get("summary") or "").strip()
        if not short:
            url = str(parsed.get("url") or "").strip()
            short = url[:80] if url else ""
        if reached is True:
            self._set_status(
                ("通关成功 · " + short) if short else "通关成功",
                busy=False,
            )
            if self._mode == "live":
                self._after_live_clearance(last_launch=last_launch)
        elif reached is False:
            self._set_status(
                ("未达成 · " + short) if short else "未达成",
                busy=False,
            )
            if self._mode == "live" and last_launch:
                self._sync_dialog_from_launch(last_launch)
        else:
            self._set_status(short[:120] or "分析完成", busy=False)
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
        self._append_log(
            f"已回写窗口勾选 ← AI 策略 use_stealth={launch.get('use_stealth')} "
            f"channel={launch.get('browser_channel')} headless={launch.get('headless')} "
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
        if ch in ("chrome", "chromium"):
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
        # AI 关掉拟真 ≈ 实验室「真实浏览器」
        if opts.get("prefer_stealth") is False and hasattr(lab, "_set_proxy_only"):
            try:
                lab._set_proxy_only(True, persist=True)
                self._append_log("AI 最终 use_stealth=false → 已切实验室「真实浏览器」\n")
            except Exception:
                pass
        elif opts.get("prefer_stealth") and hasattr(lab, "_set_proxy_only"):
            try:
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
            if ch in ("chrome", "chromium"):
                browser["browser_channel"] = ch
            cfg["browser"] = browser
            save_ai_config(cfg)
        except Exception:
            pass

        msg = "通关成功。\n\n"
        msg += "· 已按 AI 最终启动策略同步实验室选项\n"
        if launch:
            msg += (
                f"  （拟真={launch.get('use_stealth')} · "
                f"通道={launch.get('browser_channel')} · "
                f"模式={launch.get('mode')} · "
                f"反DevTools中和={launch.get('neutralize_devtools')}）\n"
            )
        if hook_js:
            msg += f"· 已写入 hook_js（约 {len(hook_js)} 字符）并开启暴力猴/密桥 Hook\n"
        else:
            msg += "· 本次实时通关未生成 hook_js（仅同步浏览器选项）\n"
        if self.mitm_check.isChecked():
            msg += "· 已勾选偏好：启动时尝试走解密代理（需解密端已开）\n"
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

    def _show_parsed(self, parsed: dict) -> None:
        lines = []
        if "reached" in parsed:
            lines.append(f"reached: {parsed.get('reached')}")
        goal = str(parsed.get("goal") or "").strip()
        if goal:
            lines.append(f"goal: {goal}")
        evidence = str(parsed.get("evidence") or "").strip()
        if evidence:
            lines.append("")
            lines.append("evidence:")
            lines.append(evidence)
        summary = str(parsed.get("summary") or "").strip()
        if summary:
            lines.append("")
            lines.append(summary)
        advice = str(parsed.get("advice") or "").strip()
        if advice:
            lines.append("")
            lines.append("建议:")
            lines.append(advice)
        patterns = parsed.get("patterns") or []
        if patterns:
            lines.append("")
            lines.append("识别到: " + ", ".join(str(p) for p in patterns[:12]))
        opts = parsed.get("browser_opts") if isinstance(parsed.get("browser_opts"), dict) else {}
        if opts:
            lines.append("")
            lines.append("浏览器建议:")
            for k, v in opts.items():
                lines.append(f"  · {k} = {v}")
        attempts = parsed.get("attempts")
        if attempts is not None:
            lines.append("")
            lines.append(f"attempts: {attempts}")
        hook_js = str(parsed.get("hook_js") or "").strip()
        if hook_js:
            lines.append("")
            lines.append(f"hook_js: 约 {len(hook_js)} 字符（见「hook_js」页）")
        if self._mode == "live" and parsed.get("reached") is True:
            lines.append("")
            lines.append(
                "提示：通关成功后会自动同步拟真选项；若有 hook_js 会写入。"
                "随后可确认是否启动实验室浏览器继续采加密流量。"
                "Agent 档案在 data/browser_agent_profile*（与实验室档案分离）。"
            )
        elif self._mode == "live":
            lines.append("")
            lines.append(
                "提示：可用实验室「启动」继续采加密流量；"
                "Agent 档案在 data/browser_agent_profile*（与实验室档案分离）。"
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

    def _set_status(self, text: str, *, busy: bool) -> None:
        self.status_label.setText(text)
        color = C.get("warn") if busy else C.get("ok")
        self.status_label.setStyleSheet(
            f"font-weight:600;padding:6px 8px;border-radius:6px;"
            f"background:{C.get('accent_soft', C.get('surface2'))};color:{color};"
        )

    def _set_busy(self, busy: bool) -> None:
        self.start_btn.setEnabled(not busy)
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
