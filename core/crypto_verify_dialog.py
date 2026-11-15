"""加解密验证结果弹窗 — 展示请求/响应是否正确。"""

from __future__ import annotations

from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
)

from core.crypto_verify import SideCheck, VerifyReport
from core.icon_loader import icon
from core.theme import C, style_button


def _result_item(ok: bool) -> QTableWidgetItem:
    """结果列：圆圈对勾 / 圆圈叉（iconfont），按主题成功/失败色着色。"""
    item = QTableWidgetItem()
    tint = C.get("ok", "#1a7f37") if ok else C.get("danger", "#cf222e")
    name = "verify_ok" if ok else "verify_fail"
    item.setIcon(icon(name, 18, tint=tint))
    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
    item.setToolTip("通过" if ok else "未通过")
    return item


def _side_panel(
    side: SideCheck,
    *,
    before_title: str = "处理前",
    after_title: str = "处理后",
    preview_header: str = "处理后预览",
) -> QWidget:
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(4, 4, 4, 4)
    lay.setSpacing(8)

    if side.message:
        msg = QLabel(side.message)
        msg.setWordWrap(True)
        msg.setStyleSheet(f"color:{C.get('text_dim')};")
        lay.addWidget(msg)

    if side.fields:
        table = QTableWidget(len(side.fields), 5)
        table.setHorizontalHeaderLabels(
            ["字段", "结果", "加解密方式", "说明", preview_header]
        )
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        table.setIconSize(QSize(18, 18))
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setMaximumHeight(min(220, 36 + 32 * len(side.fields)))
        for i, f in enumerate(side.fields):
            table.setItem(i, 0, QTableWidgetItem(f.field))
            table.setItem(i, 1, _result_item(bool(f.ok)))
            method_item = QTableWidgetItem(getattr(f, "method", "") or "—")
            method_item.setToolTip(method_item.text())
            table.setItem(i, 2, method_item)
            table.setItem(i, 3, QTableWidgetItem(f.message))
            table.setItem(i, 4, QTableWidgetItem(f.after or f.before))
        lay.addWidget(table)

    tabs = QTabWidget()
    for title, text in ((before_title, side.before), (after_title, side.after)):
        e = QPlainTextEdit()
        e.setReadOnly(True)
        e.setFont(QFont("Cascadia Code", 10))
        e.setPlainText(text or "(空)")
        tabs.addTab(e, title)
    if side.after and side.after != side.before:
        tabs.setCurrentIndex(1)
    lay.addWidget(tabs, 1)
    return w


def show_verify_dialog(
    parent,
    report: VerifyReport,
    *,
    pre_write: bool = False,
    attempt: int = 1,
    max_attempts: int = 5,
    decrypt_steps: list | None = None,
    sample_flow: dict | None = None,
) -> str:
    """展示验证结果。

    返回值:
      - \"ok\": 验证通过并生成解密代码
      - \"ok_both\": 解密+加密均通过，生成加解密代码
      - \"force\": 未通过但仍要继续写入
      - \"retry\": 未通过，让 AI 根据失败报文重试修正
      - \"cancel\": 取消
      - \"done\": 仅查看模式关闭

    若点击「分析加密」成功，encrypt 步骤会写到 parent._pending_encrypt_steps。
    """
    attempt = max(1, int(attempt or 1))
    max_attempts = max(1, int(max_attempts or 5))
    can_retry = pre_write and (not report.overall_ok) and attempt < max_attempts
    role = (getattr(report, "role", None) or "decrypt").lower()
    can_analyze_encrypt = (
        pre_write
        and report.overall_ok
        and role == "decrypt"
        and bool(decrypt_steps)
        and sample_flow is not None
    )

    dlg = QDialog(parent)
    if pre_write and report.overall_ok:
        dlg.setWindowTitle(f"加解密自动验证 — 通过（第 {attempt}/{max_attempts} 次）")
    elif pre_write:
        dlg.setWindowTitle(f"加解密自动验证 — 未通过（第 {attempt}/{max_attempts} 次）")
    else:
        dlg.setWindowTitle("加解密验证结果")
    dlg.setMinimumSize(860, 620)
    root = QVBoxLayout(dlg)
    root.setSpacing(10)

    if pre_write and not report.overall_ok:
        if can_retry:
            tip = QLabel(
                f"验证未通过。可将失败的请求/响应回传给 AI 修正步骤"
                f"（还可重试 {max_attempts - attempt} 次）。"
            )
        else:
            tip = QLabel(
                f"已连续验证 {attempt} 次仍未通过，停止自动判断（判断不出来）。"
                "可取消，或仍强制继续写入。"
            )
        tip.setWordWrap(True)
        tip.setStyleSheet(f"color:{C.get('warn', C.get('text_dim'))};")
        root.addWidget(tip)

    plugin_notice_lab = None
    if report.plugin_notice:
        plugin_notice_lab = QLabel(report.plugin_notice)
        plugin_notice_lab.setWordWrap(True)
        plugin_notice_lab.setStyleSheet(f"color:{C.get('warn', C.get('text_dim'))};")
        root.addWidget(plugin_notice_lab)

    if report.error:
        e = QLabel(report.error)
        e.setWordWrap(True)
        e.setStyleSheet(f"color:{C.get('danger')};")
        root.addWidget(e)

    encrypt_tip = QLabel("")
    encrypt_tip.setWordWrap(True)
    encrypt_tip.hide()
    root.addWidget(encrypt_tip)

    panes = QTabWidget()
    panes.addTab(_side_panel(report.request), "请求数据")
    panes.addTab(_side_panel(report.response), "响应数据")
    if report.request.ok is None and report.response.ok is not None:
        panes.setCurrentIndex(1)
    root.addWidget(panes, 1)

    if not pre_write:
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close_btn = btns.button(QDialogButtonBox.StandardButton.Close)
        if close_btn:
            style_button(close_btn, "primary")
        btns.rejected.connect(dlg.reject)
        btns.accepted.connect(dlg.accept)
        root.addWidget(btns)
        dlg.exec()
        return "done"

    result = {"action": "cancel", "encrypt_ok": False}
    foot = QHBoxLayout()
    foot.setSpacing(8)

    if report.overall_ok:
        analyze_btn = None
        if can_analyze_encrypt:
            analyze_btn = QPushButton("分析加密")
            analyze_btn.setToolTip(
                "由解密步骤反推加密，并把重加密结果与采样原密文对照"
            )
            style_button(analyze_btn, "accent")
            foot.addWidget(analyze_btn)

        ok_btn = QPushButton("验证通过、生成解密代码")
        style_button(ok_btn, "primary")
        foot.addWidget(ok_btn)

        def _ok():
            result["action"] = "ok_both" if result["encrypt_ok"] else "ok"
            dlg.accept()

        ok_btn.clicked.connect(_ok)

        def _analyze_encrypt():
            from core.crypto_verify import (
                has_reversible_crypto_steps,
                verify_encrypt_roundtrip,
            )

            if not has_reversible_crypto_steps(decrypt_steps):
                encrypt_tip.setText("当前步骤没有可反推的加解密字段，无法分析加密。")
                encrypt_tip.setStyleSheet(f"color:{C.get('warn', C.get('text_dim'))};")
                encrypt_tip.show()
                return
            try:
                enc_report, enc_steps = verify_encrypt_roundtrip(
                    decrypt_steps, sample_flow
                )
            except Exception as exc:
                encrypt_tip.setText(f"分析加密失败：{exc}")
                encrypt_tip.setStyleSheet(f"color:{C.get('danger')};")
                encrypt_tip.show()
                return

            # 加密回环视图：隐藏解密阶段的插件干跑提示，避免误以为失败
            if plugin_notice_lab is not None:
                plugin_notice_lab.hide()
            while panes.count():
                w = panes.widget(0)
                panes.removeTab(0)
                if w is not None:
                    w.deleteLater()
            panel_kw = dict(
                before_title="原密文",
                after_title="明文（加密端输入）",
                preview_header="明文预览",
            )
            panes.addTab(
                _side_panel(enc_report.request, **panel_kw), "请求数据（加密回环）"
            )
            panes.addTab(
                _side_panel(enc_report.response, **panel_kw), "响应数据（加密回环）"
            )
            if enc_report.request.ok is None and enc_report.response.ok is not None:
                panes.setCurrentIndex(1)

            if enc_report.overall_ok:
                result["encrypt_ok"] = True
                if parent is not None:
                    setattr(parent, "_pending_encrypt_steps", enc_steps)
                encrypt_tip.setText(
                    "加密分析通过：重加密与原密文一致"
                    "（确定性加密下密文相同是正常的）。确认后将生成解密 + 加密代码。"
                )
                encrypt_tip.setStyleSheet(f"color:{C.get('ok', '#1a7f37')};")
                encrypt_tip.show()
                ok_btn.setText("验证通过、生成加解密代码")
                if analyze_btn is not None:
                    analyze_btn.hide()
                dlg.setWindowTitle(
                    f"加解密自动验证 — 解密+加密通过（第 {attempt}/{max_attempts} 次）"
                )
            else:
                result["encrypt_ok"] = False
                if parent is not None:
                    setattr(parent, "_pending_encrypt_steps", None)
                encrypt_tip.setText(
                    f"加密分析未通过：{enc_report.summary}。仍可只生成解密代码。"
                )
                encrypt_tip.setStyleSheet(f"color:{C.get('warn', C.get('text_dim'))};")
                encrypt_tip.show()
                ok_btn.setText("验证通过、生成解密代码")

        if analyze_btn is not None:
            analyze_btn.clicked.connect(_analyze_encrypt)
    else:
        if can_retry:
            retry_btn = QPushButton("根据失败结果让 AI 重试")
            style_button(retry_btn, "primary")
            foot.addWidget(retry_btn)

            def _retry():
                result["action"] = "retry"
                dlg.accept()

            retry_btn.clicked.connect(_retry)

        force_btn = QPushButton("验证未通过，仍要继续")
        style_button(force_btn, "danger")
        foot.addWidget(force_btn)

        def _force():
            result["action"] = "force"
            dlg.accept()

        force_btn.clicked.connect(_force)

    foot.addStretch(1)
    cancel_btn = QPushButton("取消")
    style_button(cancel_btn, "ghost")

    def _cancel():
        result["action"] = "cancel"
        dlg.reject()

    cancel_btn.clicked.connect(_cancel)
    foot.addWidget(cancel_btn)
    root.addLayout(foot)
    dlg.exec()
    return str(result.get("action") or "cancel")
