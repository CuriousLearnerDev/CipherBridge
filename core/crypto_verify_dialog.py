"""加解密验证结果弹窗 — 展示请求/响应是否正确。"""

from __future__ import annotations

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QPlainTextEdit,
    QTabWidget,
    QVBoxLayout,
    QWidget,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
)

from core.crypto_verify import SideCheck, VerifyReport
from core.theme import C, style_button


def _side_panel(side: SideCheck) -> QWidget:
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
        table = QTableWidget(len(side.fields), 4)
        table.setHorizontalHeaderLabels(["字段", "结果", "说明", "处理后预览"])
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setMaximumHeight(min(220, 36 + 32 * len(side.fields)))
        for i, f in enumerate(side.fields):
            table.setItem(i, 0, QTableWidgetItem(f.field))
            table.setItem(i, 1, QTableWidgetItem("✅" if f.ok else "❌"))
            table.setItem(i, 2, QTableWidgetItem(f.message))
            table.setItem(i, 3, QTableWidgetItem(f.after or f.before))
        lay.addWidget(table)

    tabs = QTabWidget()
    for title, text in (("处理前", side.before), ("处理后", side.after)):
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
) -> str:
    """展示验证结果。

    返回值:
      - \"ok\": 验证通过并继续
      - \"force\": 未通过但仍要继续写入
      - \"retry\": 未通过，让 AI 根据失败报文重试修正
      - \"cancel\": 取消
      - \"done\": 仅查看模式关闭
    """
    attempt = max(1, int(attempt or 1))
    max_attempts = max(1, int(max_attempts or 5))
    can_retry = pre_write and (not report.overall_ok) and attempt < max_attempts

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

    if report.plugin_notice:
        n = QLabel(report.plugin_notice)
        n.setWordWrap(True)
        n.setStyleSheet(f"color:{C.get('warn', C.get('text_dim'))};")
        root.addWidget(n)

    if report.error:
        e = QLabel(report.error)
        e.setWordWrap(True)
        e.setStyleSheet(f"color:{C.get('danger')};")
        root.addWidget(e)

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

    result = {"action": "cancel"}
    btns = QDialogButtonBox()

    if report.overall_ok:
        ok_btn = btns.addButton("验证通过，继续生成", QDialogButtonBox.ButtonRole.AcceptRole)
        style_button(ok_btn, "primary")

        def _ok():
            result["action"] = "ok"
            dlg.accept()

        ok_btn.clicked.connect(_ok)
    else:
        if can_retry:
            retry_btn = btns.addButton(
                "根据失败结果让 AI 重试", QDialogButtonBox.ButtonRole.ActionRole
            )
            style_button(retry_btn, "primary")

            def _retry():
                result["action"] = "retry"
                dlg.accept()

            retry_btn.clicked.connect(_retry)

        force_btn = btns.addButton(
            "验证未通过，仍要继续", QDialogButtonBox.ButtonRole.DestructiveRole
        )
        style_button(force_btn, "danger")

        def _force():
            result["action"] = "force"
            dlg.accept()

        force_btn.clicked.connect(_force)

    cancel_btn = btns.addButton("取消", QDialogButtonBox.ButtonRole.RejectRole)
    style_button(cancel_btn, "ghost")

    def _cancel():
        result["action"] = "cancel"
        dlg.reject()

    cancel_btn.clicked.connect(_cancel)
    root.addWidget(btns)
    dlg.exec()
    return str(result.get("action") or "cancel")
