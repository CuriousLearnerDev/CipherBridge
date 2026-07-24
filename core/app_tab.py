"""App 逆向面板 — 选择 APK，apktool 反编译，筛加解密代码给 Agent."""

from __future__ import annotations

import os
import subprocess
import sys

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QPlainTextEdit, QFileDialog, QMessageBox, QListWidget, QListWidgetItem,
    QTabWidget,
)

from core.app_reverse import (
    ApkReverseError,
    decode_apk,
    default_apk_workspace,
    resolve_jadx_gui,
    tools_status,
)
from core.icon_loader import set_btn_icon
from core.theme import style_button, style_muted_label, style_sidebar_aux_button


class _DecodeWorker(QThread):
    finished_ok = pyqtSignal(object)
    failed = pyqtSignal(str)
    log = pyqtSignal(str)

    def __init__(self, apk_path: str, parent=None):
        super().__init__(parent)
        self.apk_path = apk_path

    def run(self):
        try:
            result = decode_apk(self.apk_path, on_log=lambda m: self.log.emit(m))
            for msg in result.messages:
                self.log.emit(msg)
            self.finished_ok.emit(result)
        except ApkReverseError as e:
            self.failed.emit(str(e))
        except Exception as e:
            self.failed.emit(f"未预期错误: {e}")


class AppReversePanel(QWidget):
    """导入 APK → 反编译 → 把加解密相关代码注入右侧 Agent."""

    scripts_ready = pyqtSignal(dict, dict)
    request_ai_analyze = pyqtSignal()
    capture_log = pyqtSignal(str)

    def __init__(self, parent=None, *, compact: bool = True):
        super().__init__(parent)
        self._worker: _DecodeWorker | None = None
        self._last_result = None
        self._apk_path = ""
        self._compact = compact
        self._build_ui()
        self._refresh_tools_hint()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        m = 0 if self._compact else 8
        layout.setContentsMargins(m, m, m, m)
        layout.setSpacing(8)

        title = QLabel("App 逆向（可选）")
        title.setObjectName("homeSectionTitle")
        layout.addWidget(title)

        row = QHBoxLayout()
        row.setSpacing(6)
        self.pick_btn = QPushButton("选择 APK")
        self.pick_btn.clicked.connect(self._pick_apk)
        style_button(self.pick_btn, "accent")
        set_btn_icon(self.pick_btn, "folder", size=14)
        self.pick_btn.setMinimumHeight(32)
        row.addWidget(self.pick_btn, 1)
        self.decode_btn = QPushButton("反编译并扫描")
        self.decode_btn.setEnabled(False)
        self.decode_btn.clicked.connect(self._start_decode)
        style_button(self.decode_btn, "primary")
        set_btn_icon(self.decode_btn, "unlock", size=14)
        self.decode_btn.setMinimumHeight(32)
        row.addWidget(self.decode_btn, 1)
        layout.addLayout(row)

        row2 = QHBoxLayout()
        self.jadx_btn = QPushButton("打开 jadx")
        self.jadx_btn.setToolTip("用 jadx-gui 打开当前 APK 做深度查看")
        self.jadx_btn.clicked.connect(self._open_jadx)
        style_sidebar_aux_button(self.jadx_btn)
        row2.addWidget(self.jadx_btn)
        self.open_out_btn = QPushButton("输出目录")
        self.open_out_btn.setEnabled(False)
        self.open_out_btn.clicked.connect(self._open_out)
        style_sidebar_aux_button(self.open_out_btn)
        row2.addWidget(self.open_out_btn)
        row2.addStretch()
        layout.addLayout(row2)

        self.apk_label = QLabel("未选择 APK")
        self.apk_label.setWordWrap(True)
        style_muted_label(self.apk_label)
        layout.addWidget(self.apk_label)

        self.tools_label = QLabel()
        self.tools_label.setWordWrap(True)
        style_muted_label(self.tools_label)
        layout.addWidget(self.tools_label)

        self.status = QLabel("选择 APK 后反编译，命中代码会送给右侧 Agent。")
        self.status.setWordWrap(True)
        style_muted_label(self.status)
        layout.addWidget(self.status)

        tabs = QTabWidget()
        self.hit_list = QListWidget()
        self.hit_list.itemClicked.connect(self._preview_hit)
        tabs.addTab(self.hit_list, "加解密候选")
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setPlaceholderText("点候选文件预览")
        tabs.addTab(self.preview, "预览")
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(1500)
        self.log_view.setPlaceholderText("反编译日志")
        tabs.addTab(self.log_view, "日志")
        tabs.setMinimumHeight(220)
        layout.addWidget(tabs, 1)

        tip = QLabel("完成后到右侧 Agent：「AI识别加解密」会参考 app:// 源码")
        style_muted_label(tip)
        tip.setWordWrap(True)
        layout.addWidget(tip)

    def _refresh_tools_hint(self):
        st = tools_status()
        parts = [
            "Java✓" if st["java"] else "Java✗",
            "apktool✓" if st["apktool"] else "apktool✗",
            "jadx✓" if st["jadx_gui"] else "jadx✗",
        ]
        self.tools_label.setText("工具: " + " · ".join(parts))
        self.jadx_btn.setEnabled(bool(st["jadx_gui"]))

    def _log(self, text: str):
        self.log_view.appendPlainText(text)
        self.capture_log.emit(text)

    def _pick_apk(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择 APK", "", "Android APK (*.apk);;所有文件 (*.*)",
        )
        if not path:
            return
        self._apk_path = os.path.abspath(path)
        self.apk_label.setText(self._apk_path)
        self.decode_btn.setEnabled(True)
        self._log(f"已选择: {self._apk_path}")

    def _start_decode(self):
        if not self._apk_path or not os.path.isfile(self._apk_path):
            QMessageBox.warning(self, "提示", "请先选择 APK")
            return
        if self._worker and self._worker.isRunning():
            self._log("正在反编译，请稍候…")
            return
        self.decode_btn.setEnabled(False)
        self.pick_btn.setEnabled(False)
        self.hit_list.clear()
        self.preview.clear()
        self.log_view.clear()
        self.status.setText("正在反编译并扫描加解密…")
        self._worker = _DecodeWorker(self._apk_path, self)
        self._worker.log.connect(self._log)
        self._worker.finished_ok.connect(self._on_done)
        self._worker.failed.connect(self._on_fail)
        self._worker.start()

    def _on_done(self, result):
        self._last_result = result
        self.decode_btn.setEnabled(True)
        self.pick_btn.setEnabled(True)
        self.open_out_btn.setEnabled(True)
        label = result.app_label or os.path.basename(result.apk_path)
        pkg = f" ({result.package_name})" if result.package_name else ""
        self.status.setText(f"完成 {label}{pkg} · 候选 {len(result.crypto_hits)} · {result.out_dir}")
        self.hit_list.clear()
        for h in result.crypto_hits:
            item = QListWidgetItem(f"[{h.score}] {h.relpath}")
            item.setData(Qt.ItemDataRole.UserRole, h.path)
            self.hit_list.addItem(item)
        scripts = result.scripts_for_ai()
        if scripts:
            meta = {
                "source": "apk",
                "apk": result.apk_path,
                "package": result.package_name,
                "out_dir": result.out_dir,
            }
            self.scripts_ready.emit(scripts, meta)
            self._log(f"已注入 Agent 素材 {len(scripts)} 个 (app://…)")
        else:
            self._log("未筛到明显加解密代码，可打开 jadx 手工定位后再试")

    def _on_fail(self, err: str):
        self.decode_btn.setEnabled(bool(self._apk_path))
        self.pick_btn.setEnabled(True)
        self.status.setText("反编译失败")
        self._log(f"错误: {err}")
        QMessageBox.critical(self, "App 逆向失败", err)

    def _preview_hit(self, item: QListWidgetItem):
        path = item.data(Qt.ItemDataRole.UserRole)
        if not path or not os.path.isfile(path):
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read(80_000)
            self.preview.setPlainText(text)
        except OSError as e:
            self.preview.setPlainText(str(e))

    def _open_out(self):
        path = self._last_result.out_dir if self._last_result else default_apk_workspace()
        if not os.path.isdir(path):
            return
        if sys.platform == "win32":
            os.startfile(path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])

    def _open_jadx(self):
        jadx = resolve_jadx_gui()
        if not jadx:
            QMessageBox.information(self, "提示", "未找到 jadx-gui")
            return
        try:
            if self._apk_path and os.path.isfile(self._apk_path):
                subprocess.Popen([jadx, self._apk_path])
            else:
                subprocess.Popen([jadx])
            self._log(f"已启动 jadx: {jadx}")
        except OSError as e:
            QMessageBox.warning(self, "启动失败", str(e))

    def _emit_scripts(self, silent: bool = False) -> bool:
        if not self._last_result:
            if not silent:
                QMessageBox.information(self, "提示", "请先反编译 APK")
            return False
        scripts = self._last_result.scripts_for_ai()
        if not scripts:
            if not silent:
                QMessageBox.warning(self, "提示", "没有可分析的加解密候选代码")
            return False
        meta = {
            "source": "apk",
            "apk": self._last_result.apk_path,
            "package": self._last_result.package_name,
            "out_dir": self._last_result.out_dir,
        }
        self.scripts_ready.emit(scripts, meta)
        return True


AppTab = AppReversePanel
