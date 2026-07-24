"""小程序反编译面板 — 头像+名称列表，旁侧解包；识别/生成在右侧 Agent."""

from __future__ import annotations

import os
import subprocess
import sys

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QPixmap, QIcon, QPainter, QColor, QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QPlainTextEdit, QFileDialog, QMessageBox, QCheckBox, QSpinBox,
    QListWidget, QListWidgetItem, QFrame, QTabWidget, QLineEdit,
)

from core.theme import style_button, style_muted_label, style_sidebar_aux_button, C
from core.icon_loader import set_btn_icon
from core.miniprogram_capture import DEFAULT_PORT, MiniprogramCaptureWorker
from core.system_proxy import is_supported as system_proxy_supported
from core.wxapkg import (
    decompile_wxapkg,
    discover_miniprograms,
    MiniprogramInfo,
    WxapkgDecryptError,
    WxapkgUnpackError,
)


class _DecompileWorker(QThread):
    finished_ok = pyqtSignal(object)
    failed = pyqtSignal(str)
    log = pyqtSignal(str)

    def __init__(self, path: str, appid: str, parent=None):
        super().__init__(parent)
        self.path = path
        self.appid = appid

    def run(self):
        try:
            result = decompile_wxapkg(
                self.path,
                appid=self.appid,
                out_dir=None,
                split_modules=True,
                scan_crypto=True,
            )
            for msg in result.messages:
                self.log.emit(msg)
            self.finished_ok.emit(result)
        except (WxapkgDecryptError, WxapkgUnpackError, FileNotFoundError, OSError) as e:
            self.failed.emit(str(e))
        except Exception as e:
            self.failed.emit(f"未预期错误: {e}")


def _placeholder_icon(size: int = 40) -> QPixmap:
    pm = QPixmap(size, size)
    pm.fill(QColor(C.get("surface2", "#3c3c3c")))
    painter = QPainter(pm)
    painter.setPen(QColor(C.get("text_dim", "#999")))
    font = QFont()
    font.setPointSize(11)
    font.setBold(True)
    painter.setFont(font)
    painter.drawText(pm.rect(), Qt.AlignmentFlag.AlignCenter, "小")
    painter.end()
    return pm


def _load_avatar(path: str, size: int = 40) -> QPixmap:
    if path and os.path.isfile(path):
        pm = QPixmap(path)
        if not pm.isNull():
            return pm.scaled(
                size, size,
                Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation,
            ).copy(0, 0, size, size)
    return _placeholder_icon(size)


class _AppRow(QFrame):
    """单行：头像 | 名称+AppID | 解包按钮."""

    unpack_clicked = pyqtSignal(object)

    def __init__(self, info: MiniprogramInfo, parent=None):
        super().__init__(parent)
        self.info = info
        self.setObjectName("miniAppRow")
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setStyleSheet(
            f"QFrame#miniAppRow {{ background: transparent; }}"
            f"QFrame#miniAppRow QLabel {{ background: transparent; }}"
        )
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(10)

        avatar = QLabel()
        avatar.setFixedSize(42, 42)
        avatar.setPixmap(_load_avatar(info.icon_path, 42))
        avatar.setStyleSheet("border-radius: 6px; background: transparent;")
        layout.addWidget(avatar)

        text_col = QVBoxLayout()
        text_col.setSpacing(2)
        tip = f"{info.display_name}\n{info.appid}\n{info.path}"
        name = QLabel(info.display_name)
        # 勿用 color:inherit — 在 QListWidget 子控件里常变成黑色
        name.setStyleSheet(
            f"font-weight: 600; background: transparent; color: {C.get('text', '#e8eaed')};"
        )
        name.setToolTip(tip)
        text_col.addWidget(name)
        sub = QLabel(f"{info.appid}  ·  {info.pkg_count} 个包")
        style_muted_label(sub)
        sub.setStyleSheet(
            f"color: {C.get('text_dim', '#8b929e')}; background: transparent; font-size: 12px;"
        )
        sub.setToolTip(tip)
        text_col.addWidget(sub)
        layout.addLayout(text_col, 1)

        self.setToolTip(tip)
        avatar.setToolTip(tip)

        btn = QPushButton("解包")
        btn.setToolTip("解密并解包此小程序")
        btn.setFixedWidth(64)
        style_button(btn, "accent")
        set_btn_icon(btn, "unlock", size=14)
        btn.clicked.connect(lambda: self.unpack_clicked.emit(self.info))
        layout.addWidget(btn)


class MiniprogramPanel(QWidget):
    """扫描本机小程序列表；解包；代理抓包；AI 识别加解密."""

    scripts_ready = pyqtSignal(dict, dict)
    request_ai_analyze = pyqtSignal()
    flow_captured = pyqtSignal(dict)
    flow_updated = pyqtSignal(dict)
    flow_selected = pyqtSignal(dict)
    capture_log = pyqtSignal(str)

    def __init__(self, parent=None, *, compact: bool = True):
        super().__init__(parent)
        self._worker: _DecompileWorker | None = None
        self._capture: MiniprogramCaptureWorker | None = None
        self._last_result = None
        self._apps: list[MiniprogramInfo] = []
        self._extra_roots: list[str] = []
        self._busy = False
        self._compact = compact
        self._local_flow_count = 0
        self._local_flows: list[dict] = []
        self._build_ui()
        self.refresh_list()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        m = 0 if self._compact else 8
        layout.setContentsMargins(m, m, m, m)
        layout.setSpacing(8)

        # —— 抓包（可选，与解包互补） ——
        cap_title = QLabel("抓包（可选）")
        cap_title.setObjectName("homeSectionTitle")
        layout.addWidget(cap_title)
        cap = QHBoxLayout()
        cap.setSpacing(6)
        self.capture_btn = QPushButton("启动抓包")
        self.capture_btn.setToolTip(
            "mitm 代理抓小程序 HTTPS（需在「设置」安装证书）"
        )
        self.capture_btn.clicked.connect(self._toggle_capture)
        style_button(self.capture_btn, "accent")
        set_btn_icon(self.capture_btn, "play", size=14)
        self.capture_btn.setMinimumHeight(32)
        cap.addWidget(self.capture_btn, 1)
        self.capture_port = QSpinBox()
        self.capture_port.setRange(1024, 65535)
        self.capture_port.setValue(DEFAULT_PORT)
        self.capture_port.setPrefix(":")
        self.capture_port.setFixedWidth(78)
        self.capture_port.setToolTip("抓包端口")
        cap.addWidget(self.capture_port)
        self.sys_proxy_check = QCheckBox("系统代理")
        self.sys_proxy_check.setChecked(system_proxy_supported())
        self.sys_proxy_check.setEnabled(system_proxy_supported())
        self.sys_proxy_check.setToolTip(
            "会接管本机 HTTP(S)；列表只显示下方过滤后的流量。"
            "停止时自动恢复；若无流量请退出微信重开"
        )
        cap.addWidget(self.sys_proxy_check)
        layout.addLayout(cap)

        filt_row = QHBoxLayout()
        filt_row.setSpacing(6)
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText(
            "过滤：域名/关键字，逗号分隔；留空=全部。例: api.xxx.com, *.myapp.cn"
        )
        self.filter_edit.setToolTip(
            "只记录匹配的 URL/Host。支持子串与 *.example.com。"
            "改完即时生效；系统代理仍会转发其它流量，只是不写入列表。"
        )
        self.filter_edit.textChanged.connect(self._on_filter_changed)
        filt_row.addWidget(self.filter_edit, 1)
        self.noise_check = QCheckBox("屏蔽噪音")
        self.noise_check.setChecked(True)
        self.noise_check.setToolTip(
            "默认忽略 Windows/微软/谷歌/苹果等系统更新与常见广告域名"
        )
        self.noise_check.toggled.connect(self._on_filter_changed)
        filt_row.addWidget(self.noise_check)
        layout.addLayout(filt_row)

        # —— 解包列表（主操作） ——
        list_head = QHBoxLayout()
        self.list_label = QLabel("解包本机小程序")
        self.list_label.setObjectName("homeSectionTitle")
        list_head.addWidget(self.list_label, 1)
        self.refresh_btn = QPushButton("刷新")
        self.refresh_btn.clicked.connect(self.refresh_list)
        style_sidebar_aux_button(self.refresh_btn)
        set_btn_icon(self.refresh_btn, "refresh", size=14)
        list_head.addWidget(self.refresh_btn)
        add_btn = QPushButton("目录")
        add_btn.setToolTip("手动添加含 wx***** 的包根目录")
        add_btn.clicked.connect(self._add_root)
        style_sidebar_aux_button(add_btn)
        list_head.addWidget(add_btn)
        self.open_btn = QPushButton("输出")
        self.open_btn.setToolTip("打开解包输出目录")
        self.open_btn.clicked.connect(self._open_out)
        self.open_btn.setEnabled(False)
        style_sidebar_aux_button(self.open_btn)
        list_head.addWidget(self.open_btn)
        layout.addLayout(list_head)

        self.status = QLabel("点右侧「解包」即可反编译；建议再抓包，识别更准。")
        self.status.setWordWrap(True)
        style_muted_label(self.status)
        layout.addWidget(self.status)

        self.app_list = QListWidget()
        self.app_list.setSpacing(4)
        self.app_list.setUniformItemSizes(False)
        self.app_list.setStyleSheet(
            f"QListWidget {{ color: {C.get('text', '#e8eaed')}; background: {C.get('input_bg', '#171a1f')}; }}"
            f"QListWidget::item {{ padding: 0; margin: 0; border: none; background: transparent; color: {C.get('text', '#e8eaed')}; }}"
            f"QListWidget::item:selected {{ background: {C.get('selection', '#3a5068')}; }}"
            f"QListWidget::item:hover {{ background: {C.get('surface2', '#30363f')}; }}"
        )
        layout.addWidget(self.app_list, 1)

        detail_tabs = QTabWidget()
        self.flow_list = QListWidget()
        self.flow_list.setToolTip("抓到的小程序流量")
        self.flow_list.itemClicked.connect(self._on_local_flow_clicked)
        detail_tabs.addTab(self.flow_list, "流量")
        self.hit_list = QListWidget()
        self.hit_list.itemClicked.connect(self._preview_hit)
        detail_tabs.addTab(self.hit_list, "候选 JS")
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setPlaceholderText("点「候选 JS」预览")
        detail_tabs.addTab(self.preview, "预览")
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(1500)
        self.log_view.setPlaceholderText("解包 / 抓包日志")
        detail_tabs.addTab(self.log_view, "日志")
        detail_tabs.setMinimumHeight(250)
        layout.addWidget(detail_tabs)

        tip = QLabel("解包/抓包完成后，到右侧 Agent 页识别或生成代理")
        style_muted_label(tip)
        tip.setWordWrap(True)
        layout.addWidget(tip)

    def _log(self, text: str):
        self.log_view.appendPlainText(text)

    def _add_root(self):
        path = QFileDialog.getExistingDirectory(self, "选择小程序包根目录（内含 wx***** 文件夹）")
        if not path:
            return
        path = os.path.abspath(path)
        if path not in self._extra_roots:
            self._extra_roots.append(path)
        self.refresh_list()

    def refresh_list(self):
        self.app_list.clear()
        self.status.setText("正在扫描小程序…")
        from core.wxapkg import default_package_roots
        roots = list(default_package_roots()) + list(self._extra_roots)
        self._apps = discover_miniprograms(self._extra_roots or None)
        if not self._apps:
            self.list_label.setText("解包本机小程序（未找到）")
            self.status.setText(
                "未找到包：请先在微信打开目标小程序，再点「刷新」"
            )
            self._log("扫描目录:")
            for r in roots:
                self._log(f"  - {r}")
            if not roots:
                self._log("  (未发现任何微信包根目录)")
            return

        self.list_label.setText(f"解包本机小程序（{len(self._apps)} 个）")
        for info in self._apps:
            item = QListWidgetItem(self.app_list)
            row = _AppRow(info)
            row.unpack_clicked.connect(self._start_decompile)
            item.setSizeHint(row.sizeHint().expandedTo(QSize(100, 56)))
            self.app_list.addItem(item)
            self.app_list.setItemWidget(item, row)
        self.status.setText(f"已扫描 {len(self._apps)} 个 — 点「解包」反编译，建议配合抓包")
        self._log(f"刷新列表: {len(self._apps)} 个")

    def _set_rows_enabled(self, enabled: bool):
        self.app_list.setEnabled(enabled)
        self.refresh_btn.setEnabled(enabled)

    def _start_decompile(self, info: MiniprogramInfo):
        if self._busy:
            self._log("正在解包，请稍候…")
            return
        self._busy = True
        self._set_rows_enabled(False)
        self.open_btn.setEnabled(False)
        self.hit_list.clear()
        self.preview.clear()
        self.log_view.clear()
        title = info.display_name
        self.status.setText(f"正在解包 {title}…")
        self._log(f"解包: {title} ({info.appid})")
        self._log(f"路径: {info.path}")
        self._log(f"包数量: {info.pkg_count}")

        self._worker = _DecompileWorker(info.path, info.appid, self)
        self._worker.log.connect(self._log)
        self._worker.finished_ok.connect(self._on_done)
        self._worker.failed.connect(self._on_fail)
        self._worker.start()

    def _on_done(self, result):
        self._busy = False
        self._set_rows_enabled(True)
        self._last_result = result
        self.open_btn.setEnabled(True)
        self.status.setText(f"解包完成 → {result.out_dir}")
        self._log(f"输出: {result.out_dir}")
        self.hit_list.clear()
        for h in result.crypto_hits:
            item = QListWidgetItem(f"[{h.score}] {h.relpath}")
            item.setData(Qt.ItemDataRole.UserRole, h.path)
            self.hit_list.addItem(item)
        if not result.crypto_hits:
            self._log("未筛到明显加解密关键字，可到右侧 Agent 页「AI识别加解密」。")
        self._emit_scripts(silent=True)
        self._update_item_title(result.appid)

    def _update_item_title(self, appid: str):
        from core.wxapkg.pipeline import guess_miniprogram_title
        title = guess_miniprogram_title(appid)
        if not title:
            return
        for i, info in enumerate(self._apps):
            if info.appid != appid:
                continue
            info.title = title
            item = self.app_list.item(i)
            if item:
                row = self.app_list.itemWidget(item)
                if isinstance(row, _AppRow):
                    # 重建该行以刷新名称
                    new_row = _AppRow(info)
                    new_row.unpack_clicked.connect(self._start_decompile)
                    item.setSizeHint(new_row.sizeHint().expandedTo(QSize(100, 56)))
                    self.app_list.setItemWidget(item, new_row)
            break

    def _on_fail(self, err: str):
        self._busy = False
        self._set_rows_enabled(True)
        self.status.setText("解包失败")
        self._log(f"错误: {err}")
        QMessageBox.critical(self, "解包失败", err)

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
        if not self._last_result:
            return
        path = self._last_result.out_dir
        if not os.path.isdir(path):
            return
        if sys.platform == "win32":
            os.startfile(path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])

    def _collect_scripts(self) -> dict[str, str]:
        if not self._last_result:
            return {}
        scripts = self._last_result.scripts_for_ai()
        if scripts:
            return scripts
        from core.wxapkg.scanner import collect_crypto_scripts, scripts_as_dict
        hits = collect_crypto_scripts(self._last_result.out_dir, max_files=16)
        return scripts_as_dict(hits)

    def _emit_scripts(self, silent: bool = False) -> bool:
        if not self._last_result:
            if not silent:
                QMessageBox.information(self, "提示", "请先点击「解包」完成反编译")
            return False
        scripts = self._collect_scripts()
        if not scripts:
            if not silent:
                QMessageBox.warning(self, "提示", "没有可分析的 JS，请确认解包成功")
            return False
        meta = {
            "appid": self._last_result.appid,
            "out_dir": self._last_result.out_dir,
        }
        self.scripts_ready.emit(scripts, meta)
        self._log(f"已载入 {len(scripts)} 个脚本到分析区")
        return True

    # —— 抓包 ——
    def _on_filter_changed(self, *_args):
        if self._capture:
            self._capture.set_capture_filter(
                self.filter_edit.text().strip(),
                block_noise=self.noise_check.isChecked(),
            )

    def _toggle_capture(self):
        if self._capture and self._capture.running:
            self._stop_capture()
        else:
            self._start_capture()

    def _start_capture(self):
        if self._capture is None:
            self._capture = MiniprogramCaptureWorker(self)
            self._capture.flow_captured.connect(self._on_capture_flow)
            self._capture.flow_updated.connect(self._on_capture_flow_updated)
            self._capture.log.connect(self._on_capture_log)
            self._capture.started.connect(self._on_capture_started)
            self._capture.stopped.connect(self._on_capture_stopped)
            self._capture.failed.connect(self._on_capture_failed)
        port = int(self.capture_port.value())
        self._capture.start(
            port,
            use_system_proxy=self.sys_proxy_check.isChecked(),
            host_filter=self.filter_edit.text().strip(),
            block_noise=self.noise_check.isChecked(),
        )

    def _stop_capture(self):
        if self._capture:
            self._capture.stop()

    def _on_capture_started(self, port: int):
        self.capture_btn.setText("停止抓包")
        style_button(self.capture_btn, "danger")
        set_btn_icon(self.capture_btn, "stop", size=14)
        self.capture_port.setEnabled(False)
        self.sys_proxy_check.setEnabled(False)
        self.status.setText(f"抓包中 :{port} — 请打开微信小程序操作")
        self._log(f"抓包已启动 127.0.0.1:{port}")
        filt = self.filter_edit.text().strip()
        if filt:
            self._log(f"仅记录匹配: {filt}")
        if self.noise_check.isChecked():
            self._log("已屏蔽常见系统噪音域名")
        if self.sys_proxy_check.isChecked() and system_proxy_supported():
            self._log("已开启系统代理；若微信无流量，请完全退出微信后重开。")
            self._log("提示：系统代理仍会转发全机流量，列表只显示过滤后的请求。")

    def _on_capture_stopped(self):
        self.capture_btn.setText("启动抓包")
        style_button(self.capture_btn, "primary")
        set_btn_icon(self.capture_btn, "play", size=14)
        self.capture_port.setEnabled(True)
        self.sys_proxy_check.setEnabled(system_proxy_supported())
        self.status.setText(f"抓包已停止 · 本页流量 {self._local_flow_count} 条")

    def _on_capture_failed(self, err: str):
        self._log(f"抓包失败: {err}")
        QMessageBox.critical(self, "抓包失败", err)
        self._on_capture_stopped()

    def _on_capture_log(self, msg: str):
        self._log(msg)
        self.capture_log.emit(msg)

    def _on_capture_flow(self, flow: dict):
        self._local_flow_count += 1
        idx = flow.get("_index")
        if isinstance(idx, int):
            while len(self._local_flows) <= idx:
                self._local_flows.append({})
            self._local_flows[idx] = flow
        else:
            self._local_flows.append(flow)
            idx = len(self._local_flows) - 1
        pending = flow.get("status") == 0
        prefix = "… " if pending else ""
        item = QListWidgetItem(
            f"{prefix}{flow.get('method')} {str(flow.get('url', ''))[:70]}"
        )
        item.setData(Qt.ItemDataRole.UserRole, idx)
        self.flow_list.addItem(item)
        self.flow_captured.emit(flow)
        self.status.setText(f"抓包中 · 已采 {self._local_flow_count} 条")

    def _on_capture_flow_updated(self, flow: dict):
        idx = flow.get("_index")
        if isinstance(idx, int):
            while len(self._local_flows) <= idx:
                self._local_flows.append({})
            self._local_flows[idx] = flow
            if 0 <= idx < self.flow_list.count():
                item = self.flow_list.item(idx)
                if item:
                    item.setText(
                        f"[{flow.get('status')}] {flow.get('method')} "
                        f"{str(flow.get('url', ''))[:68]}"
                    )
        self.flow_updated.emit(flow)

    def _on_local_flow_clicked(self, item: QListWidgetItem):
        idx = item.data(Qt.ItemDataRole.UserRole)
        if isinstance(idx, int) and 0 <= idx < len(self._local_flows):
            self.flow_selected.emit(self._local_flows[idx])

    def clear_local_flows(self):
        self.flow_list.clear()
        self._local_flows.clear()
        self._local_flow_count = 0

    def stop_capture_if_running(self):
        if self._capture and self._capture.running:
            self._stop_capture()


MiniprogramTab = MiniprogramPanel
