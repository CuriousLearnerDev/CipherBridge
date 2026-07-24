"""密桥主页 — 状态概览与上手引导（扁平、少卡片）."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import (
    QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QSizePolicy, QVBoxLayout, QWidget,
)

from core.icon_loader import TOPOLOGY_IMAGE
from core.theme import C, style_button, style_muted_label


class _StatCell(QWidget):
    """状态条里的一格，无独立边框."""

    def __init__(self, label: str, parent=None):
        super().__init__(parent)
        self.setObjectName("homeStatCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(3)
        self._label = QLabel(label)
        style_muted_label(self._label)
        self._value = QLabel("—")
        self._value.setObjectName("homeStatValue")
        layout.addWidget(self._label)
        layout.addWidget(self._value)

    def set_value(self, text: str, *, running: bool | None = None) -> None:
        self._value.setText(text)
        if running is True:
            self._value.setStyleSheet(
                f"color:{C.get('ok', C['primary'])}; font-weight:600; background:transparent;"
            )
        elif running is False:
            self._value.setStyleSheet(f"color:{C['text_dim']}; background:transparent;")
        else:
            self._value.setStyleSheet("background:transparent;")


class HomeTab(QWidget):
    """工具主页."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._routes: dict[str, QWidget] = {}
        self._tab_widget = None
        self._build_ui()

    def bind_tabs(self, tab_widget, routes: dict[str, QWidget]) -> None:
        self._tab_widget = tab_widget
        self._routes = routes

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        body = QWidget()
        root = QVBoxLayout(body)
        root.setContentsMargins(28, 22, 28, 28)
        root.setSpacing(16)

        root.addWidget(self._section("运行状态"))
        strip = QFrame()
        strip.setObjectName("homeStatStrip")
        stat_row = QHBoxLayout(strip)
        stat_row.setContentsMargins(0, 0, 0, 0)
        stat_row.setSpacing(0)
        self.chip_project = _StatCell("当前项目")
        self.chip_decrypt = _StatCell("解密端")
        self.chip_encrypt = _StatCell("加密端")
        self.chip_cert = _StatCell("HTTPS 证书")
        cells = (self.chip_project, self.chip_decrypt, self.chip_encrypt, self.chip_cert)
        for i, chip in enumerate(cells):
            chip.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            stat_row.addWidget(chip)
            if i < len(cells) - 1:
                sep = QFrame()
                sep.setObjectName("homeStatSep")
                sep.setFixedWidth(1)
                stat_row.addWidget(sep)
        root.addWidget(strip)

        root.addWidget(self._section("部署拓扑"))
        self._topo_label = QLabel()
        self._topo_label.setObjectName("homeTopology")
        self._topo_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self._topo_pixmap = QPixmap(TOPOLOGY_IMAGE)
        self._update_topology_image()
        root.addWidget(self._topo_label)

        root.addWidget(self._section("上手"))
        flow = QFrame()
        flow.setObjectName("homeWorkflow")
        fl = QGridLayout(flow)
        fl.setContentsMargins(0, 4, 0, 4)
        fl.setHorizontalSpacing(10)
        fl.setVerticalSpacing(8)
        steps = [
            ("01", "解析报文", "请求解析器粘贴抓包，点选密文字段"),
            ("02", "组装步骤", "可视化构建器调序，预览生成代码"),
            ("03", "保存项目", "保存后在左侧控制面板选择项目"),
            ("04", "启动代理", "启停解密/加密端，配置浏览器代理"),
        ]
        for row, (num, st, sd) in enumerate(steps):
            badge = QLabel(num)
            badge.setObjectName("homeStepBadge")
            badge.setFixedWidth(22)
            badge.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
            st_lbl = QLabel(st)
            st_lbl.setObjectName("homeCardTitle")
            sd_lbl = QLabel(sd)
            sd_lbl.setWordWrap(True)
            style_muted_label(sd_lbl)
            fl.addWidget(badge, row, 0, Qt.AlignmentFlag.AlignTop)
            st_col = QVBoxLayout()
            st_col.setSpacing(1)
            st_col.addWidget(st_lbl)
            st_col.addWidget(sd_lbl)
            fl.addLayout(st_col, row, 1)
        root.addWidget(flow)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        btn_parser = QPushButton("解析报文")
        btn_parser.clicked.connect(lambda: self._go("parser"))
        style_button(btn_parser, "primary")
        btn_builder = QPushButton("打开构建器")
        btn_builder.clicked.connect(lambda: self._go("builder"))
        style_button(btn_builder, "ghost")
        btn_row.addWidget(btn_parser)
        btn_row.addWidget(btn_builder)
        btn_row.addStretch()
        root.addLayout(btn_row)
        root.addStretch()

        scroll.setWidget(body)
        outer.addWidget(scroll)

    @staticmethod
    def _section(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName("homeSectionTitle")
        return lbl

    def _go(self, key: str) -> None:
        target = self._routes.get(key)
        if target is None or self._tab_widget is None:
            return
        nested = {
            "crypto": ("settings", 1),
            "log": ("settings", 2),
        }
        if key in nested:
            settings = self._routes.get("settings")
            page = nested[key][1]
            win = self.window()
            if win is not None and hasattr(win, "open_settings_hub"):
                win.open_settings_hub(page)
                return
            if settings is not None:
                idx = self._tab_widget.indexOf(settings)
                if idx >= 0:
                    self._tab_widget.setCurrentIndex(idx)
                    if hasattr(settings, "show_page"):
                        settings.show_page(page)
                return
        idx = self._tab_widget.indexOf(target)
        if idx >= 0:
            self._tab_widget.setCurrentIndex(idx)

    def refresh_status(self, control) -> None:
        if control is None:
            return

        name = control.profile_combo.currentText() if hasattr(control, "profile_combo") else ""
        self.chip_project.set_value(name or "未选择")

        dec_running = "运行中" in control.decrypt_status.text()
        dec_port = control.decrypt_port.value() if hasattr(control, "decrypt_port") else "?"
        self.chip_decrypt.set_value(
            f"{'运行' if dec_running else '停止'}  :{dec_port}",
            running=dec_running,
        )

        enc_running = "运行中" in control.encrypt_status.text()
        enc_port = control.encrypt_port.value() if hasattr(control, "encrypt_port") else "?"
        self.chip_encrypt.set_value(
            f"{'运行' if enc_running else '停止'}  :{enc_port}",
            running=enc_running,
        )

        cert_text = control.cert_status.text() if hasattr(control, "cert_status") else ""
        trusted = "已安装" in cert_text
        self.chip_cert.set_value(
            "已安装" if trusted else ("未安装" if cert_text else "—"),
            running=trusted if cert_text else None,
        )

    def _update_topology_image(self) -> None:
        if self._topo_pixmap.isNull():
            self._topo_label.setText(
                "浏览器/APP → 解密端(:8080) → Burp(:8083) → 加密端(:8081) → 服务器"
            )
            return
        w = max(420, self.width() - 80)
        self._topo_label.setPixmap(
            self._topo_pixmap.scaledToWidth(w, Qt.TransformationMode.SmoothTransformation)
        )

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if hasattr(self, "_topo_label"):
            self._update_topology_image()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._update_topology_image()
        win = self.window()
        if win and hasattr(win, "control"):
            self.refresh_status(win.control)
