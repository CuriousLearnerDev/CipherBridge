"""密桥主页 — 状态 + 上手 + 拓扑示意图。"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QPushButton,
    QSizePolicy, QVBoxLayout, QWidget,
)

from core.brand import APP_NAME, APP_SUBTITLE
from core.icon_loader import TOPOLOGY_IMAGE, set_btn_icon
from core.theme import style_button


class _StatusCell(QWidget):
    def __init__(self, label: str, parent=None):
        super().__init__(parent)
        self.setObjectName("homeStatusCell")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 8, 12, 8)
        lay.setSpacing(2)
        self._label = QLabel(label)
        self._label.setObjectName("homeMetaLabel")
        self._value = QLabel("—")
        self._value.setObjectName("homeMetaValue")
        lay.addWidget(self._label)
        lay.addWidget(self._value)

    def set_value(self, text: str, *, running: bool | None = None) -> None:
        self._value.setText(text)
        if running is True:
            self._value.setProperty("state", "running")
        elif running is False:
            self._value.setProperty("state", "stopped")
        else:
            self._value.setProperty("state", "")
        self._value.style().unpolish(self._value)
        self._value.style().polish(self._value)


class HomeTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("homePage")
        self._routes: dict[str, QWidget] = {}
        self._tab_widget = None
        self._build_ui()

    def bind_tabs(self, tab_widget, routes: dict[str, QWidget]) -> None:
        self._tab_widget = tab_widget
        self._routes = routes

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        # 顶行：标题 + 入口（无大卡片边框）
        top = QHBoxLayout()
        top.setSpacing(10)
        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title = QLabel(APP_NAME)
        title.setObjectName("homeTitle")
        title_col.addWidget(title)
        sub = QLabel(APP_SUBTITLE)
        sub.setObjectName("homeSub")
        title_col.addWidget(sub)
        top.addLayout(title_col, 1)
        for text, key, icon_name, variant in (
            ("解析报文", "parser", "parser", "primary"),
            ("可视化构建", "builder", "builder", "default"),
            ("AI 分析", "ai", "ai", "default"),
        ):
            b = QPushButton(text)
            style_button(b, variant, size="sm")
            try:
                set_btn_icon(b, icon_name, size=13)
            except Exception:
                pass
            b.clicked.connect(lambda _=False, k=key: self._go(k))
            top.addWidget(b, 0, Qt.AlignmentFlag.AlignVCenter)
        root.addLayout(top)

        # 状态一行
        strip = QFrame()
        strip.setObjectName("homeStatusStrip")
        strip_row = QHBoxLayout(strip)
        strip_row.setContentsMargins(2, 2, 2, 2)
        strip_row.setSpacing(0)
        self.chip_project = _StatusCell("项目")
        self.chip_decrypt = _StatusCell("解密端")
        self.chip_encrypt = _StatusCell("加密端")
        self.chip_cert = _StatusCell("证书")
        self._status_seps: list[QFrame] = []
        cells = (self.chip_project, self.chip_decrypt, self.chip_encrypt, self.chip_cert)
        for i, cell in enumerate(cells):
            cell.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            strip_row.addWidget(cell)
            if i < len(cells) - 1:
                sep = QFrame()
                sep.setObjectName("homeStatusSep")
                sep.setFixedWidth(1)
                sep.setFixedHeight(30)
                strip_row.addWidget(sep, 0, Qt.AlignmentFlag.AlignVCenter)
                self._status_seps.append(sep)
        root.addWidget(strip)

        # 上手：横向三步，不占大块竖空
        steps = QFrame()
        steps.setObjectName("homeStepsBar")
        sl = QHBoxLayout(steps)
        sl.setContentsMargins(4, 4, 4, 4)
        sl.setSpacing(8)
        for num, title, desc, route in (
            ("1", "解析报文", "粘贴抓包，点选字段", "parser"),
            ("2", "组装步骤", "构建器调序并保存", "builder"),
            ("3", "启动代理", "左侧启停解密/加密", None),
        ):
            card = QFrame()
            card.setObjectName("homeStepCard")
            cl = QHBoxLayout(card)
            cl.setContentsMargins(10, 8, 10, 8)
            cl.setSpacing(8)
            badge = QLabel(num)
            badge.setObjectName("homeStepNum")
            badge.setFixedSize(22, 22)
            badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            cl.addWidget(badge)
            col = QVBoxLayout()
            col.setSpacing(1)
            t = QLabel(title)
            t.setObjectName("homeStepTitle")
            d = QLabel(desc)
            d.setObjectName("homeStepDesc")
            col.addWidget(t)
            col.addWidget(d)
            cl.addLayout(col, 1)
            if route:
                go = QPushButton("打开")
                style_button(go, "ghost", size="sm")
                go.clicked.connect(lambda _=False, k=route: self._go(k))
                cl.addWidget(go)
            sl.addWidget(card, 1)
        root.addWidget(steps)

        # 结构图：链路标签 + 拓扑大图（主视觉）
        topo = QFrame()
        topo.setObjectName("homeTopoPanel")
        tl = QVBoxLayout(topo)
        tl.setContentsMargins(14, 12, 14, 14)
        tl.setSpacing(10)

        topo_head = QHBoxLayout()
        topo_head.addWidget(self._caption("部署结构"))
        topo_head.addStretch(1)
        path = QLabel("客户端 → 解密端 → Burp → 加密端 → 服务器")
        path.setObjectName("homeTopoPath")
        topo_head.addWidget(path)
        tl.addLayout(topo_head)

        self._topo_label = QLabel()
        self._topo_label.setObjectName("homeTopology")
        self._topo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._topo_label.setMinimumHeight(220)
        self._topo_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self._topo_pixmap = QPixmap(TOPOLOGY_IMAGE)
        if self._topo_pixmap.isNull():
            self._topo_label.setText(
                "客户端 → 解密端(:8083) → Burp(:8080) → 加密端(:8081) → 服务器"
            )
        else:
            self._update_topology_image()
        tl.addWidget(self._topo_label, 1)
        root.addWidget(topo, 1)

    @staticmethod
    def _caption(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName("homeCaption")
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

        roles = []
        if name and hasattr(control, "_profile_roles"):
            roles = control._profile_roles(name)

        dec_running = "运行中" in control.decrypt_status.text()
        dec_port = control.decrypt_port.value() if hasattr(control, "decrypt_port") else "?"
        has_decrypt = (not name) or ("decrypt" in roles) or dec_running
        self.chip_decrypt.setVisible(has_decrypt)
        if has_decrypt:
            self.chip_decrypt.set_value(
                f":{dec_port}  {'运行中' if dec_running else '已停止'}",
                running=dec_running,
            )

        enc_running = "运行中" in control.encrypt_status.text()
        enc_port = control.encrypt_port.value() if hasattr(control, "encrypt_port") else "?"
        has_encrypt = ("encrypt" in roles) or enc_running
        self.chip_encrypt.setVisible(has_encrypt)
        if has_encrypt:
            self.chip_encrypt.set_value(
                f":{enc_port}  {'运行中' if enc_running else '已停止'}",
                running=enc_running,
            )

        if len(self._status_seps) >= 3:
            self._status_seps[0].setVisible(self.chip_decrypt.isVisible())
            self._status_seps[1].setVisible(self.chip_encrypt.isVisible())

        cert_text = control.cert_status.text() if hasattr(control, "cert_status") else ""
        trusted = "已安装" in cert_text
        self.chip_cert.set_value(
            "已安装" if trusted else ("未安装" if cert_text else "—"),
            running=trusted if cert_text else None,
        )

    def _update_topology_image(self) -> None:
        if self._topo_pixmap.isNull() or not hasattr(self, "_topo_label"):
            return
        # 尽量铺满可用区域，作为主视觉
        max_w = max(420, self.width() - 80)
        max_h = max(200, self.height() - 280)
        pm = self._topo_pixmap.scaled(
            max_w,
            max_h,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self._topo_label.setPixmap(pm)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._update_topology_image()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._update_topology_image()
        win = self.window()
        if win and hasattr(win, "control"):
            self.refresh_status(win.control)
