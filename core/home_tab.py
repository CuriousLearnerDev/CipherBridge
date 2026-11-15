"""密桥主页 — 部署拓扑示意图。"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel,
    QSizePolicy, QVBoxLayout, QWidget,
)

from core.icon_loader import TOPOLOGY_IMAGE


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
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(8)

        topo = QFrame()
        topo.setObjectName("homeTopoPanel")
        tl = QVBoxLayout(topo)
        tl.setContentsMargins(8, 8, 8, 8)
        tl.setSpacing(8)

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

    def refresh_status(self, control) -> None:
        """兼容旧调用；状态已在左侧控制面板展示。"""
        return

    def _update_topology_image(self) -> None:
        if self._topo_pixmap.isNull() or not hasattr(self, "_topo_label"):
            return
        max_w = max(420, self.width() - 40)
        max_h = max(260, self.height() - 80)
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
