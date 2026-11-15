"""匹配规则编辑对话框."""

from __future__ import annotations

import os

from PyQt6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QGroupBox,
    QHBoxLayout, QLabel, QMessageBox, QPlainTextEdit, QPushButton, QVBoxLayout,
)

from core.pac_generator import generate_pac
from core.profile_match import load_match_rules, regenerate_plugin_with_match, save_match_rules
from core.paths import get_app_root

ROOT = get_app_root()
PROFILES_DIR = os.path.join(ROOT, "profiles")

_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD")


class MatchRulesDialog(QDialog):
    """手动配置哪些请求走代理 / 加解密."""

    def __init__(self, profile_name: str, proxy_port: int = 8080, parent=None):
        super().__init__(parent)
        self.profile_name = profile_name
        self.proxy_port = proxy_port
        self.setWindowTitle(f"设置匹配解码的流量 — {profile_name}")
        self.setMinimumWidth(480)
        self._build_ui()
        self._load_rules()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        hint = QLabel(
            "只有命中下列规则的请求才会解码处理。\n"
            "配合「导出 PAC」可让浏览器仅把这些流量送进代理，其余直连。"
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)

        form = QFormLayout()
        self.host_edit = QPlainTextEdit()
        self.host_edit.setPlaceholderText("每行一个域名，例如:\napi.example.com\n*.example.com")
        self.host_edit.setFixedHeight(90)
        form.addRow("域名 host:", self.host_edit)

        self.path_edit = QPlainTextEdit()
        self.path_edit.setPlaceholderText("每行一个路径，支持 * 通配，例如:\n/api/*\n/authlogin/*")
        self.path_edit.setFixedHeight(90)
        form.addRow("路径 path:", self.path_edit)
        layout.addLayout(form)

        method_grp = QGroupBox("HTTP 方法")
        m_layout = QHBoxLayout(method_grp)
        self.method_boxes: dict[str, QCheckBox] = {}
        for m in _METHODS:
            cb = QCheckBox(m)
            self.method_boxes[m] = cb
            m_layout.addWidget(cb)
        layout.addWidget(method_grp)

        pac_row = QHBoxLayout()
        self.export_pac_btn = QPushButton("导出 PAC 分流脚本")
        self.export_pac_btn.setToolTip(
            "生成 .pac 文件，在浏览器或 SwitchyOmega 中配置后，\n"
            "只有匹配的 URL 会走解密代理，其他网站直连。"
        )
        self.export_pac_btn.clicked.connect(self._export_pac)
        pac_row.addWidget(self.export_pac_btn)
        pac_row.addStretch()
        layout.addLayout(pac_row)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel,
        )
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("保存")
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _load_rules(self) -> None:
        match = load_match_rules(self.profile_name)
        hosts = match.get("host") or []
        paths = match.get("path") or []
        methods = {m.upper() for m in (match.get("methods") or [])}

        self.host_edit.setPlainText("\n".join(hosts))
        self.path_edit.setPlainText("\n".join(paths))

        for m, cb in self.method_boxes.items():
            if methods:
                cb.setChecked(m in methods)
            else:
                cb.setChecked(m in ("GET", "POST"))

    def _collect_match(self) -> dict:
        hosts = [ln.strip() for ln in self.host_edit.toPlainText().splitlines() if ln.strip()]
        paths = [ln.strip() for ln in self.path_edit.toPlainText().splitlines() if ln.strip()]
        methods = [m for m, cb in self.method_boxes.items() if cb.isChecked()]

        if not hosts:
            raise ValueError("请至少填写一个域名")
        if not methods:
            raise ValueError("请至少选择一种 HTTP 方法")

        match: dict = {"host": hosts, "methods": methods}
        if paths:
            match["path"] = paths
        return match

    def _save(self) -> None:
        try:
            match = self._collect_match()
            save_match_rules(self.profile_name, match)
            regen = regenerate_plugin_with_match(self.profile_name)
            msg = "匹配规则已保存。"
            if regen:
                msg += "\nplugin.py 已按新规则重新生成。"
            else:
                msg += "\n（暂无加解密步骤，未更新 plugin.py）"
            QMessageBox.information(self, "已保存", msg)
            self.accept()
        except Exception as e:
            QMessageBox.warning(self, "保存失败", str(e))

    def _export_pac(self) -> None:
        try:
            match = self._collect_match()
        except Exception as e:
            QMessageBox.warning(self, "提示", str(e))
            return

        pac = generate_pac(match, self.proxy_port)
        pac_path = os.path.join(PROFILES_DIR, f"{self.profile_name}_proxy.pac")
        with open(pac_path, "w", encoding="utf-8") as f:
            f.write(pac)

        QMessageBox.information(
            self, "PAC 已导出",
            f"文件: {pac_path}\n\n"
            f"用法:\n"
            f"1. Chrome: 设置 → 系统 → 打开代理设置 → 使用 PAC 脚本\n"
            f"   或安装 SwitchyOmega，情景模式选 PAC，填入上述路径\n"
            f"2. 仅匹配的 URL 会走 127.0.0.1:{self.proxy_port}\n"
            f"3. 其余网站直连，不经过 mitmdump\n\n"
            f"注意: 修改匹配规则后请重新导出 PAC。",
        )
