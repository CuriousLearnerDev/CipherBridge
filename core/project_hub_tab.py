"""项目管理 Tab — 列出 / 切换 / 新建 / 导入导出项目，点选即可预览 plugin.py。"""

from __future__ import annotations

import os
from typing import Any

import yaml
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from core.icon_loader import set_btn_icon
from core.paths import get_app_root
from core.theme import setup_code_editor, style_button, style_muted_label


def _role_label(roles: list) -> str:
    has_d = "decrypt" in roles
    has_e = "encrypt" in roles
    if has_d and has_e:
        return "解密 · 加密"
    if has_d:
        return "解密"
    if has_e:
        return "加密"
    return "未设角色"


class _Chip(QLabel):
    """小标签：角色 / 状态 / 文件存在。"""

    def __init__(self, text: str = "", *, kind: str = "", parent=None):
        super().__init__(text, parent)
        self.setObjectName("projectHubChip")
        self.setProperty("kind", kind)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)

    def set_chip(self, text: str, kind: str = "") -> None:
        self.setText(text)
        self.setProperty("kind", kind)
        self.style().unpolish(self)
        self.style().polish(self)
        self.setVisible(bool(text))


class _ProjectRow(QWidget):
    """列表行：名称 + 角色芯片 + 当前标记。"""

    def __init__(self, name: str, role_txt: str, is_current: bool, parent=None):
        super().__init__(parent)
        self.setObjectName("projectHubRow")
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 8, 10, 8)
        lay.setSpacing(8)

        col = QVBoxLayout()
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(3)
        self.name_lab = QLabel(name)
        self.name_lab.setObjectName("projectHubRowName")
        col.addWidget(self.name_lab)
        self.meta_lab = QLabel(role_txt)
        self.meta_lab.setObjectName("projectHubRowMeta")
        col.addWidget(self.meta_lab)
        lay.addLayout(col, 1)

        self.cur_chip = _Chip("当前", kind="current")
        self.cur_chip.setVisible(is_current)
        lay.addWidget(self.cur_chip, 0, Qt.AlignmentFlag.AlignVCenter)


class _MetaCell(QWidget):
    def __init__(self, label: str, parent=None):
        super().__init__(parent)
        self.setObjectName("projectHubMetaCell")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 8, 10, 8)
        lay.setSpacing(2)
        self._label = QLabel(label)
        self._label.setObjectName("projectHubMetaLabel")
        self._value = QLabel("—")
        self._value.setObjectName("projectHubMetaValue")
        self._value.setWordWrap(True)
        lay.addWidget(self._label)
        lay.addWidget(self._value)

    def set_value(self, text: str) -> None:
        self._value.setText(text or "—")


class ProjectHubTab(QWidget):
    """主导航「项目管理」：集中管理 profiles + plugins。"""

    def __init__(self, control, parent=None):
        super().__init__(parent)
        self.control = control
        self.setObjectName("projectHubPage")
        self._profiles_dir = os.path.join(get_app_root(), "profiles")
        self._plugins_dir = os.path.join(get_app_root(), "plugins")
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(12)

        head = QHBoxLayout()
        head.setSpacing(10)
        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title = QLabel("项目管理")
        title.setObjectName("projectHubTitle")
        title_col.addWidget(title)
        tip = QLabel("点选预览 plugin.py · 双击或「切换到此项目」同步左侧控制面板")
        tip.setObjectName("projectHubSub")
        tip.setWordWrap(True)
        title_col.addWidget(tip)
        head.addLayout(title_col, 1)

        self.refresh_btn = QPushButton("刷新")
        style_button(self.refresh_btn, "ghost", size="sm")
        try:
            set_btn_icon(self.refresh_btn, "refresh", size=14)
        except Exception:
            pass
        self.refresh_btn.clicked.connect(self.refresh)
        head.addWidget(self.refresh_btn, 0, Qt.AlignmentFlag.AlignTop)
        root.addLayout(head)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.setObjectName("projectHubSplit")
        split.setChildrenCollapsible(False)

        # ── 左侧：项目列表 ───────────────────────────
        left = QFrame()
        left.setObjectName("projectHubListPane")
        left.setProperty("card", True)
        left_l = QVBoxLayout(left)
        left_l.setContentsMargins(0, 0, 0, 0)
        left_l.setSpacing(0)

        list_head = QHBoxLayout()
        list_head.setContentsMargins(12, 10, 12, 8)
        list_head.setSpacing(6)
        list_title = QLabel("项目")
        list_title.setObjectName("projectHubSection")
        list_head.addWidget(list_title)
        self.count_lab = QLabel("0")
        self.count_lab.setObjectName("projectHubCount")
        list_head.addWidget(self.count_lab)
        list_head.addStretch(1)
        left_l.addLayout(list_head)

        self.list = QListWidget()
        self.list.setObjectName("projectHubList")
        self.list.setSpacing(4)
        self.list.setUniformItemSizes(False)
        self.list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.list.itemSelectionChanged.connect(self._on_sel)
        self.list.itemDoubleClicked.connect(self._activate_current)
        left_l.addWidget(self.list, 1)
        split.addWidget(left)

        # ── 右侧：详情 + 代码 ─────────────────────────
        right = QWidget()
        right_l = QVBoxLayout(right)
        right_l.setContentsMargins(0, 0, 0, 0)
        right_l.setSpacing(10)

        meta = QFrame()
        meta.setObjectName("projectHubMetaStrip")
        meta_row = QHBoxLayout(meta)
        meta_row.setContentsMargins(0, 0, 0, 0)
        meta_row.setSpacing(0)
        self.cell_name = _MetaCell("名称")
        self.cell_roles = _MetaCell("角色")
        self.cell_plugin = _MetaCell("插件目录")
        self.cell_files = _MetaCell("文件")
        self.cell_match = _MetaCell("匹配")
        self._meta_cells = (
            self.cell_name,
            self.cell_roles,
            self.cell_plugin,
            self.cell_files,
            self.cell_match,
        )
        self._meta_seps: list[QFrame] = []
        for i, cell in enumerate(self._meta_cells):
            cell.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            meta_row.addWidget(cell)
            if i < len(self._meta_cells) - 1:
                sep = QFrame()
                sep.setObjectName("projectHubMetaSep")
                sep.setFixedWidth(1)
                sep.setFixedHeight(36)
                meta_row.addWidget(sep, 0, Qt.AlignmentFlag.AlignVCenter)
                self._meta_seps.append(sep)
        right_l.addWidget(meta)

        status_row = QHBoxLayout()
        status_row.setContentsMargins(2, 0, 2, 0)
        status_row.setSpacing(6)
        self.status_chip = _Chip("", kind="")
        self.status_chip.hide()
        status_row.addWidget(self.status_chip)
        self.desc_lab = QLabel("")
        self.desc_lab.setObjectName("projectHubDesc")
        self.desc_lab.setWordWrap(True)
        style_muted_label(self.desc_lab)
        status_row.addWidget(self.desc_lab, 1)
        right_l.addLayout(status_row)

        code_pane = QFrame()
        code_pane.setObjectName("projectHubCodePane")
        code_pane.setProperty("card", True)
        code_l = QVBoxLayout(code_pane)
        code_l.setContentsMargins(0, 0, 0, 0)
        code_l.setSpacing(0)

        code_head = QHBoxLayout()
        code_head.setContentsMargins(12, 8, 10, 8)
        code_head.setSpacing(8)
        code_mark = QLabel("CODE")
        code_mark.setObjectName("projectHubCodeMark")
        code_head.addWidget(code_mark)
        self.code_title = QLabel("plugin.py")
        self.code_title.setObjectName("projectHubCodeTitle")
        code_head.addWidget(self.code_title, 1)
        self.open_file_btn = QPushButton("外部打开")
        style_button(self.open_file_btn, "ghost", size="sm")
        try:
            set_btn_icon(self.open_file_btn, "open", size=13)
        except Exception:
            pass
        self.open_file_btn.clicked.connect(self._open_external)
        code_head.addWidget(self.open_file_btn)
        code_l.addLayout(code_head)

        line = QFrame()
        line.setObjectName("projectHubCodeLine")
        line.setFixedHeight(1)
        code_l.addWidget(line)

        self.code_view = QPlainTextEdit()
        self.code_view.setObjectName("codeEditor")
        self.code_view.setReadOnly(True)
        self.code_view.setPlaceholderText("点选左侧项目后，这里显示 plugins/{name}/plugin.py")
        self.code_view.setFrameShape(QFrame.Shape.NoFrame)
        setup_code_editor(self.code_view)
        code_l.addWidget(self.code_view, 1)
        right_l.addWidget(code_pane, 1)

        split.addWidget(right)
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 5)
        split.setSizes([300, 700])
        root.addWidget(split, 1)

        # ── 底部操作 ────────────────────────────────
        actions = QFrame()
        actions.setObjectName("projectHubActions")
        row = QHBoxLayout(actions)
        row.setContentsMargins(0, 2, 0, 0)
        row.setSpacing(8)

        self.new_btn = QPushButton("新建")
        style_button(self.new_btn, "primary", size="sm")
        try:
            set_btn_icon(self.new_btn, "add", size=14)
        except Exception:
            pass
        self.new_btn.clicked.connect(self._new)
        row.addWidget(self.new_btn)

        self.use_btn = QPushButton("切换到此项目")
        style_button(self.use_btn, "default", size="sm")
        self.use_btn.clicked.connect(self._activate_current)
        row.addWidget(self.use_btn)

        self.edit_btn = QPushButton("编辑配置")
        style_button(self.edit_btn, "ghost", size="sm")
        self.edit_btn.setToolTip("用系统编辑器打开 profiles/{name}.yaml")
        self.edit_btn.clicked.connect(self._edit)
        row.addWidget(self.edit_btn)

        self.export_btn = QPushButton("导出…")
        style_button(self.export_btn, "ghost", size="sm")
        self.export_btn.clicked.connect(self._export)
        row.addWidget(self.export_btn)

        self.import_btn = QPushButton("导入…")
        style_button(self.import_btn, "ghost", size="sm")
        self.import_btn.clicked.connect(self._import)
        row.addWidget(self.import_btn)

        row.addStretch(1)

        self.del_btn = QPushButton("删除")
        style_button(self.del_btn, "danger", size="sm")
        try:
            set_btn_icon(self.del_btn, "delete", size=13)
        except Exception:
            pass
        self.del_btn.clicked.connect(self._delete)
        row.addWidget(self.del_btn)

        root.addWidget(actions)

        self._current_plugin_py = ""
        self._sync_actions(False)
        self._clear_detail()

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self.refresh()

    def refresh(self) -> None:
        current = ""
        if self.control is not None and hasattr(self.control, "profile_combo"):
            current = self.control.profile_combo.currentText() or ""
        names = self._list_names()
        self.count_lab.setText(str(len(names)))
        prev = self._selected_name()
        self.list.blockSignals(True)
        self.list.clear()
        sel_row = -1
        for i, name in enumerate(names):
            info = self._load_info(name)
            roles = info.get("roles") or []
            role_txt = _role_label(roles if isinstance(roles, list) else [])
            is_cur = name == current
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, name)
            row = _ProjectRow(name, role_txt, is_cur)
            item.setSizeHint(row.sizeHint().expandedTo(row.minimumSizeHint()))
            # 给一点固定高度，避免首屏 sizeHint 过小
            hint = item.sizeHint()
            if hint.height() < 48:
                hint.setHeight(52)
            item.setSizeHint(hint)
            self.list.addItem(item)
            self.list.setItemWidget(item, row)
            if name == prev or (sel_row < 0 and is_cur):
                sel_row = i
        self.list.blockSignals(False)
        if sel_row < 0 and self.list.count():
            sel_row = 0
        if sel_row >= 0:
            self.list.setCurrentRow(sel_row)
        else:
            self._clear_detail()
            self._sync_actions(False)

    def _clear_detail(self) -> None:
        self.cell_name.set_value("—")
        self.cell_roles.set_value("—")
        self.cell_plugin.set_value("—")
        self.cell_files.set_value("—")
        self.cell_match.set_value("—")
        self.status_chip.hide()
        self.desc_lab.setText("暂无项目。点「新建」或「导入…」开始。" if not self.list.count() else "选择一个项目查看详情与代码")
        self.code_view.setPlainText("")
        self.code_title.setText("plugin.py")
        self._current_plugin_py = ""

    def _list_names(self) -> list[str]:
        if not os.path.isdir(self._profiles_dir):
            return []
        out = []
        for f in sorted(os.listdir(self._profiles_dir)):
            if f.endswith(".yaml") and not f.startswith("_"):
                out.append(f[:-5])
        return out

    def _load_info(self, name: str) -> dict[str, Any]:
        path = os.path.join(self._profiles_dir, f"{name}.yaml")
        if not os.path.isfile(path):
            return {}
        try:
            with open(path, encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
            return cfg if isinstance(cfg, dict) else {}
        except Exception:
            return {}

    def _plugin_py_path(self, name: str) -> str:
        info = self._load_info(name)
        plugin = str(info.get("plugin") or name)
        return os.path.join(self._plugins_dir, plugin, "plugin.py")

    def _selected_name(self) -> str:
        item = self.list.currentItem()
        if not item:
            return ""
        return str(item.data(Qt.ItemDataRole.UserRole) or "")

    def _on_sel(self) -> None:
        name = self._selected_name()
        self._sync_actions(bool(name))
        if not name:
            self._clear_detail()
            return
        info = self._load_info(name)
        plugin = str(info.get("plugin") or name)
        roles = info.get("roles") or []
        if not isinstance(roles, list):
            roles = []
        desc = str(info.get("description") or "").strip()
        plugin_py = os.path.join(self._plugins_dir, plugin, "plugin.py")
        state_js = os.path.join(self._plugins_dir, plugin, "state.json")
        has_py = os.path.isfile(plugin_py)
        has_state = os.path.isfile(state_js)

        self.cell_name.set_value(name)
        self.cell_roles.set_value(_role_label(roles))
        self.cell_plugin.set_value(f"plugins/{plugin}/")
        files = []
        files.append("plugin.py ✓" if has_py else "plugin.py 缺失")
        files.append("state.json ✓" if has_state else "state.json —")
        self.cell_files.set_value(" · ".join(files))

        match = info.get("match") if isinstance(info.get("match"), dict) else {}
        hosts = match.get("host") or []
        paths = match.get("path") or []
        match_bits = []
        if hosts:
            match_bits.append("host=" + ",".join(str(h) for h in hosts[:3]))
        if paths:
            match_bits.append("path=" + ",".join(str(p) for p in paths[:3]))
        self.cell_match.set_value(" · ".join(match_bits) if match_bits else "未限制")

        cur = ""
        if self.control is not None and hasattr(self.control, "profile_combo"):
            cur = self.control.profile_combo.currentText() or ""
        if name == cur:
            self.status_chip.set_chip("当前使用中", "current")
            self.status_chip.show()
        else:
            self.status_chip.hide()
        self.desc_lab.setText(desc if desc else "（无描述）")

        self._current_plugin_py = plugin_py
        self.code_title.setText(f"plugins/{plugin}/plugin.py")
        if has_py:
            try:
                with open(plugin_py, encoding="utf-8") as f:
                    code = f.read()
            except Exception as e:
                code = f"# 读取失败: {e}"
            self.code_view.setPlainText(code)
        else:
            self.code_view.setPlainText(
                f"# 未找到 {plugin_py}\n"
                "# 请在可视化构建器保存步骤，或新建项目生成空白模板。"
            )

    def _sync_actions(self, has: bool) -> None:
        for b in (
            self.use_btn,
            self.edit_btn,
            self.export_btn,
            self.del_btn,
            self.open_file_btn,
        ):
            b.setEnabled(has)

    def _ensure_selected_on_combo(self) -> str:
        name = self._selected_name()
        if not name or self.control is None:
            return name
        combo = self.control.profile_combo
        if combo.findText(name) < 0:
            self.control._refresh_profiles()
        if combo.findText(name) >= 0 and combo.currentText() != name:
            combo.setCurrentText(name)
        return name

    def _new(self) -> None:
        if self.control is None:
            return
        self.control._new_project()
        self.refresh()

    def _activate_current(self, *_args) -> None:
        name = self._ensure_selected_on_combo()
        if not name:
            QMessageBox.information(self, "提示", "请先选择项目")
            return
        self.refresh()

    def _edit(self) -> None:
        if self.control is None:
            return
        self._ensure_selected_on_combo()
        self.control._edit_plugin()

    def _open_external(self) -> None:
        path = self._current_plugin_py or ""
        if not path or not os.path.isfile(path):
            QMessageBox.information(self, "提示", "当前项目没有 plugin.py")
            return
        import platform
        import subprocess

        try:
            if platform.system() == "Windows":
                os.startfile(path)  # type: ignore[attr-defined]
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as e:
            QMessageBox.warning(self, "打开失败", str(e))

    def _export(self) -> None:
        if self.control is None:
            return
        self._ensure_selected_on_combo()
        self.control._export_project()

    def _import(self) -> None:
        if self.control is None:
            return
        self.control._import_project()
        self.refresh()

    def _delete(self) -> None:
        if self.control is None:
            return
        self._ensure_selected_on_combo()
        self.control._delete_project()
        self.refresh()
