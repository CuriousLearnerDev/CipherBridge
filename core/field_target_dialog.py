"""AI 分析前指定解密字段 / 加密位置：选请求 → 请求/响应 → 点击字段."""

from __future__ import annotations

from typing import Any

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QFrame, QHBoxLayout, QLabel,
    QListWidget, QListWidgetItem, QPushButton, QButtonGroup, QSizePolicy,
    QSplitter, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from core.field_targets import (
    collect_side_fields,
    extract_fields_from_flows,
    flow_seq,
    format_field_targets_hint,
    preview_value,
    summarize_field_targets,
)
from core.theme import style_button, style_muted_label, style_sidebar_aux_button

# 兼容旧私有名
_collect_side_fields = collect_side_fields
_preview = preview_value


def _make_panel(title: str, *, step: str | None = None) -> tuple[QFrame, QVBoxLayout]:
    """紧凑面板卡片."""
    card = QFrame()
    card.setObjectName("ftPanel")
    outer = QVBoxLayout(card)
    outer.setContentsMargins(6, 6, 6, 6)
    outer.setSpacing(4)
    head = QHBoxLayout()
    head.setSpacing(4)
    head.setContentsMargins(0, 0, 0, 0)
    if step:
        badge = QLabel(step)
        badge.setObjectName("ftStepBadge")
        badge.setFixedSize(16, 16)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        head.addWidget(badge)
    title_lab = QLabel(title)
    title_lab.setObjectName("ftPanelTitle")
    head.addWidget(title_lab, 1)
    outer.addLayout(head)
    body = QVBoxLayout()
    body.setContentsMargins(0, 0, 0, 0)
    body.setSpacing(3)
    outer.addLayout(body, 1)
    return card, body


def _make_seg_bar(
    parent, items: list[tuple[str, str]], *, exclusive_id: str, height: int = 22,
) -> tuple[QFrame, QButtonGroup, dict[str, QPushButton]]:
    """分段按钮条：[(label, data), ...]."""
    bar = QFrame()
    bar.setObjectName("ftSegBar")
    lay = QHBoxLayout(bar)
    lay.setContentsMargins(1, 1, 1, 1)
    lay.setSpacing(1)
    group = QButtonGroup(parent)
    group.setExclusive(True)
    btns: dict[str, QPushButton] = {}
    for i, (label, data) in enumerate(items):
        btn = QPushButton(label)
        btn.setObjectName("ftSegBtn")
        btn.setCheckable(True)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        btn.setFixedHeight(height)
        btn.setProperty("segData", data)
        group.addButton(btn, i)
        lay.addWidget(btn)
        btns[data] = btn
    return bar, group, btns


class FieldTargetDialog(QDialog):
    """选请求 → 请求/响应 → 点字段；工具风分段控件 + 步骤面板."""

    ROLE_DECRYPT = "decrypt"
    ROLE_ENCRYPT = "encrypt"
    ROLE_RESP = "resp_decrypt"

    def __init__(
        self,
        flows: list[dict],
        *,
        initial: dict | None = None,
        default_role: str | None = None,
        allowed_roles: list[str] | tuple[str, ...] | None = None,
        parent=None,
    ):
        super().__init__(parent)
        self.setObjectName("fieldTargetDialog")
        self.setWindowTitle("指定加解密字段")
        self.setMinimumSize(680, 420)
        self.resize(760, 480)
        self._flows = list(flows or [])
        self._initial = initial or {}
        self._default_role = default_role or self.ROLE_DECRYPT
        # 分析解密：只显示解密/响应解密；分析加密：只显示加密
        if allowed_roles:
            self._allowed_roles = [
                r
                for r in allowed_roles
                if r in (self.ROLE_DECRYPT, self.ROLE_ENCRYPT, self.ROLE_RESP)
            ]
        elif self._default_role == self.ROLE_ENCRYPT:
            self._allowed_roles = [self.ROLE_ENCRYPT]
        else:
            self._allowed_roles = [self.ROLE_DECRYPT, self.ROLE_RESP]
        if self._default_role not in self._allowed_roles:
            self._default_role = self._allowed_roles[0]
        self._side = "request"
        self._role = self._default_role
        self._picked: dict[str, dict] = {}
        self._build()
        self._restore_initial()
        self._sync_status()

    def _pick_key(self, role: str, it: dict) -> str:
        return f"{role}|{it.get('seq')}|{it.get('scope')}|{it.get('path')}"

    def _restore_initial(self) -> None:
        if self._initial.get("unrestricted"):
            self.unrestricted.setChecked(True)
            return
        for role, key in (
            (self.ROLE_DECRYPT, "decrypt"),
            (self.ROLE_ENCRYPT, "encrypt"),
            (self.ROLE_RESP, "resp_decrypt"),
        ):
            if role not in self._allowed_roles:
                continue
            for it in self._initial.get(key) or []:
                item = dict(it)
                item["role"] = role
                self._picked[self._pick_key(role, item)] = item
        self._refresh_picked_list()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(4)

        # 顶栏一行：标题 | 跳过 | 状态
        head = QHBoxLayout()
        head.setSpacing(6)
        title = QLabel("缩小 AI 分析范围")
        title.setObjectName("ftDialogTitle")
        title.setToolTip("选请求 → 请求/响应 → 点字段；算法密钥仍由 AI 分析")
        head.addWidget(title)
        self.unrestricted = QCheckBox("跳过指定")
        self.unrestricted.setToolTip("不限定字段，保持盲目分析")
        self.unrestricted.toggled.connect(self._on_unrestricted)
        head.addWidget(self.unrestricted)
        head.addStretch()
        self.status_lab = QLabel()
        self.status_lab.setObjectName("ftStatusChip")
        head.addWidget(self.status_lab)
        root.addLayout(head)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.setChildrenCollapsible(False)
        split.setHandleWidth(4)

        left_card, left_body = _make_panel("请求")
        sort_row = QHBoxLayout()
        sort_row.setSpacing(4)
        self.sort_combo = QComboBox()
        self.sort_combo.setFixedHeight(22)
        self.sort_combo.addItem("顺序↑", "seq_asc")
        self.sort_combo.addItem("顺序↓", "seq_desc")
        self.sort_combo.addItem("URL", "url")
        self.sort_combo.addItem("方法", "method")
        self.sort_combo.setToolTip("列表排序")
        self.sort_combo.currentIndexChanged.connect(self._rebuild_flow_list)
        sort_row.addWidget(self.sort_combo, 1)
        self.flow_count_lab = QLabel()
        style_muted_label(self.flow_count_lab)
        sort_row.addWidget(self.flow_count_lab)
        left_body.addLayout(sort_row)
        self.flow_list = QListWidget()
        self.flow_list.setObjectName("ftFlowList")
        self.flow_list.setToolTip("点击选中请求")
        self.flow_list.setSpacing(0)
        self.flow_list.setUniformItemSizes(True)
        self.flow_list.currentRowChanged.connect(self._on_flow_changed)
        left_body.addWidget(self.flow_list, 1)
        split.addWidget(left_card)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(4)

        field_card, field_body = _make_panel("字段")
        ctrl = QHBoxLayout()
        ctrl.setSpacing(4)
        side_bar, self.side_group, self.side_btns = _make_seg_bar(
            self,
            [("请求", "request"), ("响应", "response")],
            exclusive_id="side",
            height=22,
        )
        side_bar.setMaximumWidth(140)
        self.side_btns["request"].setChecked(True)
        self.side_group.idClicked.connect(self._on_side_clicked)
        ctrl.addWidget(side_bar)
        role_items = []
        if self.ROLE_DECRYPT in self._allowed_roles:
            role_items.append(("解密", self.ROLE_DECRYPT))
        if self.ROLE_RESP in self._allowed_roles:
            role_items.append(("响应解密", self.ROLE_RESP))
        if self.ROLE_ENCRYPT in self._allowed_roles:
            role_items.append(("加密", self.ROLE_ENCRYPT))
        if not role_items:
            role_items = [("解密", self.ROLE_DECRYPT)]
        role_bar, self.role_group, self.role_btns = _make_seg_bar(
            self,
            role_items,
            exclusive_id="role",
            height=22,
        )
        if self.ROLE_DECRYPT in self.role_btns:
            self.role_btns[self.ROLE_DECRYPT].setToolTip(
                "高亮「解密」：勾选字段后确认 → 分析并生成解密端"
            )
        if self.ROLE_RESP in self.role_btns:
            self.role_btns[self.ROLE_RESP].setToolTip(
                "高亮「响应解密」：勾选响应字段 → 按解密端分析"
            )
        if self.ROLE_ENCRYPT in self.role_btns:
            self.role_btns[self.ROLE_ENCRYPT].setToolTip(
                "高亮「加密」：勾选字段后确认 → 分析并生成加密端"
            )
        want = self._default_role
        if want in self.role_btns:
            self.role_btns[want].setChecked(True)
            self._role = want
        else:
            first = role_items[0][1]
            self.role_btns[first].setChecked(True)
            self._role = first
        self.role_group.idClicked.connect(self._on_role_clicked)
        ctrl.addWidget(role_bar, 1)
        field_body.addLayout(ctrl)

        self.field_tree = QTreeWidget()
        self.field_tree.setObjectName("ftFieldTree")
        self.field_tree.setHeaderLabels(["字段", "值"])
        self.field_tree.setColumnWidth(0, 160)
        self.field_tree.setAlternatingRowColors(True)
        self.field_tree.setRootIsDecorated(True)
        self.field_tree.setAnimated(False)
        self.field_tree.setIndentation(14)
        self.field_tree.setToolTip("点击叶节点加入；再点取消")
        self.field_tree.itemClicked.connect(self._on_tree_clicked)
        field_body.addWidget(self.field_tree, 1)

        pick_head = QHBoxLayout()
        pick_head.setSpacing(4)
        pick_lab = QLabel("已选")
        pick_lab.setObjectName("ftPanelTitle")
        pick_head.addWidget(pick_lab)
        pick_head.addStretch()
        clear_btn = QPushButton("清空")
        style_button(clear_btn, "ghost", size="sm")
        clear_btn.setToolTip("清空已选；单项可双击移除")
        clear_btn.clicked.connect(self._clear_picked)
        pick_head.addWidget(clear_btn)
        field_body.addLayout(pick_head)
        self.picked_list = QListWidget()
        self.picked_list.setObjectName("ftPickedList")
        self.picked_list.setMaximumHeight(72)
        self.picked_list.setToolTip("双击移除")
        self.picked_list.itemDoubleClicked.connect(self._remove_picked_item)
        field_body.addWidget(self.picked_list)
        rl.addWidget(field_card, 1)

        split.addWidget(right)
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 5)
        split.setSizes([220, 520])
        root.addWidget(split, 1)
        self._content = split

        if not self._flows:
            warn = QLabel("无可用流量，请先勾选含 Body 的请求，或勾选「跳过指定」。")
            warn.setWordWrap(True)
            warn.setObjectName("ftEmptyHint")
            root.addWidget(warn)

        foot = QHBoxLayout()
        foot.setSpacing(6)
        foot.addStretch(1)
        cancel = QPushButton("取消")
        style_button(cancel, "ghost", size="sm")
        cancel.clicked.connect(self.reject)
        ok = QPushButton("确认")
        style_button(ok, "primary", size="sm")
        ok.setMinimumWidth(72)
        ok.clicked.connect(self.accept)
        foot.addWidget(cancel)
        foot.addWidget(ok)
        root.addLayout(foot)

        self._rebuild_flow_list()
        self._on_unrestricted(False)

    def _set_side(self, side: str) -> None:
        self._side = side
        btn = self.side_btns.get(side)
        if btn and not btn.isChecked():
            btn.setChecked(True)

    def _set_role(self, role: str) -> None:
        self._role = role
        btn = self.role_btns.get(role)
        if btn and not btn.isChecked():
            btn.setChecked(True)

    def _on_side_clicked(self, _id: int) -> None:
        btn = self.side_group.button(_id)
        if btn is None:
            return
        side = str(btn.property("segData") or "request")
        self._side = side
        if side == "response":
            if self.ROLE_RESP in self._allowed_roles:
                self._set_role(self.ROLE_RESP)
        elif self._role == self.ROLE_RESP:
            if self._default_role in self._allowed_roles:
                want = self._default_role
            elif self.ROLE_DECRYPT in self._allowed_roles:
                want = self.ROLE_DECRYPT
            else:
                want = self._allowed_roles[0]
            self._set_role(want)
        self._reload_tree()

    def _on_role_clicked(self, _id: int) -> None:
        btn = self.role_group.button(_id)
        if btn is None:
            return
        self._role = str(btn.property("segData") or self.ROLE_DECRYPT)
        self._reload_tree()
        self._sync_status()

    def _sorted_indices(self) -> list[int]:
        idxs = list(range(len(self._flows)))
        mode = self.sort_combo.currentData() if hasattr(self, "sort_combo") else "seq_asc"

        def seq_key(i: int) -> int:
            return flow_seq(self._flows[i], i + 1)

        if mode == "seq_desc":
            idxs.sort(key=seq_key, reverse=True)
        elif mode == "url":
            idxs.sort(key=lambda i: str(self._flows[i].get("url") or ""))
        elif mode == "method":
            idxs.sort(
                key=lambda i: (
                    str(self._flows[i].get("method") or ""),
                    str(self._flows[i].get("url") or ""),
                )
            )
        else:
            idxs.sort(key=seq_key)
        return idxs

    def _rebuild_flow_list(self) -> None:
        prev_idx = None
        cur = self.flow_list.currentItem()
        if cur is not None:
            prev_idx = cur.data(Qt.ItemDataRole.UserRole)
        self.flow_list.clear()
        for i in self._sorted_indices():
            f = self._flows[i]
            seq = flow_seq(f, i + 1)
            status = f.get("status", "")
            method = f.get("method", "GET")
            url = str(f.get("url") or "")
            # 路径短显示
            path = url
            try:
                from urllib.parse import urlparse
                p = urlparse(url)
                path = (p.path or "/") + (("?" + p.query) if p.query else "")
            except Exception:
                pass
            path = path[:52] + ("…" if len(path) > 52 else "")
            st = f"{status}" if status not in (None, "", 0) else "…"
            text = f"#{seq} {method} [{st}] {path}"
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, i)
            item.setToolTip(url)
            self.flow_list.addItem(item)
        n = self.flow_list.count()
        self.flow_count_lab.setText(f"共 {n} 条" if n else "无请求")
        if n == 0:
            self.field_tree.clear()
            return
        row = 0
        if prev_idx is not None:
            for r in range(n):
                if self.flow_list.item(r).data(Qt.ItemDataRole.UserRole) == prev_idx:
                    row = r
                    break
        self.flow_list.setCurrentRow(row)

    def _current_flow_index(self) -> int | None:
        item = self.flow_list.currentItem()
        if item is None:
            return None
        idx = item.data(Qt.ItemDataRole.UserRole)
        return idx if isinstance(idx, int) else None

    def _on_flow_changed(self, _row: int) -> None:
        self._reload_tree()
        self._sync_status()

    def _reload_tree(self) -> None:
        self.field_tree.clear()
        fi = self._current_flow_index()
        if fi is None or fi < 0 or fi >= len(self._flows):
            empty = QTreeWidgetItem(self.field_tree, ["（请先在左侧选择请求）", ""])
            empty.setFlags(Qt.ItemFlag.NoItemFlags)
            return
        flow = self._flows[fi]
        side = self._side
        fields = _collect_side_fields(flow, fi, side)
        if not fields:
            tip = "暂无响应体" if side == "response" else "暂无可解析字段"
            empty = QTreeWidgetItem(self.field_tree, [tip, ""])
            empty.setFlags(Qt.ItemFlag.NoItemFlags)
            return
        groups: dict[str, QTreeWidgetItem] = {}
        role = self._role
        for it in fields:
            scope = it["scope"]
            if scope not in groups:
                groups[scope] = QTreeWidgetItem(self.field_tree, [scope, ""])
                groups[scope].setFlags(groups[scope].flags() & ~Qt.ItemFlag.ItemIsSelectable)
            leaf = QTreeWidgetItem(groups[scope], [it["path"], it["preview"]])
            leaf.setData(0, Qt.ItemDataRole.UserRole, it)
            checked = self._pick_key(role, it) in self._picked
            leaf.setCheckState(0, Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
            leaf.setFlags(
                leaf.flags()
                | Qt.ItemFlag.ItemIsUserCheckable
                | Qt.ItemFlag.ItemIsSelectable
            )
        self.field_tree.expandAll()

    def _on_tree_clicked(self, item: QTreeWidgetItem, _col: int) -> None:
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not isinstance(data, dict) or not data.get("path"):
            return
        role = self._role
        if self._side == "response" and role == self.ROLE_DECRYPT:
            role = self.ROLE_RESP
            self._set_role(self.ROLE_RESP)
        key = self._pick_key(role, data)
        if key in self._picked:
            del self._picked[key]
            item.setCheckState(0, Qt.CheckState.Unchecked)
        else:
            entry = dict(data)
            entry["role"] = role
            self._picked[key] = entry
            item.setCheckState(0, Qt.CheckState.Checked)
        self._refresh_picked_list()
        self._sync_status()

    def _refresh_picked_list(self) -> None:
        self.picked_list.clear()
        label_map = {
            self.ROLE_DECRYPT: "解密",
            self.ROLE_ENCRYPT: "加密",
            self.ROLE_RESP: "响应解密",
        }
        for key, it in self._picked.items():
            role = it.get("role") or self.ROLE_DECRYPT
            seq = it.get("seq", "?")
            text = (
                f"[{label_map.get(role, role)}]  #{seq}  "
                f"{it.get('path')}  ·  {_preview(it.get('preview'), 40)}"
            )
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, key)
            item.setToolTip(f"{it.get('scope')} / {it.get('path')}")
            self.picked_list.addItem(item)
        self._sync_status()

    def _remove_picked_item(self, item: QListWidgetItem) -> None:
        key = item.data(Qt.ItemDataRole.UserRole)
        if key in self._picked:
            del self._picked[key]
        self._refresh_picked_list()
        self._reload_tree()

    def _clear_picked(self) -> None:
        self._picked.clear()
        self._refresh_picked_list()
        self._reload_tree()

    def _sync_status(self) -> None:
        n = len(self._picked)
        if self.unrestricted.isChecked():
            self.status_lab.setText("盲目分析")
            return
        self.status_lab.setText(f"已选 {n} 个字段" if n else "尚未选字段")

    def _on_unrestricted(self, on: bool) -> None:
        self._content.setEnabled(not on)
        self._sync_status()

    def result(self) -> dict:
        analysis_role = (
            "encrypt" if self._role == self.ROLE_ENCRYPT else "decrypt"
        )
        if self.unrestricted.isChecked():
            return {
                "unrestricted": True,
                "decrypt": [],
                "encrypt": [],
                "resp_decrypt": [],
                "analysis_role": analysis_role,
            }
        decrypt, encrypt, resp = [], [], []
        for it in self._picked.values():
            role = it.get("role")
            clean = {
                "path": it["path"],
                "preview": it.get("preview", ""),
                "scope": it.get("scope", ""),
                "flow_i": it.get("flow_i"),
                "seq": it.get("seq"),
                "side": it.get("side"),
            }
            if role == self.ROLE_ENCRYPT:
                encrypt.append(clean)
            elif role == self.ROLE_RESP:
                resp.append(clean)
            else:
                decrypt.append(clean)
        return {
            "unrestricted": False,
            "decrypt": decrypt,
            "encrypt": encrypt,
            "resp_decrypt": resp,
            "analysis_role": analysis_role,
        }


def ask_field_targets(
    parent,
    flows: list[dict],
    initial: dict | None = None,
    *,
    default_role: str | None = None,
    allowed_roles: list[str] | tuple[str, ...] | None = None,
) -> dict | None:
    """弹出对话框；取消返回 None.

    allowed_roles: 限制可选角色。None 时按 default_role 推断
    （解密分析 → 解密/响应解密；加密分析 → 仅加密）。
    """
    dlg = FieldTargetDialog(
        flows,
        initial=initial,
        default_role=default_role,
        allowed_roles=allowed_roles,
        parent=parent,
    )
    if dlg.exec() != QDialog.DialogCode.Accepted:
        return None
    return dlg.result()
