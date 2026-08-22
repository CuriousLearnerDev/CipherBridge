"""AI 分析前指定解密字段 / 加密位置：选请求 → 请求/响应 → 点击字段."""

from __future__ import annotations

import json
import urllib.parse
from typing import Any

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QFrame, QHBoxLayout, QLabel,
    QListWidget, QListWidgetItem, QPushButton, QButtonGroup, QSizePolicy,
    QSplitter, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from core.theme import style_button, style_muted_label, style_sidebar_aux_button


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


def _preview(val: Any, limit: int = 72) -> str:
    s = str(val).replace("\n", "\\n")
    if len(s) > limit:
        return s[: limit - 1] + "…"
    return s


def _detect_body_format(headers: dict, body: str) -> str:
    ct = ""
    for k, v in (headers or {}).items():
        if str(k).lower() == "content-type":
            ct = str(v).lower()
            break
    body = (body or "").strip()
    if not body:
        return "none"
    if "json" in ct or body[:1] in "{[":
        return "json"
    if "x-www-form-urlencoded" in ct or (
        "=" in body and "&" in body and body[:1] not in "{["
    ):
        return "form"
    try:
        json.loads(body)
        return "json"
    except Exception:
        pass
    return "raw"


def _norm_headers(flow: dict) -> dict:
    headers = flow.get("request_headers") or flow.get("headers") or {}
    if isinstance(headers, list):
        return {h.get("name", ""): h.get("value", "") for h in headers if isinstance(h, dict)}
    return dict(headers) if isinstance(headers, dict) else {}


def flow_seq(flow: dict, fallback: int = 0) -> int:
    s = flow.get("_seq")
    if isinstance(s, int) and s > 0:
        return s
    return fallback


def format_field_targets_hint(targets: dict | None) -> str:
    """拼进 Agent goal 的用户约束."""
    if not targets or targets.get("unrestricted"):
        return ""
    decrypt = targets.get("decrypt") or []
    encrypt = targets.get("encrypt") or []
    resp_decrypt = targets.get("resp_decrypt") or []
    if not decrypt and not encrypt and not resp_decrypt:
        return ""

    lines = [
        "【用户指定目标 — 必须遵守，不要改猜其它无关字段】",
    ]
    if decrypt:
        lines.append("请求解密字段（密文所在，生成 🔓 解密字段）:")
        for it in decrypt:
            seq = it.get("seq")
            prefix = f"请求#{seq} " if seq else ""
            lines.append(
                f"  - {prefix}field=`{it['path']}` scope=`{it['scope']}` "
                f"样例={it.get('preview', '')[:40]}"
            )
    if resp_decrypt:
        lines.append("响应解密字段（生成 🔓 解密响应字段）:")
        for it in resp_decrypt:
            seq = it.get("seq")
            prefix = f"请求#{seq} " if seq else ""
            lines.append(
                f"  - {prefix}field=`{it['path']}` scope=`{it['scope']}` "
                f"样例={it.get('preview', '')[:40]}"
            )
    if encrypt:
        lines.append("请求加密位置（明文/待加密字段，生成 🔒 加密字段）:")
        for it in encrypt:
            seq = it.get("seq")
            prefix = f"请求#{seq} " if seq else ""
            lines.append(
                f"  - {prefix}field=`{it['path']}` scope=`{it['scope']}` "
                f"样例={it.get('preview', '')[:40]}"
            )
    lines.append(
        "steps 中 params.field / scope 必须与上表一致；"
        "仍用 flow/hook/script 查算法与密钥，但字段不要自行扩展。"
    )
    return "\n".join(lines)


def summarize_field_targets(targets: dict | None) -> str:
    if not targets or targets.get("unrestricted"):
        return "未限定（盲目分析）"
    parts = []
    d = targets.get("decrypt") or []
    e = targets.get("encrypt") or []
    r = targets.get("resp_decrypt") or []
    if d:
        parts.append("解密:" + ",".join(x["path"] for x in d[:4]) + ("…" if len(d) > 4 else ""))
    if r:
        parts.append("响应解密:" + ",".join(x["path"] for x in r[:3]))
    if e:
        parts.append("加密:" + ",".join(x["path"] for x in e[:4]) + ("…" if len(e) > 4 else ""))
    return " · ".join(parts) if parts else "未勾选字段"


# 兼容旧调用
def extract_fields_from_flows(flows: list[dict]) -> dict[str, list[dict]]:
    buckets: dict[str, list[dict]] = {
        "req_body": [],
        "req_query": [],
        "req_header": [],
        "resp_body": [],
    }
    for fi, flow in enumerate(flows or []):
        dlg_fields = _collect_side_fields(flow, fi, "request")
        for it in dlg_fields:
            if it["scope"].startswith("📋 Query"):
                buckets["req_query"].append(it)
            elif it["scope"].startswith("📋 Header"):
                buckets["req_header"].append(it)
            else:
                buckets["req_body"].append(it)
        for it in _collect_side_fields(flow, fi, "response"):
            buckets["resp_body"].append(it)
    return buckets


def _collect_side_fields(flow: dict, flow_i: int, side: str) -> list[dict]:
    """side: request | response → 扁平字段列表."""
    out: list[dict] = []
    seq = flow_seq(flow, flow_i + 1)
    headers = _norm_headers(flow)

    def add(path: str, preview: str, scope: str) -> None:
        out.append(
            {
                "path": path,
                "preview": preview,
                "scope": scope,
                "flow_i": flow_i,
                "seq": seq,
                "side": side,
            }
        )

    if side == "request":
        url = str(flow.get("url") or "")
        if "?" in url:
            q = urllib.parse.urlparse(url).query
            for k, v in urllib.parse.parse_qsl(q, keep_blank_values=True):
                add(k, _preview(v), "📋 Query")
        skip_h = {
            "content-length", "host", "connection", "accept",
            "accept-encoding", "user-agent",
        }
        for k, v in headers.items():
            if str(k).lower() in skip_h:
                continue
            add(str(k), _preview(v), "📋 Header")
        body = str(flow.get("request_body") or flow.get("body") or "")
        fmt = _detect_body_format(headers, body)
        if fmt == "json" and body.strip():
            try:
                _walk_add(json.loads(body), "", "📋 Body (JSON)", add)
            except Exception:
                add("(raw)", _preview(body, 100), "📋 Body")
        elif fmt == "form" and body.strip():
            for k, v in urllib.parse.parse_qsl(body, keep_blank_values=True):
                add(k, _preview(v), "📋 Body (Form)")
        elif body.strip():
            add("(raw)", _preview(body, 100), "📋 Body")
    else:
        resp = str(flow.get("response_body") or "")
        if not resp.strip() or resp.startswith("(等待"):
            return out
        try:
            _walk_add(json.loads(resp), "", "📋 Response Body (JSON)", add)
        except Exception:
            add("(raw)", _preview(resp, 100), "📋 Response Body")
    return out


def _walk_add(obj: Any, prefix: str, scope: str, add) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                _walk_add(v, path, scope, add)
            else:
                add(path, _preview(v), scope)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            path = f"{prefix}[{i}]"
            if isinstance(v, (dict, list)):
                _walk_add(v, path, scope, add)
            else:
                add(path, _preview(v), scope)


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

        left_card, left_body = _make_panel("请求", step="1")
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

        field_card, field_body = _make_panel("字段", step="2")
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
        role_bar, self.role_group, self.role_btns = _make_seg_bar(
            self,
            [
                ("解密", self.ROLE_DECRYPT),
                ("响应解密", self.ROLE_RESP),
                ("加密", self.ROLE_ENCRYPT),
            ],
            exclusive_id="role",
            height=22,
        )
        want = self._default_role
        if want in self.role_btns:
            self.role_btns[want].setChecked(True)
            self._role = want
        else:
            self.role_btns[self.ROLE_DECRYPT].setChecked(True)
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
        self.foot_hint = QLabel()
        style_muted_label(self.foot_hint)
        foot.addWidget(self.foot_hint, 1)
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
            self._set_role(self.ROLE_RESP)
        elif self._role == self.ROLE_RESP:
            want = self.ROLE_ENCRYPT if self._default_role == self.ROLE_ENCRYPT else self.ROLE_DECRYPT
            self._set_role(want)
        self._reload_tree()

    def _on_role_clicked(self, _id: int) -> None:
        btn = self.role_group.button(_id)
        if btn is None:
            return
        self._role = str(btn.property("segData") or self.ROLE_DECRYPT)
        self._reload_tree()

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
            self.foot_hint.setText("已跳过字段限定")
            return
        self.status_lab.setText(f"已选 {n} 个字段" if n else "尚未选字段")
        fi = self._current_flow_index()
        if fi is not None and 0 <= fi < len(self._flows):
            seq = flow_seq(self._flows[fi], fi + 1)
            side = "响应" if self._side == "response" else "请求"
            self.foot_hint.setText(f"当前：#{seq} · {side} · 标记为「{self._role_label()}」")
        else:
            self.foot_hint.setText("从左侧点选一条请求开始")

    def _role_label(self) -> str:
        return {
            self.ROLE_DECRYPT: "请求解密",
            self.ROLE_RESP: "响应解密",
            self.ROLE_ENCRYPT: "加密",
        }.get(self._role, self._role)

    def _on_unrestricted(self, on: bool) -> None:
        self._content.setEnabled(not on)
        self._sync_status()

    def result(self) -> dict:
        if self.unrestricted.isChecked():
            return {"unrestricted": True, "decrypt": [], "encrypt": [], "resp_decrypt": []}
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
        }


def ask_field_targets(
    parent,
    flows: list[dict],
    initial: dict | None = None,
    *,
    default_role: str | None = None,
) -> dict | None:
    """弹出对话框；取消返回 None."""
    dlg = FieldTargetDialog(
        flows, initial=initial, default_role=default_role, parent=parent,
    )
    if dlg.exec() != QDialog.DialogCode.Accepted:
        return None
    return dlg.result()
