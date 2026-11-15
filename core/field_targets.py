"""加解密目标字段 — 纯逻辑（无 Qt，GUI / Web 共用）。"""

from __future__ import annotations

import json
import urllib.parse
from typing import Any


def preview_value(val: Any, limit: int = 72) -> str:
    s = str(val).replace("\n", "\\n")
    if len(s) > limit:
        return s[: limit - 1] + "…"
    return s


def detect_body_format(headers: dict, body: str) -> str:
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


def norm_headers(flow: dict) -> dict:
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


def walk_add(obj: Any, prefix: str, scope: str, add) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                walk_add(v, path, scope, add)
            else:
                add(path, preview_value(v), scope)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            path = f"{prefix}[{i}]"
            if isinstance(v, (dict, list)):
                walk_add(v, path, scope, add)
            else:
                add(path, preview_value(v), scope)


def collect_side_fields(flow: dict, flow_i: int, side: str) -> list[dict]:
    """side: request | response → 扁平字段列表."""
    out: list[dict] = []
    seq = flow_seq(flow, flow_i + 1)
    headers = norm_headers(flow)

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
                add(k, preview_value(v), "📋 Query")
        skip_h = {
            "content-length", "host", "connection", "accept",
            "accept-encoding", "user-agent",
        }
        for k, v in headers.items():
            if str(k).lower() in skip_h:
                continue
            add(str(k), preview_value(v), "📋 Header")
        body = str(flow.get("request_body") or flow.get("body") or "")
        fmt = detect_body_format(headers, body)
        if fmt == "json" and body.strip():
            try:
                walk_add(json.loads(body), "", "📋 Body (JSON)", add)
            except Exception:
                add("(raw)", preview_value(body, 100), "📋 Body")
        elif fmt == "form" and body.strip():
            for k, v in urllib.parse.parse_qsl(body, keep_blank_values=True):
                add(k, preview_value(v), "📋 Body (Form)")
        elif body.strip():
            add("(raw)", preview_value(body, 100), "📋 Body")
    else:
        resp = str(flow.get("response_body") or "")
        if not resp.strip() or resp.startswith("(等待"):
            return out
        try:
            walk_add(json.loads(resp), "", "📋 Response Body (JSON)", add)
        except Exception:
            add("(raw)", preview_value(resp, 100), "📋 Response Body")
    return out


def extract_fields_from_flows(flows: list[dict]) -> dict[str, list[dict]]:
    buckets: dict[str, list[dict]] = {
        "req_body": [],
        "req_query": [],
        "req_header": [],
        "resp_body": [],
    }
    for fi, flow in enumerate(flows or []):
        dlg_fields = collect_side_fields(flow, fi, "request")
        for it in dlg_fields:
            if it["scope"].startswith("📋 Query"):
                buckets["req_query"].append(it)
            elif it["scope"].startswith("📋 Header"):
                buckets["req_header"].append(it)
            else:
                buckets["req_body"].append(it)
        for it in collect_side_fields(flow, fi, "response"):
            buckets["resp_body"].append(it)
    return buckets
