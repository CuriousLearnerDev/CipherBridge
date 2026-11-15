"""HTTP 报文解析 — 对齐 GUI 请求解析器输出结构。"""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any


def _flatten_json(obj: Any, prefix: str = "", out: dict | None = None) -> dict[str, str]:
    if out is None:
        out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                _flatten_json(v, key, out)
            else:
                out[key] = "" if v is None else str(v)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = f"{prefix}[{i}]"
            if isinstance(v, (dict, list)):
                _flatten_json(v, key, out)
            else:
                out[key] = "" if v is None else str(v)
    else:
        if prefix:
            out[prefix] = "" if obj is None else str(obj)
    return out


def _detect_body_format(headers: dict[str, str], body: str) -> str:
    if not (body or "").strip():
        return "none"
    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = (v or "").lower()
            break
    if "json" in ct:
        return "json"
    if "x-www-form-urlencoded" in ct:
        return "form"
    s = body.strip()
    if s.startswith("{") or s.startswith("["):
        try:
            json.loads(s)
            return "json"
        except Exception:
            pass
    if "=" in s and "&" in s and not s.startswith("<"):
        return "form"
    return "json" if s.startswith("{") else "raw"


def parse_http_raw(raw: str, *, include_response: bool = True) -> dict[str, Any]:
    raw = (raw or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not raw:
        return {"ok": False, "error": "报文为空"}

    lines = raw.split("\n")
    first_line = lines[0].strip() if lines else ""
    body_start = raw.find("\n\n")
    header_section = raw[:body_start] if body_start != -1 else raw
    body_section = raw[body_start + 2 :].strip() if body_start != -1 else ""

    try:
        from core.flow_format import split_request_response_body

        req_body, resp_block = split_request_response_body(body_section)
    except Exception:
        req_body, resp_block = body_section, ""

    method = ""
    url = ""
    if " " in first_line:
        parts = first_line.split(" ", 2)
        method = parts[0] if parts else ""
        url = parts[1] if len(parts) > 1 else ""

    headers: dict[str, str] = {}
    for line in header_section.split("\n")[1:]:
        line = line.strip()
        if line and ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    query: dict[str, str] = {}
    if url and "?" in url:
        parsed = urllib.parse.urlparse(url)
        for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
            query[k] = v

    body_format = _detect_body_format(headers, req_body or "")
    fields: dict[str, str] = {}
    tree: list[dict[str, Any]] = [
        {"key": "方法", "value": method},
        {"key": "URL", "value": url},
    ]
    tree.append(
        {
            "key": "Headers",
            "value": "",
            "children": [{"key": k, "value": v} for k, v in headers.items()],
        }
    )
    if query:
        tree.append(
            {
                "key": "Query",
                "value": "",
                "children": [{"key": k, "value": v} for k, v in query.items()],
            }
        )
    tree.append({"key": "Body格式", "value": body_format})

    body_children: list[dict[str, Any]] = []
    if req_body:
        if body_format == "json":
            try:
                obj = json.loads(req_body)
                fields = _flatten_json(obj)
                for k, v in fields.items():
                    body_children.append({"key": k, "value": v})
            except json.JSONDecodeError:
                body_children.append({"key": "原始", "value": req_body[:500]})
        elif body_format == "form":
            for k, v in urllib.parse.parse_qsl(req_body, keep_blank_values=True):
                fields[k] = v
                body_children.append({"key": k, "value": v})
        else:
            body_children.append({"key": "原始", "value": (req_body or "")[:500]})
    tree.append(
        {
            "key": "Body",
            "value": f"({body_format})",
            "children": body_children,
        }
    )

    response: dict[str, Any] | None = None
    if include_response and resp_block:
        response = _parse_response(resp_block)
        tree.append(
            {
                "key": "响应",
                "value": str(response.get("status") or ""),
                "children": [
                    {"key": k, "value": v}
                    for k, v in (response.get("fields") or {}).items()
                ],
            }
        )

    return {
        "ok": True,
        "method": method,
        "url": url,
        "headers": headers,
        "query": query,
        "body": req_body or "",
        "body_format": body_format,
        "fields": fields,
        "tree": tree,
        "response": response,
    }


def _parse_response(resp_block: str) -> dict[str, Any]:
    lines = resp_block.replace("\r\n", "\n").split("\n")
    status = "200"
    if lines and lines[0].strip().upper().startswith("HTTP/"):
        m = re.match(r"HTTP/\d\.\d\s+(\d+)", lines[0].strip(), re.I)
        if m:
            status = m.group(1)
    headers: dict[str, str] = {}
    i = 1
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            i += 1
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
        i += 1
    body = "\n".join(lines[i:]).strip()
    fields: dict[str, str] = {}
    if body:
        try:
            fields = _flatten_json(json.loads(body))
        except Exception:
            fields = {"原始": body[:300]}
    return {"status": status, "headers": headers, "body": body, "fields": fields}
