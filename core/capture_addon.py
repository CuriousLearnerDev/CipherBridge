"""纯抓包 mitmdump 插件 — 向 stdout 输出 CB_FLOW|JSON，供 AI Lab 小程序采集解析.

用法: mitmdump -s core/capture_addon.py -p 8090 --ssl-insecure
"""

from __future__ import annotations

import base64
import json
from typing import Any

from mitmproxy import http

try:
    from core.capture_filter import (
        load_allow_from_env,
        load_block_noise_from_env,
        should_capture_url,
    )
except Exception:  # pragma: no cover - 独立 -s 加载时兜底
    from capture_filter import (  # type: ignore
        load_allow_from_env,
        load_block_noise_from_env,
        should_capture_url,
    )

MAX_BODY = 80_000
PREFIX = "CB_FLOW|"
_ALLOW = load_allow_from_env()
_BLOCK_NOISE = load_block_noise_from_env()


def _source() -> str:
    import os

    return (os.environ.get("CB_CAPTURE_SOURCE") or "miniprogram-proxy").strip() or "miniprogram-proxy"


def _want(url: str) -> bool:
    return should_capture_url(url, allow_patterns=_ALLOW, block_noise=_BLOCK_NOISE)


def _maybe_gunzip(raw: bytes) -> bytes:
    """若仍是 gzip 魔数，手动解压（兜底 raw_content）。"""
    if len(raw) >= 2 and raw[0] == 0x1F and raw[1] == 0x8B:
        import gzip

        try:
            return gzip.decompress(raw)
        except Exception:
            return raw
    return raw


def _message_body(msg) -> bytes | None:
    """优先取 mitmproxy 已按 Content-Encoding 解码的 content，避免 gzip 原文."""
    if msg is None:
        return None
    data = None
    try:
        # .content = 解码后；.raw_content = 线上压缩原文
        data = msg.content
    except Exception:
        data = None
    if data is None:
        try:
            data = msg.raw_content
        except Exception:
            data = None
    if isinstance(data, bytes):
        return _maybe_gunzip(data)
    return data


def _body_text(raw: bytes | None) -> str:
    if not raw:
        return ""
    if isinstance(raw, str):
        return raw[:MAX_BODY]
    data = _maybe_gunzip(raw)[:MAX_BODY]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("gbk", errors="replace")
        except Exception:
            return "(binary) " + base64.b64encode(data[:4096]).decode("ascii")


def _headers(h: Any, *, decoded_body: bool = False) -> dict[str, str]:
    try:
        out = {str(k): str(v) for k, v in h.items()}
    except Exception:
        return {}
    if decoded_body:
        # body 已解压，去掉易误导的压缩相关头
        for name in list(out.keys()):
            low = name.lower()
            if low in ("content-encoding", "transfer-encoding"):
                out.pop(name, None)
    return out


def _emit(payload: dict) -> None:
    print(PREFIX + json.dumps(payload, ensure_ascii=False), flush=True)


def _flow_key(flow: http.HTTPFlow) -> str:
    fid = getattr(flow, "id", None)
    if fid is not None:
        return str(fid)
    return str(id(flow))


def request(flow: http.HTTPFlow) -> None:
    if flow.request.method == "CONNECT":
        return
    url = flow.request.pretty_url
    if not _want(url):
        return
    req_body = _message_body(flow.request)
    _emit(
        {
            "phase": "request",
            "key": _flow_key(flow),
            "method": flow.request.method,
            "url": url,
            "request_body": _body_text(req_body),
            "request_headers": _headers(flow.request.headers, decoded_body=True),
            "response_body": "(pending)",
            "response_headers": {},
            "status": 0,
            "source": _source(),
        }
    )


def response(flow: http.HTTPFlow) -> None:
    if flow.request.method == "CONNECT":
        return
    resp = flow.response
    if resp is None:
        return
    url = flow.request.pretty_url
    if not _want(url):
        return
    req_body = _message_body(flow.request)
    resp_body = _message_body(resp)
    _emit(
        {
            "phase": "response",
            "key": _flow_key(flow),
            "method": flow.request.method,
            "url": url,
            "request_body": _body_text(req_body),
            "request_headers": _headers(flow.request.headers, decoded_body=True),
            "response_body": _body_text(resp_body),
            "response_headers": _headers(resp.headers, decoded_body=True),
            "status": int(resp.status_code),
            "source": _source(),
        }
    )
