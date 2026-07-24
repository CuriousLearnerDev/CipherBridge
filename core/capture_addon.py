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


def _want(url: str) -> bool:
    return should_capture_url(url, allow_patterns=_ALLOW, block_noise=_BLOCK_NOISE)


def _body_text(raw: bytes | None) -> str:
    if not raw:
        return ""
    data = raw[:MAX_BODY]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("gbk", errors="replace")
        except Exception:
            return "(binary) " + base64.b64encode(data[:4096]).decode("ascii")


def _headers(h: Any) -> dict[str, str]:
    try:
        return {str(k): str(v) for k, v in h.items()}
    except Exception:
        return {}


def _emit(payload: dict) -> None:
    print(PREFIX + json.dumps(payload, ensure_ascii=False), flush=True)


def request(flow: http.HTTPFlow) -> None:
    if flow.request.method == "CONNECT":
        return
    url = flow.request.pretty_url
    if not _want(url):
        return
    _emit(
        {
            "phase": "request",
            "key": getattr(flow, "id", None) or id(flow),
            "method": flow.request.method,
            "url": url,
            "request_body": _body_text(flow.request.raw_content or flow.request.content),
            "request_headers": _headers(flow.request.headers),
            "response_body": "(等待响应…)",
            "response_headers": {},
            "status": 0,
            "source": "miniprogram-proxy",
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
    _emit(
        {
            "phase": "response",
            "key": getattr(flow, "id", None) or id(flow),
            "method": flow.request.method,
            "url": url,
            "request_body": _body_text(flow.request.raw_content or flow.request.content),
            "request_headers": _headers(flow.request.headers),
            "response_body": _body_text(resp.raw_content or resp.content),
            "response_headers": _headers(resp.headers),
            "status": int(resp.status_code),
            "source": "miniprogram-proxy",
        }
    )
