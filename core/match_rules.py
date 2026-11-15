"""请求匹配规则 — profile match 与生成插件共用."""

from __future__ import annotations

import fnmatch
import json
import urllib.parse
from typing import Any


def _normalize_path(path: str) -> str:
    """mitmproxy 的 path 常带 query，匹配前去掉."""
    p = path or ""
    if "?" in p:
        p = p.split("?", 1)[0]
    return p or "/"


def _path_matches(path: str, pattern: str) -> bool:
    """支持 /api/* 同时命中 /api 与 /api/xxx."""
    path = _normalize_path(path)
    pattern = (pattern or "").strip() or "*"
    if fnmatch.fnmatch(path, pattern):
        return True
    if pattern.endswith("/*"):
        base = pattern[:-2] or "/"
        if path == base or path == base + "/":
            return True
    return False


def matches_request(
    match: dict[str, Any],
    *,
    host: str,
    path: str,
    method: str,
    content_type: str = "",
    body_text: str = "",
) -> bool:
    """判断请求是否命中 profile 的 match 规则."""
    if not match:
        return True

    hosts = match.get("host", [])
    if hosts:
        host_matched = False
        for h in hosts:
            if h == host or h == "*":
                host_matched = True
                break
            if "*" in h and h.replace("*", "") in host:
                host_matched = True
                break
        if not host_matched:
            return False

    paths = match.get("path", [])
    if paths and not any(_path_matches(path, p) for p in paths):
        return False

    methods = match.get("methods", [])
    if methods and method not in methods:
        return False

    ctypes = match.get("content_type", [])
    ct = (content_type or "").lower()
    if ctypes and not any(c in ct for c in ctypes):
        return False

    require_fields = match.get("require_fields", [])
    if require_fields:
        try:
            if "json" in ct:
                body = json.loads(body_text or "{}")
            elif "urlencoded" in ct:
                body = dict(urllib.parse.parse_qsl(body_text or ""))
            else:
                body = {}
            if not all(f in body for f in require_fields):
                return False
        except Exception:
            return False

    return True


def generate_match_guard_code(match: dict[str, Any]) -> str:
    """为 plugin.py 生成 _should_process 匹配函数."""
    if not match:
        return ""
    return f'''MATCH_RULES = {match!r}
_MATCH_MISS_LOGGED = 0

def _should_process(flow: http.HTTPFlow) -> bool:
    from core.match_rules import matches_request
    ok = matches_request(
        MATCH_RULES,
        host=flow.request.host,
        path=flow.request.path,
        method=flow.request.method,
        content_type=flow.request.headers.get("Content-Type", ""),
        body_text=flow.request.text or "",
    )
    if not ok:
        global _MATCH_MISS_LOGGED
        if _MATCH_MISS_LOGGED < 5:
            _MATCH_MISS_LOGGED += 1
            print(
                f"跳过加解密(未匹配规则，仍转发Burp): {{flow.request.method}} "
                f"{{flow.request.host}}{{flow.request.path}}"
            )
            if _MATCH_MISS_LOGGED == 5:
                print("跳过加解密: 后续同类提示已省略，请检查 profiles 的 match 或左侧「规则」")
    return ok

'''
