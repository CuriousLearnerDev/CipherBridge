"""HTTP 流量 ↔ 请求解析器报文格式转换（Burp 风格）."""

from __future__ import annotations

import re
from urllib.parse import urlparse


def _header_lines(hdrs: dict | None) -> list[str]:
    if not hdrs or not isinstance(hdrs, dict):
        return []
    return [f"{k}: {v}" for k, v in hdrs.items()]


def _header_map(hdrs: dict | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not isinstance(hdrs, dict):
        return out
    for k, v in hdrs.items():
        if k is None:
            continue
        out[str(k)] = "" if v is None else str(v)
    return out


def _has_header(hdrs: dict[str, str], name: str) -> bool:
    low = name.lower()
    return any(k.lower() == low for k in hdrs)


def _set_header(hdrs: dict[str, str], name: str, value: str) -> None:
    """按大小写不敏感覆盖/写入 Header."""
    low = name.lower()
    for k in list(hdrs.keys()):
        if k.lower() == low:
            hdrs[k] = value
            return
    hdrs[name] = value


def enrich_request_headers(flow: dict) -> dict[str, str]:
    """补全 JS Hook 常缺的 Host / Content-Length / Content-Type."""
    hdrs = _header_map(flow.get("request_headers"))
    url = flow.get("url") or ""
    body = flow.get("request_body") or ""
    if isinstance(body, bytes):
        body_len = len(body)
        body_text = body.decode("utf-8", errors="replace")
    else:
        body_text = str(body)
        body_len = len(body_text.encode("utf-8"))

    try:
        u = urlparse(url)
        if u.hostname and not _has_header(hdrs, "Host"):
            host = u.hostname
            if u.port and not (
                (u.scheme == "http" and u.port == 80)
                or (u.scheme == "https" and u.port == 443)
            ):
                host = f"{host}:{u.port}"
            _set_header(hdrs, "Host", host)
    except Exception:
        pass

    if body_text and not _has_header(hdrs, "Content-Length"):
        _set_header(hdrs, "Content-Length", str(body_len))

    if body_text and not _has_header(hdrs, "Content-Type"):
        s = body_text.lstrip()
        if s.startswith("{") or s.startswith("["):
            _set_header(hdrs, "Content-Type", "application/json")
        elif "=" in body_text and not s.startswith("<"):
            _set_header(hdrs, "Content-Type", "application/x-www-form-urlencoded")

    return hdrs


def _reason_phrase(status: int) -> str:
    table = {
        200: "OK",
        201: "Created",
        204: "No Content",
        301: "Moved Permanently",
        302: "Found",
        304: "Not Modified",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
    }
    return table.get(int(status or 0), "OK")


def format_request_burp(flow: dict, *, max_body: int = 0) -> str:
    """Burp 风格请求报文：POST /path HTTP/1.1 + Host + Headers + Body."""
    method = (flow.get("method") or "POST").upper()
    url = flow.get("url") or ""
    body = flow.get("request_body") or ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    body = str(body)
    if max_body and len(body) > max_body:
        body = body[:max_body] + "\n…(body 已截断)"

    try:
        u = urlparse(url)
        path = u.path or "/"
        if u.query:
            path = f"{path}?{u.query}"
        if u.fragment:
            path = f"{path}#{u.fragment}"
    except Exception:
        path = url or "/"

    hdrs = enrich_request_headers({**flow, "request_body": body})
    lines = [f"{method} {path} HTTP/1.1"]
    lines.extend(_header_lines(hdrs))
    lines.append("")
    lines.append(body)
    return "\n".join(lines)


def format_response_burp(flow: dict, *, max_body: int = 0) -> str:
    """Burp 风格响应报文."""
    resp_body = flow.get("response_body") or ""
    if isinstance(resp_body, bytes):
        resp_body = resp_body.decode("utf-8", errors="replace")
    resp_body = str(resp_body)
    if resp_body in ("(等待响应…)", "(等待响应...)"):
        return "(等待响应…)"
    if max_body and len(resp_body) > max_body:
        resp_body = resp_body[:max_body] + "\n…(body 已截断)"

    status = int(flow.get("status") or 0)
    if status <= 0 and not resp_body.strip():
        return "(无响应)"

    if status <= 0:
        status = 200

    hdrs = _header_map(flow.get("response_headers"))
    lines = [f"HTTP/1.1 {status} {_reason_phrase(status)}"]
    if hdrs:
        lines.extend(_header_lines(hdrs))
    else:
        lines.append("Content-Type: text/plain")
    lines.append("")
    lines.append(resp_body)
    return "\n".join(lines)


def flow_to_parser_raw(flow: dict) -> str:
    """请求解析器可解析的 Burp 报文（请求 + 可选响应）。"""
    req = format_request_burp(flow)
    resp = format_response_burp(flow)
    if resp in ("(等待响应…)", "(无响应)", ""):
        return req
    return req + "\n\n" + resp


def split_request_response_body(body_section: str) -> tuple[str, str | None]:
    """从请求 Body 段中分离 Burp 风格的响应块（以 HTTP/1.x 状态行开头）."""
    if not body_section:
        return "", None
    m = re.search(r"(?:^|\n)\s*(HTTP/\d\.\d\s+\d+[^\n]*)\s*\n", body_section)
    if not m:
        return body_section.strip(), None
    req_body = body_section[: m.start()].strip()
    resp_block = body_section[m.start() :].strip()
    return req_body, resp_block if resp_block else None
