"""HTTP 报文格式化 — 输出 Burp 风格的请求/响应文本."""

from __future__ import annotations

import logging
import os

logger = logging.getLogger("cryptoproxy.http")

MAX_LOG_CHARS = 65536

_STATUS_REASONS = {
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
    405: "Method Not Allowed",
    500: "Internal Server Error",
    502: "Bad Gateway",
    504: "Gateway Timeout",
}

HTTP_LOG_BEGIN = ">>>CRYPTOPROXY_HTTP_BEGIN>>>"
HTTP_LOG_END = "<<<CRYPTOPROXY_HTTP_END<<<"
HTTP_LOG_BLANK = "<<<CRYPTOPROXY_HTTP_BLANK>>>"


def _body_text(content: bytes) -> str:
    if not content:
        return ""
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        preview = content[:128].hex()
        suffix = "..." if len(content) > 128 else ""
        return f"[binary {len(content)} bytes]\n{preview}{suffix}"


def _host_header(flow) -> str:
    req = flow.request
    host = req.host
    port = req.port
    if (req.scheme == "https" and port != 443) or (req.scheme == "http" and port != 80):
        return f"{host}:{port}"
    return host


def format_request(flow) -> str:
    """格式化解密/加密后的请求报文."""
    req = flow.request
    lines = [f"{req.method} {req.path} HTTP/1.1"]

    headers = []
    has_host = False
    for key, value in req.headers.items(multi=True):
        if key.lower() == "host":
            has_host = True
        if key.lower() == "content-length":
            continue
        headers.append((key, value))
    if not has_host:
        headers.insert(0, ("Host", _host_header(flow)))

    body = req.content or b""
    for key, value in headers:
        lines.append(f"{key}: {value}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    lines.append("")
    if body:
        lines.append(_body_text(body))
    return "\n".join(lines)


def format_response(flow) -> str:
    """格式化解密/加密后的响应报文."""
    resp = flow.response
    if resp is None:
        return ""

    reason = getattr(resp, "reason", None) or _STATUS_REASONS.get(resp.status_code, "")
    status_line = f"HTTP/1.1 {resp.status_code}"
    if reason:
        status_line += f" {reason}"
    lines = [status_line]

    body = resp.content or b""
    for key, value in resp.headers.items(multi=True):
        if key.lower() == "content-length":
            continue
        lines.append(f"{key}: {value}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    lines.append("")
    if body:
        lines.append(_body_text(body))
    return "\n".join(lines)


def log_http_message(flow, phase: str, role: str, profile: str) -> None:
    """将 Burp 风格报文写入 mitmdump 日志流，供 GUI 日志 Tab 捕获."""
    if os.environ.get("LOG_HTTP", "1") == "0":
        return

    if phase == "request":
        message = format_request(flow)
        summary = f"{flow.request.method} {flow.request.path}"
    else:
        message = format_response(flow)
        status = flow.response.status_code if flow.response else 0
        summary = f"HTTP {status}"

    if not message:
        return

    if len(message) > MAX_LOG_CHARS:
        message = message[:MAX_LOG_CHARS] + f"\n... [已截断, 共 {len(message)} 字符]"

    tag = f"[{role}][{profile}][{phase}] {summary}"
    logger.info("%s %s", HTTP_LOG_BEGIN, tag)
    for line in message.splitlines():
        logger.info("%s", HTTP_LOG_BLANK if line == "" else line)
    logger.info("%s", HTTP_LOG_END)
