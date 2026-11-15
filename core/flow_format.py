"""HTTP 流量 ↔ 请求解析器报文格式转换（Burp 风格）."""

from __future__ import annotations

import base64
import binascii
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


def is_pending_response_body(body: str | None) -> bool:
    """识别尚未收到响应的占位正文（含历史中文与 Windows 乱码形态）。"""
    if body is None:
        return False
    s = str(body).strip()
    if not s:
        return False
    if s in (
        "(pending)",
        "(waiting)",
        "(waiting response...)",
        "(等待响应…)",
        "(等待响应...)",
        "(等待响应)",
    ):
        return True
    # UTF-8「等待响应」被当 GBK/Latin-1 读时的常见乱码
    if "等待响应" in s:
        return True
    if s.startswith("(�") and ("Ӧ" in s or "Ӧ��" in s or len(s) < 24):
        return True
    return False


def _hex_dump(raw: bytes, *, width: int = 16, max_bytes: int = 2048) -> str:
    """经典 Hex dump，默认最多 2KB。"""
    data = raw[:max_bytes]
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<{width * 3}}  {asc}")
    if len(raw) > max_bytes:
        lines.append(f"…(hex 已截断，共 {len(raw)} bytes)")
    return "\n".join(lines)


def _format_binary_body(flow: dict, summary: str) -> str:
    """二进制响应：摘要 + Hex + Base64 原始数据。"""
    raw = b""
    b64 = flow.get("response_body_b64") or ""
    if isinstance(b64, str) and b64.strip():
        try:
            raw = base64.b64decode(b64, validate=False)
        except (binascii.Error, ValueError):
            raw = b""
    if not raw and isinstance(flow.get("response_body"), bytes):
        raw = flow["response_body"]

    ct = ""
    hdrs = flow.get("response_headers") or {}
    if isinstance(hdrs, dict):
        for k, v in hdrs.items():
            if str(k).lower() == "content-type":
                ct = str(v)
                break
    n = int(flow.get("response_body_len") or len(raw) or 0)
    head = summary.strip() if summary.startswith("(binary") else (
        f"(binary · {ct or 'unknown'} · {n or len(raw)} bytes)"
    )
    parts = [head, ""]
    if raw:
        parts.append(f"---- Hex（前 {min(len(raw), 2048)} / {len(raw)} bytes）----")
        parts.append(_hex_dump(raw))
        parts.append("")
        parts.append("---- Base64（可复制）----")
        # 折行便于阅读
        b64_out = base64.b64encode(raw).decode("ascii")
        wrap = 76
        parts.extend(b64_out[i : i + wrap] for i in range(0, len(b64_out), wrap))
    else:
        parts.append("（未保存原始字节；请重新采集该流量）")
    return "\n".join(parts)


def format_response_burp(flow: dict, *, max_body: int = 0) -> str:
    """Burp 风格响应报文."""
    resp_body = flow.get("response_body") or ""
    body_kind = str(flow.get("body_kind") or flow.get("_body_kind") or "")
    has_b64 = bool(flow.get("response_body_b64"))

    if isinstance(resp_body, bytes) or body_kind == "binary" or has_b64 or (
        isinstance(resp_body, str) and resp_body.startswith("(binary")
    ):
        if isinstance(resp_body, bytes):
            summary = f"(binary · {len(resp_body)} bytes)"
        else:
            summary = str(resp_body) if str(resp_body).startswith("(binary") else "(binary)"
        # 乱码旧数据且无 b64：提示重采
        if (
            isinstance(resp_body, str)
            and not has_b64
            and not resp_body.startswith("(binary")
        ):
            sample = resp_body[:3000]
            if sample.count("\ufffd") > max(12, len(sample) // 25):
                summary = "(binary · garbled · 无原始字节，请重新采集)"
                resp_body = _format_binary_body(flow, summary)
            else:
                # 当作用文本
                pass
        else:
            resp_body = _format_binary_body(flow, summary)
    else:
        resp_body = str(resp_body)
        sample = resp_body[:3000]
        if sample.count("\ufffd") > max(12, len(sample) // 25):
            resp_body = _format_binary_body(
                flow, "(binary · garbled · 请重新采集以保存原始字节)"
            )

    status = int(flow.get("status") or 0)

    if is_pending_response_body(resp_body):
        return "(pending)"
    if max_body and len(resp_body) > max_body:
        resp_body = resp_body[:max_body] + "\n…(body 已截断)"

    if status <= 0 and not resp_body.strip():
        return "(无响应)"

    # 有正文但 status 仍为 0：多为响应未合并成功，勿伪造 200
    if status <= 0:
        return "(pending — incomplete)\n\n" + resp_body

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
    if (
        not resp
        or resp.startswith("(pending")
        or resp in ("(等待响应…)", "(无响应)", "")
        or is_pending_response_body(flow.get("response_body"))
    ):
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
