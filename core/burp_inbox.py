"""接收 Burp 扩展右键发来的流量（本机 HTTP）。"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import urlparse

from PyQt6.QtCore import QObject, pyqtSignal

DEFAULT_INBOX_PORT = 19528


def _headers_from_list(lines: list | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not isinstance(lines, list):
        return out
    for line in lines:
        if not isinstance(line, str) or ":" not in line:
            continue
        # skip request/status line if present
        if line.startswith("HTTP/") or (
            " " in line.split(":", 1)[0] and line.split(" ", 1)[0].upper()
            in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
        ):
            continue
        k, v = line.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def normalize_burp_flow(raw: dict) -> dict[str, Any]:
    """把 Burp 扩展推送的 JSON 收成密桥 flow 结构."""
    method = str(raw.get("method") or "GET").upper()
    url = str(raw.get("url") or "").strip()
    req_headers = raw.get("request_headers")
    if isinstance(req_headers, list):
        req_headers = _headers_from_list(req_headers)
    elif not isinstance(req_headers, dict):
        req_headers = {}
    else:
        req_headers = {str(k): "" if v is None else str(v) for k, v in req_headers.items()}

    resp_headers = raw.get("response_headers")
    if isinstance(resp_headers, list):
        resp_headers = _headers_from_list(resp_headers)
    elif not isinstance(resp_headers, dict):
        resp_headers = {}
    else:
        resp_headers = {str(k): "" if v is None else str(v) for k, v in resp_headers.items()}

    body = raw.get("request_body")
    if body is None:
        body = ""
    elif isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    else:
        body = str(body)

    resp_body = raw.get("response_body")
    if resp_body is None:
        resp_body = ""
    elif isinstance(resp_body, bytes):
        resp_body = resp_body.decode("utf-8", errors="replace")
    else:
        resp_body = str(resp_body)

    try:
        status = int(raw.get("status") or 0)
    except Exception:
        status = 0

    if not url and req_headers.get("Host"):
        path = str(raw.get("path") or "/")
        scheme = str(raw.get("protocol") or "http")
        url = f"{scheme}://{req_headers.get('Host')}{path}"

    return {
        "method": method,
        "url": url,
        "request_headers": req_headers,
        "request_body": body,
        "response_headers": resp_headers,
        "response_body": resp_body,
        "status": status,
        "source": "burp",
        "_list_prefix": "[Burp] ",
    }


class _Handler(BaseHTTPRequestHandler):
    inbox: "BurpFlowInbox"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return

    def _send(self, code: int, obj: dict) -> None:
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/", "/health"):
            self._send(
                200,
                {
                    "ok": True,
                    "service": "CipherBridge Burp Inbox",
                    "port": self.inbox.port,
                },
            )
            return
        self._send(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8", errors="replace") or "{}")
        except Exception:
            self._send(400, {"ok": False, "error": "invalid json"})
            return

        if path in ("/flows", "/flow", "/ingest"):
            items = payload.get("flows")
            if items is None and isinstance(payload, dict) and (
                payload.get("url") or payload.get("method") or payload.get("request")
            ):
                items = [payload]
            if not isinstance(items, list) or not items:
                self._send(400, {"ok": False, "error": "flows array required"})
                return
            flows = []
            for it in items[:50]:
                if isinstance(it, dict):
                    flows.append(normalize_burp_flow(it))
            if not flows:
                self._send(400, {"ok": False, "error": "no valid flows"})
                return
            self.inbox.emit_flows(flows)
            self._send(200, {"ok": True, "count": len(flows)})
            return

        self._send(404, {"ok": False, "error": "not found"})


class BurpFlowInbox(QObject):
    """本机接收 Burp「发送到密桥」的流量."""

    flows_received = pyqtSignal(list)
    status = pyqtSignal(str)

    def __init__(self, port: int = DEFAULT_INBOX_PORT, parent=None):
        super().__init__(parent)
        self.port = int(port)
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def emit_flows(self, flows: list[dict]) -> None:
        self.flows_received.emit(list(flows))

    def start(self) -> bool:
        if self._httpd is not None:
            return True

        class BoundHandler(_Handler):
            pass

        BoundHandler.inbox = self
        try:
            self._httpd = ThreadingHTTPServer(("127.0.0.1", self.port), BoundHandler)
        except OSError as e:
            self.status.emit(f"Burp 收件箱启动失败 :{self.port} — {e}")
            self._httpd = None
            return False

        def _run():
            try:
                self._httpd.serve_forever(poll_interval=0.5)
            except Exception:
                pass

        self._thread = threading.Thread(target=_run, name="burp-inbox", daemon=True)
        self._thread.start()
        self.status.emit(f"Burp 收件箱已监听 127.0.0.1:{self.port}（右键流量→发送到密桥）")
        return True

    def stop(self) -> None:
        httpd = self._httpd
        self._httpd = None
        if httpd is not None:
            try:
                httpd.shutdown()
            except Exception:
                pass
            try:
                httpd.server_close()
            except Exception:
                pass
        self._thread = None
