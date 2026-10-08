"""浏览器实验室 — Playwright + JS Hook + 流量采集 (独立分析，默认不走 CryptoProxy)."""

from __future__ import annotations

import base64
import json
import os
import queue
from urllib.parse import urlparse

from PyQt6.QtCore import QThread, pyqtSignal

from core.paths import get_app_root

ROOT = get_app_root()
HOOK_SCRIPT = os.path.join(ROOT, "hooks", "crypto_hook.js")
NETWORK_CAPTURE_SCRIPT = os.path.join(ROOT, "hooks", "network_capture.js")
ANTI_DEBUG_SCRIPT = os.path.join(ROOT, "hooks", "anti_debug.js")

_STATIC_SUFFIXES = (
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".css",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".map", ".webp", ".mp4", ".mp3",
)

# URL 路径关键字（勿放 login/auth 等过宽词，否则验证码接口也会进 JS）
_SCRIPT_URL_KEYWORDS = (
    "encrypt", "decrypt", "crypto", "cipher", "sign",
    "security", "anti", "debug", "pack", "obfus", "protect", "guard",
)
# 明确不是 JS 的路径片段
_NON_SCRIPT_URL_NEEDLES = (
    "imgcode", "img_code", "captcha", "verifycode", "verify_code",
    "checkcode", "check_code", "vcode", "smsimg", "getimage", "imagecode",
    "/image/", "/img/", "/pic/", "/captcha/",
)
_BINARY_MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"RIFF", "image/webp"),  # 粗判，后面再看 WEBP
    (b"\x00\x00\x01\x00", "image/x-icon"),
    (b"BM", "image/bmp"),
    (b"PK\x03\x04", "application/zip"),
    (b"\x1f\x8b", "application/gzip"),
)
# 单文件写入 Agent 的上限（过小会截掉页尾 inline debugger，如 sojson ~77k）
_MAX_SCRIPT_STORE = 300_000
_MAX_SCRIPT_READ = 320_000


def _norm_headers(raw: dict | None, max_items: int = 80, max_val: int = 8000) -> dict:
    if not raw or not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in list(raw.items())[:max_items]:
        out[str(k)] = str(v)[:max_val]
    return out


def _header_content_type(headers: dict | None) -> str:
    if not headers:
        return ""
    for k, v in headers.items():
        if str(k).lower() == "content-type":
            return str(v).lower()
    return ""


def _sniff_binary_kind(raw: bytes) -> str | None:
    if not raw:
        return None
    head = raw[:64]
    for magic, kind in _BINARY_MAGIC:
        if head.startswith(magic):
            if magic == b"RIFF" and b"WEBP" not in raw[:16]:
                continue
            return kind
    # 高比例 NUL / 非文本控制字节 → 二进制
    sample = raw[:4096]
    if b"\x00" in sample[:512]:
        return "application/octet-stream"
    ctrl = sum(1 for b in sample if b < 9 or (13 < b < 32))
    if ctrl > max(32, len(sample) // 16):
        return "application/octet-stream"
    return None


def _looks_like_js_text(content: str) -> bool:
    """正文是否像 JS / HTML 源码（非图片乱码）。"""
    if not content:
        return False
    sample = content[:4000]
    if "\ufffd" in sample[:200] and sample.count("\ufffd") > 8:
        return False
    head = sample.lstrip()[:120]
    if head.startswith(("!", "(", "{", "var ", "const ", "let ", "function",
                        "\"use strict", "'use strict", "//", "/*", "import ",
                        "export ", "<!DOCTYPE", "<html", "<!--")):
        return True
    # 常见打包器特征
    low = sample[:800].lower()
    return any(
        x in low
        for x in (
            "webpack", "define(", "require(", "module.exports",
            "window.", "document.", "function(", "=>{",
        )
    )


def _url_looks_non_script(url: str) -> bool:
    low = (url or "").lower()
    path = urlparse(low).path
    if any(path.endswith(ext) for ext in (
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp",
        ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf",
    )):
        return True
    return any(n in low for n in _NON_SCRIPT_URL_NEEDLES)


def _merge_headers(base: dict | None, richer: dict | None) -> dict:
    """合并请求头：以 richer（通常 Playwright）补齐 base（JS Hook）缺失项."""
    out = _norm_headers(base)
    extra = _norm_headers(richer)
    if not extra:
        return out
    if len(extra) >= len(out) + 2:
        # Playwright 头明显更全：以其为主，再叠 JS 里显式设置的
        merged = dict(extra)
        low_extra = {k.lower() for k in merged}
        for k, v in out.items():
            if k.lower() not in low_extra:
                merged[k] = v
        return merged
    low = {k.lower(): k for k in out}
    for k, v in extra.items():
        if k.lower() not in low:
            out[k] = v
    return out


class BrowserLabWorker(QThread):
    """后台线程运行 Playwright，避免阻塞 GUI."""

    log = pyqtSignal(str)
    flow_captured = pyqtSignal(dict)
    flow_updated = pyqtSignal(dict)
    hook_line = pyqtSignal(str)
    script_captured = pyqtSignal(dict)
    stopped = pyqtSignal()

    def __init__(
        self,
        url: str,
        hook_enabled: bool = True,
        anti_debug: bool = True,
        cdp_skip_pauses: bool = True,
        inject_opts: dict | None = None,
        headless: bool = False,
        use_mitm_proxy: bool = False,
        mitm_port: int = 8083,
        load_violentmonkey: bool = True,
        load_reres: bool = True,
        load_cb_hook: bool = True,
        ext_proxy: str | None = "http://127.0.0.1:7897",
        record_mode: bool = True,
        browser_channel: str = "chromium",
        real_browser: bool = False,
        parent=None,
    ):
        super().__init__(parent)
        self.url = url.strip()
        self.hook_enabled = hook_enabled
        self.anti_debug = anti_debug
        self.cdp_skip_pauses = cdp_skip_pauses
        self.inject_opts = dict(inject_opts or {})
        self.headless = headless
        self.use_mitm_proxy = use_mitm_proxy
        self.mitm_port = mitm_port
        self.load_violentmonkey = load_violentmonkey
        self.load_reres = load_reres
        self.load_cb_hook = load_cb_hook
        self.ext_proxy = ext_proxy
        self.record_mode = bool(record_mode)
        self.browser_channel = browser_channel or "chromium"
        self.real_browser = bool(real_browser)
        if self.real_browser:
            # 呜呼有头持久：不挂任何页面脚本 / 扩展 / CDP
            self.hook_enabled = False
            self.anti_debug = False
            self.cdp_skip_pauses = False
            self.load_violentmonkey = False
            self.load_reres = False
            self.load_cb_hook = False
            self.inject_opts = dict(self.inject_opts)
            self.inject_opts["rewriteResponse"] = False
            self.record_mode = True
            self.headless = False
        self._ephemeral_profile: str | None = None
        self._stop_flag = False
        self._seen_flows: set[str] = set()
        self._pending_flow_idx: dict[str, int] = {}
        self._seen_scripts: set[str] = set()
        self._capture_count = 0
        self._script_count = 0
        self._js_capture_enabled = False
        self._rewrite_hits = 0
        self._pause_hits = 0
        self._pause_seen: set[str] = set()
        # Playwright 回调在 Chromium 线程执行，禁止直接 emit Qt 信号（Windows 会 0xC0000409 崩溃）
        self._evt_queue: queue.SimpleQueue = queue.SimpleQueue()

    def stop(self):
        self._stop_flag = True

    def _enqueue(self, item: tuple) -> None:
        try:
            self._evt_queue.put_nowait(item)
        except Exception:
            pass

    def _flow_key(self, flow: dict) -> str:
        return f"{flow.get('method', '')}|{flow.get('url', '')}|{flow.get('request_body', '')[:200]}"

    def _ingest_flow(self, flow: dict) -> None:
        key = self._flow_key(flow)
        phase = flow.get("phase", "response")
        flow = {k: v for k, v in flow.items() if k != "phase"}
        src = (flow.get("source") or "").lower()

        if phase == "request":
            if key in self._seen_flows:
                return
            self._seen_flows.add(key)
            self._capture_count += 1
            pending = dict(flow)
            pending["response_body"] = pending.get("response_body") or "(等待响应…)"
            pending["status"] = 0
            pending.setdefault("request_headers", {})
            pending.setdefault("response_headers", {})
            pending["_key"] = key
            self._pending_flow_idx[key] = self._capture_count - 1
            self.flow_captured.emit(pending)
            short_url = (flow.get("url") or "")[:70]
            self.log.emit(f"→ #{self._capture_count} {flow.get('method')} {short_url}")
            return

        if key in self._pending_flow_idx:
            flow["_key"] = key
            flow["_index"] = self._pending_flow_idx.pop(key)
            # Playwright 头更全时带上，供 GUI 合并
            if "playwright" in src or src in ("xhr", "fetch", "document"):
                flow["_prefer_pw_headers"] = True
            self.flow_updated.emit(flow)
            short_url = (flow.get("url") or "")[:70]
            self.log.emit(
                f"✓ #{flow['_index'] + 1} [{flow.get('status')}] {short_url} "
                f"({flow.get('source', 'js-hook')})"
            )
            return

        if key in self._seen_flows:
            # JS 已完成该条：若 Playwright 随后到来，只补全请求头
            if flow.get("request_headers") or flow.get("response_headers"):
                flow["_key"] = key
                flow["_headers_patch"] = True
                self.flow_updated.emit(flow)
            return

        self._seen_flows.add(key)
        self._capture_count += 1
        flow["_key"] = key
        self.flow_captured.emit(flow)
        short_url = (flow.get("url") or "")[:70]
        self.log.emit(
            f"捕获 #{self._capture_count} [{flow.get('method')}] {short_url} "
            f"({flow.get('source', 'js-hook')})"
        )

    def _flow_from_capture_data(self, data: dict) -> dict:
        return {
            "method": data.get("method", "GET"),
            "url": data.get("url", ""),
            "request_body": (data.get("request_body") or "")[:200000],
            "response_body": (data.get("response_body") or "")[:200000],
            "request_headers": _norm_headers(data.get("request_headers")),
            "response_headers": _norm_headers(data.get("response_headers")),
            "status": data.get("status", 0),
            "source": data.get("source", "js-hook"),
            "phase": data.get("phase", "response"),
        }

    def _process_capture_payload(self, payload) -> None:
        if self._stop_flag:
            return
        try:
            if isinstance(payload, str):
                data = json.loads(payload)
            elif isinstance(payload, dict):
                data = payload
            else:
                return
            self._ingest_flow(self._flow_from_capture_data(data))
        except (json.JSONDecodeError, TypeError, KeyError):
            pass

    def _handle_js_capture(self, _source, payload) -> None:
        self._enqueue(("capture", payload))

    def _drain_events(self) -> None:
        while True:
            try:
                kind, data = self._evt_queue.get_nowait()
            except queue.Empty:
                break
            if kind == "capture":
                self._process_capture_payload(data)
            elif kind == "hook":
                self.hook_line.emit(str(data))
            elif kind == "script":
                url, content = data
                self._emit_script(url, content)
            elif kind == "flow":
                self._ingest_flow(data)
            elif kind == "log":
                self.log.emit(str(data))

    @staticmethod
    def _looks_static(url: str) -> bool:
        path = urlparse(url).path.lower()
        return any(path.endswith(s) for s in _STATIC_SUFFIXES)

    @staticmethod
    def _is_api_like(request, response_headers: dict | None = None) -> bool:
        rt = request.resource_type
        if rt in ("xhr", "fetch"):
            return True
        if rt in ("image", "stylesheet", "script", "font", "media", "websocket", "manifest"):
            return False
        headers = request.headers
        accept = (headers.get("accept") or "").lower()
        ctype = (headers.get("content-type") or "").lower()
        if response_headers:
            ctype = ctype or (response_headers.get("content-type") or "").lower()
        if "json" in accept or "json" in ctype:
            return True
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            return rt in ("xhr", "fetch", "other", "")
        return False

    def _read_response_body(self, response, max_bytes: int = 120_000) -> str:
        text, _kind, _raw = self._read_response_payload(response, max_bytes=max_bytes)
        return text

    def _read_response_payload(
        self, response, max_bytes: int = 120_000
    ) -> tuple[str, str, bytes | None]:
        """返回 (展示正文, kind, raw_bytes)。

        kind=text|binary|empty。二进制不把乱码塞进 response_body，原始字节经 raw 返回。
        """
        try:
            headers = dict(response.headers or {})
            ct = _header_content_type(headers)
            cl = headers.get("content-length") or headers.get("Content-Length")
            if cl:
                try:
                    if int(cl) > max_bytes * 4 and (
                        ct.startswith("image/")
                        or "octet-stream" in ct
                        or "font" in ct
                    ):
                        # 过大：仍尽量读一段原始供详情 Hex/Base64
                        raw = response.body() or b""
                        if len(raw) > max_bytes:
                            raw = raw[:max_bytes]
                        return (
                            f"(binary · {ct or 'unknown'} · {cl} bytes，详情见 Base64/Hex)",
                            "binary",
                            raw or None,
                        )
                except ValueError:
                    pass
            raw = response.body()
            if not raw:
                return "", "empty", None
            if len(raw) > max_bytes:
                raw = raw[:max_bytes]
            if ct.startswith(("image/", "audio/", "video/", "font/")) or "octet-stream" in ct:
                return (
                    f"(binary · {ct} · {len(raw)} bytes，详情见 Base64/Hex)",
                    "binary",
                    raw,
                )
            sniffed = _sniff_binary_kind(raw)
            if sniffed:
                return (
                    f"(binary · {sniffed} · {len(raw)} bytes，详情见 Base64/Hex)",
                    "binary",
                    raw,
                )
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                if _sniff_binary_kind(raw) or raw.count(0) > 4:
                    return (
                        f"(binary · {ct or 'unknown'} · {len(raw)} bytes，详情见 Base64/Hex)",
                        "binary",
                        raw,
                    )
                text = raw.decode("utf-8", errors="replace")
            if text.count("\ufffd") > max(12, len(text[:2000]) // 25):
                return (
                    f"(binary · {ct or 'unknown'} · {len(raw)} bytes，详情见 Base64/Hex)",
                    "binary",
                    raw,
                )
            return text, "text", None
        except Exception:
            return "", "empty", None

    def _script_url_interesting(self, url: str) -> bool:
        if _url_looks_non_script(url):
            return False
        low = (url or "").lower()
        path = urlparse(low).path
        if path.endswith((".js", ".mjs", ".cjs")):
            return True
        return any(k in low for k in _SCRIPT_URL_KEYWORDS)

    def _on_console(self, msg) -> None:
        text = msg.text or ""
        if text.startswith("[capture] "):
            if self._js_capture_enabled:
                return
            self._enqueue(("capture", text[10:]))
            return
        if "[debug]" in text:
            self._enqueue(("hook", text))

    def _should_record_flow(self, request, response_headers: dict | None = None) -> bool:
        """是否记入「流量」列表。图片/二进制进流量；不进 JS（由脚本采集单独过滤）。"""
        url = request.url or ""
        rt = (request.resource_type or "").lower()
        ct = _header_content_type(response_headers)
        # 纯噪音：样式/字体/媒体流/websocket — 仍跳过
        if rt in ("stylesheet", "font", "media", "websocket", "manifest", "ping"):
            return False
        if ct.startswith(("font/", "text/css", "audio/", "video/")):
            return False
        # 图片 / 验证码二进制 → 流量
        if rt == "image" or ct.startswith("image/") or "octet-stream" in ct:
            return True
        if _url_looks_non_script(url) and any(
            n in (url or "").lower()
            for n in (
                "imgcode", "captcha", "verifycode", "checkcode",
                "imagecode", "vcode",
            )
        ):
            return True
        if rt in ("xhr", "fetch"):
            return True
        # 主文档（HTML）始终进流量，便于看见打开了哪一页
        if rt == "document":
            return True
        if self._is_api_like(request, response_headers):
            return True
        # 静态 .js/.css 等：除 xhr/fetch/image 外跳过（.js 走「JS」页采集）
        if self._looks_static(url) and rt not in ("xhr", "fetch", "other", "image"):
            return False
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            return True
        return False

    def _on_request(self, request) -> None:
        """Playwright 请求阶段：真实浏览器模式下先占位，不依赖页面注入。"""
        if self._stop_flag or not self.real_browser:
            return
        try:
            url = request.url or ""
            if url.startswith(("data:", "blob:", "chrome-extension:", "chrome:")):
                return
            if not self._should_record_flow(request):
                return
            try:
                req_hdrs = dict(request.all_headers())
            except Exception:
                req_hdrs = dict(request.headers)
            self._enqueue(("flow", {
                "method": request.method,
                "url": url,
                "request_body": (request.post_data or "")[:200000],
                "response_body": "",
                "request_headers": _norm_headers(req_hdrs),
                "response_headers": {},
                "status": 0,
                "source": "playwright",
                "phase": "request",
            }))
        except Exception:
            pass

    def _emit_script(self, url: str, content: str) -> None:
        if not url or not content or url in self._seen_scripts:
            return
        self._seen_scripts.add(url)
        self._script_count += 1
        try:
            from core.script_enrich import strip_source_maps

            body, removed = strip_source_maps(content)
        except Exception:
            body = content
            removed = 0
        stored = body[:_MAX_SCRIPT_STORE]
        self.script_captured.emit({
            "url": url,
            "content": stored,
            "size": len(body),
            "raw_size": len(content),
            "sourcemap_removed": int(removed),
        })
        short = url.split("/")[-1][:50]
        note = ""
        if removed:
            note += f"，已剥 source map -{removed}"
        if len(body) > _MAX_SCRIPT_STORE:
            note += f"，已截断存 {_MAX_SCRIPT_STORE}"
        self.log.emit(f"JS #{self._script_count}: {short} ({len(stored)} bytes{note})")

    def _should_capture_script(self, url: str, content: str) -> bool:
        if not content or len(content) < 80:
            return False
        if content.startswith("(binary"):
            return False
        if _url_looks_non_script(url):
            return False
        if not _looks_like_js_text(content):
            return False
        low = (url or "").lower()
        if any(
            x in low
            for x in (
                "google-analytics",
                "googletagmanager",
                "gtag/js",
                "clarity.ms",
                "hotjar",
            )
        ):
            return False
        path = urlparse(url).path.lower()
        if path.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx")):
            return True
        if self._script_url_interesting(url):
            return True
        keywords = (
            "encrypt", "decrypt", "cryptojs", "aes", "cipher", "rsa",
            "debugger", "setinterval", "devtools", "console.clear", "outerwidth",
        )
        head = content[:8000].lower()
        tail = content[-12000:].lower() if len(content) > 8000 else ""
        blob = head + "\n" + tail
        return any(k in blob for k in keywords)

    def _on_response(self, response) -> None:
        """Playwright 网络层采集（不注入页面；真实浏览器全靠这条）。"""
        if self._stop_flag:
            return
        url = ""
        try:
            req = response.request
            url = req.url or ""
            if url.startswith(("data:", "blob:", "chrome-extension:", "chrome:")):
                return
            rt = (req.resource_type or "").lower()
            resp_hdrs = dict(response.headers or {})
            ct = _header_content_type(resp_hdrs)

            # 1) 脚本/文档：跳过图片等二进制
            try:
                if rt in ("image", "font", "media", "stylesheet", "websocket"):
                    pass
                elif ct.startswith(("image/", "audio/", "video/", "font/")):
                    pass
                elif _url_looks_non_script(url):
                    pass
                elif rt in ("script", "document") or self._script_url_interesting(url):
                    content, kind, _raw = self._read_response_payload(
                        response, max_bytes=_MAX_SCRIPT_READ
                    )
                    if kind == "text" and content and self._should_capture_script(url, content):
                        self._enqueue(("script", (url, content)))
            except Exception:
                pass

            # 2) 流量（含图片/二进制；原始字节存 Base64，详情可查看）
            if not self._should_record_flow(req, resp_hdrs):
                return
            req_body = req.post_data or ""
            resp_body, body_kind, raw = self._read_response_payload(response)
            if (
                not self.real_browser
                and body_kind != "binary"
                and not req_body.strip()
                and not resp_body.strip()
            ):
                return
            try:
                req_hdrs = dict(req.all_headers())
            except Exception:
                req_hdrs = dict(req.headers)
            flow = {
                "method": req.method,
                "url": url,
                "request_body": req_body[:200000],
                "response_body": (resp_body or "")[:200000],
                "request_headers": _norm_headers(req_hdrs),
                "response_headers": _norm_headers(resp_hdrs),
                "status": response.status,
                "source": "playwright",
                "phase": "response",
                "body_kind": body_kind,
            }
            if body_kind == "binary" and raw:
                # 原始数据：Base64（上限约 120KB 原字节）
                flow["response_body_b64"] = base64.b64encode(raw).decode("ascii")
                flow["response_body_len"] = len(raw)
            self._enqueue(("flow", flow))
        except Exception as e:
            if url:
                self._enqueue(("log", f"捕获跳过 {url[:60]}: {type(e).__name__}"))

    def run(self):
        import sys
        from core.playwright_env import setup_playwright_browsers_path, has_bundled_chromium

        setup_playwright_browsers_path()
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            py = sys.executable
            self.log.emit(
                f"未安装 Playwright（当前 Python:\n  {py}）\n\n"
                f"请在该解释器下执行:\n"
                f'  "{py}" -m pip install playwright\n'
                f'  "{py}" -m playwright install chromium\n\n'
                "完成后重启 GUI。"
            )
            self.stopped.emit()
            return

        if getattr(sys, "frozen", False) and not has_bundled_chromium():
            # 真实浏览器 / 本机 Chrome·Edge 不依赖内置 Chromium
            from core.ai_config import normalize_browser_channel

            ch = normalize_browser_channel(self.browser_channel)
            if not self.real_browser and ch == "chromium":
                self.log.emit(
                    "未找到内置 Chromium（ms-playwright 目录）。\n"
                    "请使用完整绿色版包，或联系发布者重新打包。"
                )
                self.stopped.emit()
                return

        if self.real_browser:
            self.log.emit(
                "真实浏览器模式：本机 Chrome/Edge，不注入页面脚本；"
                "流量/JS 由 Playwright 网络层采集（呜呼思路）"
            )
        elif self.use_mitm_proxy:
            self.log.emit(f"启动浏览器（经解密端 127.0.0.1:{self.mitm_port}）…")
        else:
            self.log.emit("启动浏览器（直连 + 页面内 Hook；未走解密端代理）…")
        try:
            from core.browser_ext_manager import (
                consume_pending_userscript_install,
                ensure_vendor_extensions,
                list_extension_paths,
            )
            from core.playwright_env import (
                apply_launch_channel,
                channel_label,
                profile_dir_for_channel,
                real_browser_channel_attempts,
            )

            # 扩展需 persistent context；真实浏览器模式完全不加载扩展
            if self.real_browser:
                ext_paths = []
            else:
                if self.load_violentmonkey or self.load_reres:
                    ensure_vendor_extensions(
                        want_vm=self.load_violentmonkey,
                        want_reres=self.load_reres,
                        proxy=self.ext_proxy,
                        log=lambda m: self.log.emit(m),
                    )
                ext_paths = list_extension_paths(
                    load_violentmonkey=self.load_violentmonkey,
                    load_reres=self.load_reres,
                    load_cb_hook=self.load_cb_hook,
                )
                # 双保险：过滤任何 vendor/.../reres（MV2）
                ext_paths = [
                    p for p in ext_paths
                    if not (
                        os.path.basename(p.rstrip("\\/")).lower() == "reres"
                        and f"{os.sep}vendor{os.sep}" in (p.replace("/", os.sep) + os.sep)
                    )
                ]

            if self.real_browser:
                # 呜呼：只关 AutomationControlled，不挂其它指纹/扩展参数
                launch_args = [
                    "--disable-blink-features=AutomationControlled",
                    "--ignore-certificate-errors",
                ]
            else:
                launch_args = [
                    "--ignore-certificate-errors",
                    "--enable-extensions",
                ]
                if ext_paths:
                    joined = ",".join(ext_paths)
                    launch_args.append(f"--disable-extensions-except={joined}")
                    launch_args.append(f"--load-extension={joined}")
                    self.log.emit(f"将加载 {len(ext_paths)} 个扩展：")
                    for p in ext_paths:
                        name = os.path.basename(p.rstrip("\\/"))
                        label = {
                            "cb_hook": "CipherBridge Hook",
                            "violentmonkey": "暴力猴 Violentmonkey",
                            "reres": "ReRes MV3（请求映射）",
                        }.get(name, name)
                        self.log.emit(f"  · {label}")

            # 记录模式：固定持久 profile；关闭则临时目录（关浏览器后删除）
            # 真实浏览器强制持久目录（呜呼 headed persistent）
            if self.record_mode or self.real_browser:
                user_data_dir = profile_dir_for_channel(self.browser_channel)
                os.makedirs(user_data_dir, exist_ok=True)
                self.log.emit(
                    f"记录模式 · {channel_label(self.browser_channel)} → {user_data_dir}"
                )
            else:
                import tempfile

                user_data_dir = tempfile.mkdtemp(prefix="cb_browser_")
                self._ephemeral_profile = user_data_dir
                self.log.emit(
                    f"非记录模式 · {channel_label(self.browser_channel)}（临时）→ {user_data_dir}"
                )

            with sync_playwright() as p:
                ctx_opts: dict = {
                    "headless": False if self.real_browser else (bool(self.headless) and not ext_paths),
                    "args": launch_args,
                    "ignore_https_errors": True,
                    "viewport": None,
                }
                # 加载了 cb_hook 时：用扩展 chrome.proxy 控代理，便于弹窗切换；
                # 不再写 --proxy-server（命令行代理会锁死，扩展无法改直连）。
                use_ext_proxy = (
                    not self.real_browser
                    and bool(self.load_cb_hook)
                    and any(
                        os.path.basename(p.rstrip("\\/")).lower() == "cb_hook"
                        for p in ext_paths
                    )
                )
                if use_ext_proxy:
                    try:
                        from core.browser_ext_manager import write_proxy_pref

                        if self.use_mitm_proxy:
                            write_proxy_pref(
                                mode="decrypt",
                                host="127.0.0.1",
                                port=int(self.mitm_port or 8083),
                            )
                            self.log.emit(
                                f"代理由 Hook 扩展控制 → 解密端 127.0.0.1:{self.mitm_port}"
                                "（工具栏图标可切换直连/Burp）"
                            )
                        else:
                            write_proxy_pref(mode="direct")
                            self.log.emit("代理由 Hook 扩展控制 → 直连（可在扩展弹窗改）")
                    except Exception as e:
                        self.log.emit(f"写入代理偏好失败: {e}")
                elif self.use_mitm_proxy:
                    proxy = f"http://127.0.0.1:{self.mitm_port}"
                    ctx_opts["proxy"] = {"server": proxy}
                    # Chromium 层再强制一次，避免 persistent context 代理未生效
                    launch_args.append(f"--proxy-server={proxy}")
                    launch_args.append("--proxy-bypass-list=<-loopback>")
                    ctx_opts["args"] = launch_args
                # 扩展只能挂在 persistent context
                from core.browser_stealth import (
                    apply_stealth_to_context,
                    apply_playwright_marker_cleanup,
                    merge_launch_options,
                    stealth_summary,
                    wait_out_js_challenge_sync,
                )

                def _launch_with_channel(ch: str, udir: str):
                    opts = dict(ctx_opts)
                    opts = apply_launch_channel(opts, ch)
                    if self.real_browser:
                        # 不 merge 全套 stealth args，只保留呜呼那一条 + ignoreHTTPS
                        opts["ignore_default_args"] = ["--enable-automation"]
                    else:
                        opts = merge_launch_options(opts, for_lab=True)
                    return p.chromium.launch_persistent_context(udir, **opts)

                context = None
                if self.real_browser:
                    last_err = None
                    for ch in real_browser_channel_attempts(self.browser_channel):
                        udir = profile_dir_for_channel(ch)
                        os.makedirs(udir, exist_ok=True)
                        try:
                            context = _launch_with_channel(ch, udir)
                            self.browser_channel = ch
                            user_data_dir = udir
                            self.log.emit(f"已用 {channel_label(ch)} 启动（真实浏览器）")
                            break
                        except Exception as e:
                            last_err = e
                            self.log.emit(f"{channel_label(ch)} 启动失败，尝试下一个… ({e})")
                    if context is None:
                        raise last_err or RuntimeError("真实浏览器启动失败")
                else:
                    self.log.emit(f"拟真环境：{stealth_summary()}")
                    try:
                        context = _launch_with_channel(self.browser_channel, user_data_dir)
                    except Exception as e:
                        if self.browser_channel and "chrome" in str(self.browser_channel).lower():
                            self.log.emit(
                                f"本机 Chrome 启动失败: {e}\n"
                                "请确认已安装 Google Chrome，或改回「Chromium（内置）」。"
                            )
                        raise
                try:
                    if not self.real_browser:
                        apply_stealth_to_context(context)
                        # 站点早期补丁必须赶在页面脚本 / expose_binding 之前
                        # （扩展 bootstrap 是 async，赶不上 fpscanner 等同步 CDP 检测）
                        if self.load_cb_hook:
                            from core.browser_ext_manager import SITE_EARLY_HOOK_PATH

                            if os.path.isfile(SITE_EARLY_HOOK_PATH):
                                with open(SITE_EARLY_HOOK_PATH, encoding="utf-8") as f:
                                    context.add_init_script(f.read())
                                self.log.emit(
                                    "已注入站点早期补丁 site_early_hook.js（init_script）"
                                )
                    # 与「反调试」勾选绑定：中和页面反 DevTools（防闪一下变 about:blank）
                    if self.anti_debug:
                        from core.disable_devtool_guard import (
                            DISABLE_DEVTOOL_GUARD_JS,
                            install_disable_devtool_routes,
                        )

                        context.add_init_script(DISABLE_DEVTOOL_GUARD_JS)
                        install_disable_devtool_routes(
                            context, log=lambda m: self.log.emit(m)
                        )
                        self.log.emit("已启用反 DevTools 中和（随「反调试」开启）")
                except Exception as e:
                    self.log.emit(f"拟真脚本注入提示: {e}")

                # 反调试须最先注入，抢在业务 JS 之前；选项可按站点勾选
                if self.anti_debug and os.path.isfile(ANTI_DEBUG_SCRIPT):
                    opts_json = json.dumps(self.inject_opts, ensure_ascii=False)
                    context.add_init_script(f"window.__cbInjectOpts = {opts_json};")
                    with open(ANTI_DEBUG_SCRIPT, encoding="utf-8") as f:
                        context.add_init_script(f.read())
                    on_flags = ",".join(k for k, v in self.inject_opts.items() if v) or "(默认)"
                    self.log.emit(f"已注入 anti_debug.js（模块: {on_flags}）")

                # 真实浏览器：不注入 network_capture（瑞数等挑战会识别）
                if (not self.real_browser) and os.path.isfile(NETWORK_CAPTURE_SCRIPT):
                    context.expose_binding("cpCapture", self._handle_js_capture)
                    with open(NETWORK_CAPTURE_SCRIPT, encoding="utf-8") as f:
                        context.add_init_script(f.read())
                    self._js_capture_enabled = True
                    self.log.emit("已注入 network_capture.js（含请求/响应头）")

                if self.hook_enabled and os.path.isfile(HOOK_SCRIPT):
                    with open(HOOK_SCRIPT, encoding="utf-8") as f:
                        context.add_init_script(f.read())
                    self.log.emit("已注入 crypto_hook.js — 触发加密后显示密钥")

                # 所有 init / expose_binding 之后再清 Playwright 全局标记（抗 hasPlaywright）
                if not self.real_browser:
                    try:
                        apply_playwright_marker_cleanup(context)
                    except Exception as e:
                        self.log.emit(f"Playwright 标记清理提示: {e}")

                # 响应改写：字面量 debugger → return（打断递归）；空 while(true){} 剔除
                rewrite_on = bool(self.inject_opts.get("rewriteResponse", True))
                if self.anti_debug and rewrite_on:
                    from core.anti_debug_rewrite import rewrite_anti_debug_js, should_rewrite_url

                    def _on_route(route):
                        try:
                            req = route.request
                            url = req.url or ""
                            # 不改写扩展 / 数据 URL
                            if url.startswith(("chrome-extension:", "data:", "blob:")):
                                route.continue_()
                                return
                            resp = route.fetch()
                            headers = dict(resp.headers or {})
                            ct = headers.get("content-type") or headers.get("Content-Type") or ""
                            if not should_rewrite_url(url, ct):
                                route.fulfill(response=resp)
                                return
                            body = resp.body()
                            if not body or len(body) > _MAX_SCRIPT_READ:
                                route.fulfill(response=resp)
                                return
                            try:
                                text = body.decode("utf-8")
                            except UnicodeDecodeError:
                                route.fulfill(response=resp)
                                return
                            new_text, stats = rewrite_anti_debug_js(text)
                            if any(stats.get(k) for k in ("debugger", "unicode", "hex", "concat", "empty_while")):
                                self._rewrite_hits += 1
                                parts = []
                                for k, label in (
                                    ("debugger", "明文"),
                                    ("unicode", "unicode"),
                                    ("hex", "hex"),
                                    ("concat", "拼接"),
                                    ("empty_while", "死循环"),
                                ):
                                    n = int(stats.get(k) or 0)
                                    if n:
                                        parts.append(f"{label}×{n}")
                                self._enqueue((
                                    "log",
                                    f"响应改写 #{self._rewrite_hits}: "
                                    + " ".join(parts)
                                    + f" @ {url[:80]}",
                                ))
                                route.fulfill(
                                    response=resp,
                                    body=new_text.encode("utf-8"),
                                )
                            else:
                                route.fulfill(response=resp)
                        except Exception as e:
                            try:
                                route.continue_()
                            except Exception:
                                pass
                            self._enqueue(("log", f"响应改写跳过: {type(e).__name__}"))

                    context.route("**/*", _on_route)
                    self.log.emit("已开启响应改写：debugger→return（治字面量+递归）")

                context.on("response", self._on_response)
                context.on("request", self._on_request)
                context.on("console", self._on_console)
                if self.real_browser:
                    self.log.emit(
                        "已挂 Playwright 网络监听（不注入页面脚本，流量/JS 从浏览器层采集）"
                    )

                page = context.pages[0] if context.pages else context.new_page()
                if self.anti_debug and self.cdp_skip_pauses:
                    try:
                        cdp = context.new_cdp_session(page)
                        cdp.send("Debugger.enable")
                        # 不用 setSkipAllPauses：否则收不到 paused，无法定位。
                        # 改为 paused → 记录 URL:行:列 → 立即 resume（几乎不卡）。

                        def _on_paused(event=None):
                            try:
                                ev = event if isinstance(event, dict) else {}
                                reason = str(ev.get("reason") or "")
                                frames = ev.get("callFrames") or []
                                locs = []
                                for fr in frames[:6]:
                                    if not isinstance(fr, dict):
                                        continue
                                    loc = fr.get("location") or {}
                                    url = str(fr.get("url") or "") or "(inline/eval)"
                                    # CDP 行号从 0 起，展示时 +1
                                    line = int(loc.get("lineNumber") or 0) + 1
                                    col = int(loc.get("columnNumber") or 0)
                                    fn = str(fr.get("functionName") or "") or "(anonymous)"
                                    locs.append(f"{url}:{line}:{col} · {fn}")
                                top = locs[0] if locs else f"(无栈 reason={reason})"
                                # 同位置只报一次，避免刷屏
                                if top not in self._pause_seen:
                                    self._pause_seen.add(top)
                                    self._pause_hits += 1
                                    msg = (
                                        f"[debug] debugger 命中 #{self._pause_hits} "
                                        f"reason={reason or '?'} @ {top}"
                                    )
                                    self._enqueue(("hook", msg))
                                    self._enqueue(("log", msg))
                                    for extra in locs[1:4]:
                                        self._enqueue(("log", f"  ↑ {extra}"))
                            except Exception as e:
                                self._enqueue(("log", f"CDP paused 解析失败: {type(e).__name__}"))
                            try:
                                cdp.send("Debugger.resume")
                            except Exception:
                                pass

                        try:
                            cdp.on("Debugger.paused", _on_paused)
                        except Exception:
                            pass
                        self.log.emit(
                            "CDP：已启用 debugger 定位（暂停即记录 URL:行号 并自动继续）"
                        )
                    except Exception as e:
                        self.log.emit(f"CDP 反调试未生效（可忽略）: {e}")

                # 若刚生成过用户脚本，打开 file:// 触发油猴安装确认
                pending = consume_pending_userscript_install()
                if pending and self.load_violentmonkey:
                    try:
                        from pathlib import Path

                        uri = Path(pending).resolve().as_uri()
                        self.log.emit("打开油猴用户脚本安装页（若弹出请点「安装」）…")
                        install_page = context.new_page()
                        install_page.goto(uri, wait_until="domcontentloaded", timeout=15000)
                    except Exception as e:
                        self.log.emit(f"打开用户脚本安装页失败（可手动导入）: {e}")

                target = self.url if self.url.startswith("http") else f"https://{self.url}"
                self.log.emit(f"打开: {target}")
                page.goto(target, wait_until="domcontentloaded", timeout=60000)
                wait_out_js_challenge_sync(
                    page,
                    log=lambda m: self.log.emit(m),
                )
                self.log.emit("页面已打开；API 请求会立即出现在左侧列表")

                while not self._stop_flag:
                    self._drain_events()
                    page.wait_for_timeout(100)

                self._drain_events()
                context.close()
        except Exception as e:
            self.log.emit(f"浏览器错误: {e}")
        finally:
            ephem = self._ephemeral_profile
            self._ephemeral_profile = None
            if ephem:
                try:
                    import shutil

                    shutil.rmtree(ephem, ignore_errors=True)
                    self.log.emit("已清理临时 Profile")
                except Exception:
                    pass
        self.log.emit(
            f"浏览器已关闭（流量 {self._capture_count} 条，JS {self._script_count} 个）"
        )
        self.stopped.emit()
