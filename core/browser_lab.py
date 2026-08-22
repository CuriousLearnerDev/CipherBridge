"""浏览器实验室 — Playwright + JS Hook + 流量采集 (独立分析，默认不走 CryptoProxy)."""

from __future__ import annotations

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
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".map", ".webp", ".mp4", ".mp3",
)

# 业务加解密 + 反调试常见命名；过窄会导致 security.js 等被丢掉
_SCRIPT_URL_KEYWORDS = (
    "encrypt", "decrypt", "crypto", "cipher", "login", "auth", "sign", "password",
    "security", "anti", "debug", "pack", "obfus", "protect", "guard",
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
        try:
            cl = response.headers.get("content-length") or response.headers.get("Content-Length")
            if cl:
                try:
                    if int(cl) > max_bytes:
                        return ""
                except ValueError:
                    pass
            raw = response.body()
            if not raw:
                return ""
            if len(raw) > max_bytes:
                raw = raw[:max_bytes]
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _script_url_interesting(self, url: str) -> bool:
        low = (url or "").lower()
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

    def _emit_script(self, url: str, content: str) -> None:
        if not url or not content or url in self._seen_scripts:
            return
        self._seen_scripts.add(url)
        self._script_count += 1
        stored = content[:_MAX_SCRIPT_STORE]
        self.script_captured.emit({
            "url": url,
            "content": stored,
            "size": len(content),
        })
        short = url.split("/")[-1][:50]
        note = ""
        if len(content) > _MAX_SCRIPT_STORE:
            note = f"，已截断存 {_MAX_SCRIPT_STORE}"
        self.log.emit(f"JS #{self._script_count}: {short} ({len(content)} bytes{note})")

    def _should_capture_script(self, url: str, content: str) -> bool:
        if not content or len(content) < 80:
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
        if self._script_url_interesting(url):
            return True
        # 同站 .js 默认收录（反调试常在 security / pack 等无关键字文件里）
        path = urlparse(url).path.lower()
        if path.endswith(".js") or path.endswith(".mjs"):
            return True
        # 文档页：含反调试或加解密痕迹才收录
        keywords = (
            "encrypt", "decrypt", "cryptojs", "aes", "password", "cipher", "rsa",
            "debugger", "setinterval", "devtools", "console.clear", "outerwidth",
        )
        head = content[:8000].lower()
        # 页尾 inline 反调试常见，也扫尾部
        tail = content[-12000:].lower() if len(content) > 8000 else ""
        blob = head + "\n" + tail
        return any(k in blob for k in keywords)

    def _on_response(self, response) -> None:
        """Playwright 网络层：补全真实请求头；JS Hook 开启时仍抓脚本."""
        if self._stop_flag:
            return
        url = ""
        try:
            req = response.request
            url = req.url or ""
            # 1) 脚本采集（JS Hook 开启时主要靠这条）
            if self._js_capture_enabled:
                try:
                    rt = req.resource_type or ""
                    if rt in ("script", "document") or self._script_url_interesting(url):
                        content = self._read_response_body(response, max_bytes=_MAX_SCRIPT_READ)
                        if content and self._should_capture_script(url, content):
                            self._enqueue(("script", (url, content)))
                except Exception:
                    pass

            # 2) API 流量：始终用 Playwright 头（含 Cookie/UA 等浏览器自动头）
            if self._looks_static(url):
                return
            resp_hdrs = dict(response.headers)
            if not self._is_api_like(req, resp_hdrs):
                return
            req_body = req.post_data or ""
            resp_body = self._read_response_body(response)
            if not req_body.strip() and not resp_body.strip():
                return
            # all_headers 比 headers 更完整（含 cookie）
            try:
                req_hdrs = dict(req.all_headers())
            except Exception:
                req_hdrs = dict(req.headers)
            self._enqueue(("flow", {
                "method": req.method,
                "url": url,
                "request_body": req_body[:200000],
                "response_body": resp_body[:200000],
                "request_headers": _norm_headers(req_hdrs),
                "response_headers": _norm_headers(resp_hdrs),
                "status": response.status,
                "source": "playwright",
                "phase": "response",
            }))
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
            self.log.emit(
                "未找到内置 Chromium（ms-playwright 目录）。\n"
                "请使用完整绿色版包，或联系发布者重新打包。"
            )
            self.stopped.emit()
            return

        if self.use_mitm_proxy:
            self.log.emit(f"启动浏览器（经解密端 127.0.0.1:{self.mitm_port}）…")
        else:
            self.log.emit("启动浏览器（直连 + 页面内 Hook；未走解密端代理）…")
        try:
            from core.browser_ext_manager import (
                PROFILE_DIR,
                consume_pending_userscript_install,
                ensure_vendor_extensions,
                list_extension_paths,
            )

            # 扩展需 persistent context；默认拉油猴 + ReRes（可走代理下 GitHub）
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
            os.makedirs(PROFILE_DIR, exist_ok=True)
            launch_args = [
                "--ignore-certificate-errors",
                "--disable-web-security",
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

            with sync_playwright() as p:
                ctx_opts: dict = {
                    "headless": bool(self.headless) and not ext_paths,
                    "args": launch_args,
                    "ignore_https_errors": True,
                    "viewport": None,
                }
                # 加载了 cb_hook 时：用扩展 chrome.proxy 控代理，便于弹窗切换；
                # 不再写 --proxy-server（命令行代理会锁死，扩展无法改直连）。
                use_ext_proxy = bool(self.load_cb_hook) and any(
                    os.path.basename(p.rstrip("\\/")).lower() == "cb_hook"
                    for p in ext_paths
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
                context = p.chromium.launch_persistent_context(PROFILE_DIR, **ctx_opts)

                # 反调试须最先注入，抢在业务 JS 之前；选项可按站点勾选
                if self.anti_debug and os.path.isfile(ANTI_DEBUG_SCRIPT):
                    opts_json = json.dumps(self.inject_opts, ensure_ascii=False)
                    context.add_init_script(f"window.__cbInjectOpts = {opts_json};")
                    with open(ANTI_DEBUG_SCRIPT, encoding="utf-8") as f:
                        context.add_init_script(f.read())
                    on_flags = ",".join(k for k, v in self.inject_opts.items() if v) or "(默认)"
                    self.log.emit(f"已注入 anti_debug.js（模块: {on_flags}）")

                if os.path.isfile(NETWORK_CAPTURE_SCRIPT):
                    context.expose_binding("cpCapture", self._handle_js_capture)
                    with open(NETWORK_CAPTURE_SCRIPT, encoding="utf-8") as f:
                        context.add_init_script(f.read())
                    self._js_capture_enabled = True
                    self.log.emit("已注入 network_capture.js（含请求/响应头）")

                if self.hook_enabled and os.path.isfile(HOOK_SCRIPT):
                    with open(HOOK_SCRIPT, encoding="utf-8") as f:
                        context.add_init_script(f.read())
                    self.log.emit("已注入 crypto_hook.js — 触发加密后显示密钥")

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
                context.on("console", self._on_console)

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
                self.log.emit("页面已打开；API 请求会立即出现在左侧列表")

                while not self._stop_flag:
                    self._drain_events()
                    page.wait_for_timeout(100)

                self._drain_events()
                context.close()
        except Exception as e:
            self.log.emit(f"浏览器错误: {e}")
        self.log.emit(
            f"浏览器已关闭（流量 {self._capture_count} 条，JS {self._script_count} 个）"
        )
        self.stopped.emit()
