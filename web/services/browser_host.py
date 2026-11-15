"""Web 侧浏览器实验室宿主 — 复用 BrowserLabWorker，采集写入共享会话。"""

from __future__ import annotations

import logging
import sys
import threading
from typing import Any

from web.deps import ensure_sys_path

ensure_sys_path()

logger = logging.getLogger(__name__)


def _ensure_qt() -> None:
    from PyQt6.QtCore import QCoreApplication

    app = QCoreApplication.instance()
    if app is None:
        # 无 GUI 进程内跑 QThread 信号
        app = QCoreApplication(sys.argv[:1] or ["cipherbridge-web"])
    # 定时泵事件，让 Queued 信号也能落地（Direct 为主）
    return app


class BrowserHost:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._worker = None
        self.logs: list[str] = []
        self.running = False
        self.url = ""
        self.opts: dict[str, Any] = {}
        self._pump_timer = None

    def status(self) -> dict[str, Any]:
        with self._lock:
            alive = bool(self._worker and self._worker.isRunning())
            return {
                "running": alive,
                "url": self.url,
                "opts": dict(self.opts),
                "log_count": len(self.logs),
                "logs_tail": list(self.logs[-40:]),
            }

    def _append_log(self, msg: str) -> None:
        with self._lock:
            self.logs.append(str(msg))
            if len(self.logs) > 3000:
                del self.logs[:-2000]

    def _on_flow(self, flow: dict) -> None:
        from web.services.ai_lab import get_runtime

        rt = get_runtime()
        with rt._lock:
            f = dict(flow or {})
            f.setdefault("_seq", len(rt.flows) + 1)
            rt.flows.append(f)
        self._append_log(
            f"流量 #{len(get_runtime().flows)} {f.get('method')} {str(f.get('url') or '')[:80]}"
        )

    def _on_flow_updated(self, flow: dict) -> None:
        from web.services.ai_lab import get_runtime

        rt = get_runtime()
        key = flow.get("_key")
        idx = flow.get("_index")
        with rt._lock:
            target = None
            if isinstance(idx, int) and 0 <= idx < len(rt.flows):
                target = rt.flows[idx]
            elif key:
                for f in reversed(rt.flows):
                    if f.get("_key") == key:
                        target = f
                        break
            if target is None:
                return
            for k in (
                "status",
                "response_body",
                "response_headers",
                "request_headers",
                "request_body",
            ):
                if k in flow and flow[k] not in (None, ""):
                    target[k] = flow[k]

    def _on_script(self, data: dict) -> None:
        from web.services.ai_lab import get_runtime

        url = str((data or {}).get("url") or "").strip()
        content = str((data or {}).get("content") or (data or {}).get("code") or "")
        if not url:
            return
        rt = get_runtime()
        with rt._lock:
            rt.scripts[url] = content
        self._append_log(f"JS {url[:80]} ({len(content)} chars)")

    def _on_hook(self, line: str) -> None:
        from web.services.ai_lab import get_runtime

        rt = get_runtime()
        with rt._lock:
            rt.hooks.append(str(line))
            if len(rt.hooks) > 2000:
                del rt.hooks[:-1500]
        self._append_log(str(line)[:200])

    def _on_log(self, msg: str) -> None:
        self._append_log(msg)

    def _on_stopped(self) -> None:
        with self._lock:
            self.running = False
            self._worker = None
        self._append_log("浏览器已停止")
        self._stop_pump()

    def _start_pump(self) -> None:
        self._stop_pump()

        def _loop() -> None:
            from PyQt6.QtCore import QCoreApplication
            import time

            while True:
                with self._lock:
                    alive = bool(self._worker and self._worker.isRunning())
                if not alive:
                    break
                app = QCoreApplication.instance()
                if app is not None:
                    try:
                        app.processEvents()
                    except Exception:
                        pass
                time.sleep(0.05)

        t = threading.Thread(target=_loop, name="cb-web-qt-pump", daemon=True)
        self._pump_timer = t
        t.start()

    def _stop_pump(self) -> None:
        self._pump_timer = None

    def start(self, *, url: str, **opts: Any) -> dict[str, Any]:
        from PyQt6.QtCore import Qt
        from core.ai_config import load_ai_config, normalize_browser_channel
        from core.browser_lab import BrowserLabWorker

        url = (url or "").strip()
        if not url:
            return {"ok": False, "error": "请填写目标 URL"}
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        with self._lock:
            if self._worker and self._worker.isRunning():
                return {"ok": False, "error": "浏览器已在运行，请先停止"}

        _ensure_qt()
        cfg = load_ai_config()
        browser = dict(cfg.get("browser") or {})

        # 启动参数：请求覆盖 > 配置
        real_browser = bool(opts.get("real_browser", browser.get("real_browser") or browser.get("proxy_only")))
        cdp_attach = bool(opts.get("cdp_attach", browser.get("cdp_attach")))
        cdp_browser = str(opts.get("cdp_browser") or browser.get("cdp_browser") or "msedge")
        channel = normalize_browser_channel(
            opts.get("browser_channel") or browser.get("browser_channel") or "chromium"
        )
        if cdp_attach:
            real_browser = False
            channel = normalize_browser_channel(cdp_browser if cdp_browser in ("msedge", "chrome") else "msedge")
        elif real_browser and channel == "chromium":
            channel = "chrome"

        clean = real_browser or cdp_attach
        hook_enabled = False if clean else bool(opts.get("hook_enabled", browser.get("hook_enabled", True)))
        anti_debug = False if clean else bool(opts.get("anti_debug", browser.get("anti_debug", False)))
        cdp_skip = False if clean else bool(opts.get("cdp_skip_pauses", browser.get("cdp_skip_pauses", False)))
        inject_opts = dict(browser.get("inject_opts") or {})
        if isinstance(opts.get("inject_opts"), dict):
            inject_opts.update(opts["inject_opts"])
        if clean:
            inject_opts["rewriteResponse"] = False

        load_vm = False if clean else bool(opts.get("load_violentmonkey", browser.get("load_violentmonkey", True)))
        load_reres = False if clean else bool(opts.get("load_reres", browser.get("load_reres", True)))
        load_cb = False if clean else bool(opts.get("load_cb_hook", browser.get("load_cb_hook", True)))
        use_mitm = bool(opts.get("use_mitm_proxy", browser.get("use_mitm_proxy", False)))
        mitm_port = int(opts.get("mitm_port", browser.get("mitm_port", 8083)) or 8083)
        ext_proxy = str(opts.get("ext_proxy") or browser.get("ext_proxy") or "").strip()
        if ext_proxy and not ext_proxy.startswith("http"):
            ext_proxy = f"http://{ext_proxy}"
        if "record_mode" in opts:
            record_mode = bool(opts.get("record_mode"))
        else:
            record_mode = True if clean else bool(browser.get("record_mode", True))

        worker = BrowserLabWorker(
            url=url,
            hook_enabled=hook_enabled,
            anti_debug=anti_debug,
            cdp_skip_pauses=cdp_skip,
            inject_opts=inject_opts,
            headless=False,
            use_mitm_proxy=use_mitm,
            mitm_port=mitm_port,
            load_violentmonkey=load_vm,
            load_reres=load_reres,
            load_cb_hook=load_cb,
            ext_proxy=ext_proxy or None,
            record_mode=record_mode,
            browser_channel=channel,
            real_browser=real_browser,
            cdp_attach=cdp_attach,
        )
        dc = Qt.ConnectionType.DirectConnection
        worker.log.connect(self._on_log, dc)
        worker.flow_captured.connect(self._on_flow, dc)
        worker.flow_updated.connect(self._on_flow_updated, dc)
        worker.hook_line.connect(self._on_hook, dc)
        worker.script_captured.connect(self._on_script, dc)
        worker.stopped.connect(self._on_stopped, dc)

        with self._lock:
            self.logs = []
            self.url = url
            self.opts = {
                "real_browser": real_browser,
                "cdp_attach": cdp_attach,
                "cdp_browser": cdp_browser if cdp_attach else "",
                "browser_channel": channel,
                "hook_enabled": hook_enabled,
                "anti_debug": anti_debug,
                "cdp_skip_pauses": cdp_skip,
                "use_mitm_proxy": use_mitm,
                "mitm_port": mitm_port,
                "load_violentmonkey": load_vm,
                "load_reres": load_reres,
                "load_cb_hook": load_cb,
                "record_mode": record_mode,
                "inject_opts": dict(inject_opts),
            }
            self._worker = worker
            self.running = True

        worker.start()
        self._start_pump()
        mode = (
            f"CDP·{'Edge' if channel == 'msedge' else 'Chrome'}"
            if cdp_attach
            else ("真实浏览器" if real_browser else "普通注入")
        )
        self._append_log(f"启动浏览器 [{mode}] {url}")
        return {"ok": True, **self.status()}

    def stop(self) -> dict[str, Any]:
        with self._lock:
            w = self._worker
        if w and w.isRunning():
            w.stop()
            self._append_log("正在停止浏览器…")
            return {"ok": True, "stopping": True, **self.status()}
        return {"ok": True, "stopping": False, **self.status()}


_HOST: BrowserHost | None = None


def get_browser_host() -> BrowserHost:
    global _HOST
    if _HOST is None:
        _HOST = BrowserHost()
    return _HOST
