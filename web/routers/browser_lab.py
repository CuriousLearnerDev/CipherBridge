"""Web：浏览器采集 / CDP / 真实浏览器 / 策略扫描 — 对齐 GUI AI Lab。"""

from __future__ import annotations

import threading
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from web.services.ai_lab import get_runtime
from web.services.browser_host import get_browser_host

router = APIRouter(tags=["browser"])

_sweep_job: dict[str, Any] = {
    "status": "idle",
    "logs": [],
    "result": None,
    "error": "",
}
_sweep_lock = threading.Lock()
_sweep_cancel = False


class BrowserStartBody(BaseModel):
    url: str
    real_browser: bool | None = None
    cdp_attach: bool | None = None
    cdp_browser: str | None = None  # msedge | chrome
    browser_channel: str | None = None
    hook_enabled: bool | None = None
    anti_debug: bool | None = None
    cdp_skip_pauses: bool | None = None
    use_mitm_proxy: bool | None = None
    mitm_port: int | None = None
    load_violentmonkey: bool | None = None
    load_reres: bool | None = None
    load_cb_hook: bool | None = None
    record_mode: bool | None = None
    inject_opts: dict[str, Any] | None = None
    clear_session: bool = False


class ExportHooksBody(BaseModel):
    anti_debug: bool = True
    hook_enabled: bool = True
    inject_opts: dict[str, Any] = Field(default_factory=dict)
    extra_js: str = ""


@router.get("/api/browser/status")
def api_browser_status():
    host = get_browser_host()
    sess = get_runtime().session_summary()
    return {"ok": True, **host.status(), "session": sess}


@router.post("/api/browser/start")
def api_browser_start(body: BrowserStartBody):
    if body.clear_session:
        get_runtime().clear_session()
    opts = body.model_dump(exclude={"url", "clear_session"}, exclude_none=True)
    out = get_browser_host().start(url=body.url, **opts)
    if not out.get("ok"):
        raise HTTPException(status_code=400, detail=out.get("error") or "启动失败")
    return out


@router.post("/api/browser/stop")
def api_browser_stop():
    return get_browser_host().stop()


@router.post("/api/browser/export-hooks")
def api_export_hooks(body: ExportHooksBody):
    """按当前注入勾选生成油猴脚本（对齐 GUI「生成 Hook 脚本」）。"""
    from core.browser_ext_manager import export_hooks_to_userscript

    try:
        paths = export_hooks_to_userscript(
            include_anti_debug=bool(body.anti_debug),
            include_crypto_hook=bool(body.hook_enabled),
            inject_opts=dict(body.inject_opts or {}),
            extra_js=body.extra_js or "",
            mark_pending_install=True,
        )
        preview = ""
        us = paths.get("userscript") or ""
        if us:
            try:
                with open(us, encoding="utf-8") as f:
                    preview = f.read()
            except OSError:
                preview = ""
        return {"ok": True, **paths, "preview": preview}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


def _flow_kind_tag(flow: dict) -> str:
    body = str(flow.get("response_body") or "")
    url = str(flow.get("url") or "").lower()
    if (
        body.startswith("(binary")
        or flow.get("body_kind") == "binary"
        or flow.get("response_body_b64")
    ):
        return "二进制"
    if any(
        n in url
        for n in ("imgcode", "captcha", "verifycode", "checkcode", "imagecode", "/static/images/")
    ):
        return "图片"
    return ""


@router.get("/api/browser/capture")
def api_browser_capture():
    """流量 / JS / Hook 列表（与 Agent 会话同源）。"""
    rt = get_runtime()
    host = get_browser_host()
    with rt._lock:
        sel_f = rt.selected_flow_indices
        sel_s = rt.selected_script_urls
        flows = []
        for i, f in enumerate(rt.flows):
            seq = f.get("_seq") if isinstance(f.get("_seq"), int) else i + 1
            checked = True if sel_f is None else (i in sel_f)
            flows.append(
                {
                    "index": i,
                    "seq": seq,
                    "method": f.get("method"),
                    "url": f.get("url"),
                    "status": f.get("status"),
                    "source": f.get("source"),
                    "kind": _flow_kind_tag(f),
                    "checked": checked,
                    "req_len": len(str(f.get("request_body") or "")),
                    "resp_len": len(str(f.get("response_body") or "")),
                }
            )
        scripts = []
        # dict 插入序 = 捕获/加载顺序（与浏览器采集先后一致）
        for i, (u, c) in enumerate(list(rt.scripts.items()), 1):
            checked = True if sel_s is None else (u in sel_s)
            scripts.append(
                {
                    "url": u,
                    "size": len(c or ""),
                    "checked": checked,
                    "order": i,
                    "seq": i,
                }
            )
        hooks = list(rt.hooks[-200:])
    return {
        "ok": True,
        "browser": host.status(),
        "flows": flows,
        "scripts": scripts,
        "hooks": hooks,
        "counts": {
            "flows": len(flows),
            "scripts": len(scripts),
            "hooks": len(hooks),
            "flows_selected": sum(1 for f in flows if f.get("checked")),
            "scripts_selected": sum(1 for s in scripts if s.get("checked")),
        },
    }


@router.get("/api/browser/capture/flow/{index}")
def api_get_flow(index: int):
    from core.flow_format import format_request_burp, format_response_burp, flow_to_parser_raw

    rt = get_runtime()
    with rt._lock:
        if index < 0 or index >= len(rt.flows):
            raise HTTPException(status_code=404, detail="flow 不存在")
        flow = dict(rt.flows[index])
    req = format_request_burp(flow)
    resp = format_response_burp(flow)
    return {
        "ok": True,
        "flow": flow,
        "request_raw": req,
        "response_raw": resp,
        "raw": flow_to_parser_raw(flow),
    }


@router.get("/api/browser/capture/script")
def api_get_script(url: str):
    rt = get_runtime()
    with rt._lock:
        if url not in rt.scripts:
            raise HTTPException(status_code=404, detail="script 不存在")
        code = rt.scripts[url]
    return {"ok": True, "url": url, "code": code, "size": len(code)}


class SweepBody(BaseModel):
    url: str
    headless: bool = False
    base_channel: str = "chrome"
    use_stealth: bool = True
    neutralize_devtools: bool = False
    use_proxy: bool = False
    proxy: str = ""
    then_agent: bool = False


@router.post("/api/browser/sweep")
def api_sweep_start(body: SweepBody):
    """全量策略扫描（GUI 环境绕过同款矩阵）。"""
    global _sweep_cancel
    with _sweep_lock:
        if _sweep_job.get("status") == "running":
            raise HTTPException(status_code=400, detail="策略扫描已在运行")
        _sweep_cancel = False
        _sweep_job.update(
            {
                "status": "running",
                "logs": [],
                "result": None,
                "error": "",
                "url": body.url,
            }
        )

    def _log(m: str) -> None:
        with _sweep_lock:
            logs = _sweep_job.setdefault("logs", [])
            logs.append(str(m))
            if len(logs) > 2000:
                del logs[:-1500]

    def _run() -> None:
        global _sweep_cancel
        try:
            from core.bypass_strategy_sweep import run_strategy_sweep
            import asyncio

            proxy = None
            if body.use_proxy:
                proxy = (body.proxy or "").strip() or None
                if proxy and not proxy.startswith("http"):
                    proxy = f"http://{proxy}"

            async def _amain():
                return await run_strategy_sweep(
                    url=body.url,
                    headless=body.headless,
                    base_channel=body.base_channel,
                    use_stealth=body.use_stealth,
                    neutralize_devtools=body.neutralize_devtools,
                    proxy=proxy,
                    on_log=_log,
                    cancel_check=lambda: _sweep_cancel,
                )

            loop = asyncio.new_event_loop()
            try:
                result = loop.run_until_complete(_amain())
            finally:
                loop.close()
            with _sweep_lock:
                _sweep_job["status"] = "ok"
                _sweep_job["result"] = result
            _log("✅ 策略扫描完成")
        except Exception as e:
            with _sweep_lock:
                _sweep_job["status"] = "failed"
                _sweep_job["error"] = str(e)
            _log(f"❌ {e}")

    threading.Thread(target=_run, name="cb-web-sweep", daemon=True).start()
    return {"ok": True, "status": "running"}


@router.post("/api/browser/sweep/stop")
def api_sweep_stop():
    global _sweep_cancel
    _sweep_cancel = True
    return {"ok": True}


@router.get("/api/browser/sweep")
def api_sweep_status():
    with _sweep_lock:
        return {
            "ok": True,
            "status": _sweep_job.get("status"),
            "logs": list(_sweep_job.get("logs") or [])[-80:],
            "result": _sweep_job.get("result"),
            "error": _sweep_job.get("error") or "",
            "url": _sweep_job.get("url") or "",
        }


# ── AI 绕过：与 GUI「环境绕过 / 开始通关」同款 BrowserAgentWorker ──
_bypass_job: dict[str, Any] = {
    "status": "idle",
    "logs": [],
    "result": "",
    "error": "",
    "launch": {},
}
_bypass_lock = threading.Lock()
_bypass_worker = None


class BypassLiveBody(BaseModel):
    url: str
    goal: str = ""
    strategy_sweep: bool = True
    sweep_then_agent: bool = True
    headless: bool = False
    use_stealth: bool | None = None
    neutralize_devtools: bool | None = None
    browser_channel: str | None = None
    cdp_attach: bool = False
    use_proxy: bool = False
    proxy: str = ""


_BYPASS_EXTRA = (
    "【密桥实验室可选启动策略 — 由你决策，勿死磕默认】\n"
    "若页面疑似风控/挑战/空白，请用 browser_restart.reconfigure 换策略：\n"
    "1) use_stealth=false：接近真实浏览器\n"
    "2) use_stealth=true + channel=chrome：拟真\n"
    "3) cdp_attach=true + channel=msedge|chrome：系统浏览器+CDP\n"
    "4) fresh_profile / neutralize_devtools / 清代理\n"
    "连续同策略失败 2～3 次必须换参。最终 JSON 必填 reason（为什么过了/过不了）。"
)


@router.post("/api/browser/bypass/live")
def api_bypass_live_start(body: BypassLiveBody):
    """GUI 同款：全量策略扫描 + 实时浏览器通关（BrowserAgentWorker）。"""
    global _bypass_worker
    url = (body.url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="请填写目标 URL")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    with _bypass_lock:
        if _bypass_job.get("status") == "running":
            raise HTTPException(status_code=400, detail="环境绕过已在运行")
        _bypass_job.update(
            {
                "status": "running",
                "logs": [],
                "result": "",
                "error": "",
                "launch": {},
                "url": url,
            }
        )

    # 采集浏览器与绕过 Agent 档案冲突时先停采集
    try:
        host = get_browser_host()
        st = host.status()
        if st.get("running"):
            host.stop()
            with _bypass_lock:
                _bypass_job.setdefault("logs", []).append(
                    "已先停止采集浏览器，改用环境绕过独立档案"
                )
    except Exception:
        pass

    from core.ai_config import load_ai_config, normalize_browser_channel
    from core.browser_agent import (
        BrowserAgentWorker,
        agent_profile_dir_for_channel,
        agent_profile_dir_for_cdp,
        _DEFAULT_GOAL_TPL,
    )
    from web.services.browser_host import _ensure_qt

    _ensure_qt()
    cfg = load_ai_config()
    browser = cfg.get("browser") if isinstance(cfg.get("browser"), dict) else {}
    browser = dict(browser or {})

    ch = normalize_browser_channel(
        body.browser_channel
        or browser.get("browser_channel")
        or "chrome"
    )
    use_stealth = (
        bool(body.use_stealth)
        if body.use_stealth is not None
        else not bool(browser.get("real_browser") or browser.get("proxy_only"))
    )
    anti = (
        bool(body.neutralize_devtools)
        if body.neutralize_devtools is not None
        else bool(browser.get("anti_debug"))
    )
    cdp = bool(body.cdp_attach or browser.get("cdp_attach"))
    if cdp:
        use_stealth = False
        anti = False
        prefer = str(browser.get("cdp_browser") or ch)
        ch = normalize_browser_channel(prefer if prefer in ("msedge", "chrome") else "msedge")

    proxy = None
    if body.use_proxy:
        proxy = (body.proxy or "").strip() or None
        if not proxy and browser.get("use_mitm_proxy"):
            port = int(browser.get("mitm_port") or 8083)
            proxy = f"http://127.0.0.1:{port}"
        if proxy and not str(proxy).startswith("http"):
            proxy = f"http://{proxy}"

    goal = (body.goal or "").strip() or _DEFAULT_GOAL_TPL.format(url=url)
    profile = (
        agent_profile_dir_for_cdp()
        if cdp
        else agent_profile_dir_for_channel(ch)
    )

    def _log(m: str) -> None:
        with _bypass_lock:
            logs = _bypass_job.setdefault("logs", [])
            logs.append(str(m))
            if len(logs) > 3000:
                del logs[:-2000]

    worker = BrowserAgentWorker(
        goal=goal,
        url=url,
        cfg=cfg,
        headless=bool(body.headless),
        browser_channel=ch,
        use_stealth=use_stealth,
        browser_proxy=proxy,
        profile_dir=profile,
        extra_context=_BYPASS_EXTRA,
        neutralize_devtools=anti,
        cdp_attach=cdp,
        strategy_sweep=bool(body.strategy_sweep),
        sweep_then_agent=bool(body.sweep_then_agent),
        parent=None,
    )

    def _on_log(m: str) -> None:
        _log(m)

    def _on_ok(text: str) -> None:
        global _bypass_worker
        launch = dict(getattr(worker, "last_launch", None) or {})
        with _bypass_lock:
            _bypass_job["status"] = "ok"
            _bypass_job["result"] = text or ""
            _bypass_job["launch"] = launch
            _bypass_job["error"] = ""
        _log("✅ 环境绕过完成")
        with _bypass_lock:
            _bypass_worker = None

    def _on_fail(err: str) -> None:
        global _bypass_worker
        with _bypass_lock:
            _bypass_job["status"] = "cancelled" if err == "已取消" else "failed"
            _bypass_job["error"] = str(err or "失败")
        _log(f"❌ {err}")
        with _bypass_lock:
            _bypass_worker = None

    from PyQt6.QtCore import Qt

    dc = Qt.ConnectionType.DirectConnection
    worker.log.connect(_on_log, dc)
    worker.finished_ok.connect(_on_ok, dc)
    worker.failed.connect(_on_fail, dc)

    with _bypass_lock:
        _bypass_worker = worker
    _log(
        f"—— 开始环境绕过（同 GUI）——\nURL: {url}\n"
        f"策略扫描={body.strategy_sweep} · 拟真={use_stealth} · CDP={cdp} · 通道={ch}"
    )
    worker.start()
    return {"ok": True, "status": "running", "url": url}


@router.post("/api/browser/bypass/live/stop")
def api_bypass_live_stop():
    global _bypass_worker
    with _bypass_lock:
        w = _bypass_worker
    if w is not None:
        try:
            w.cancel()
        except Exception:
            pass
    return {"ok": True}


@router.get("/api/browser/bypass/live")
def api_bypass_live_status():
    with _bypass_lock:
        return {
            "ok": True,
            "status": _bypass_job.get("status"),
            "logs": list(_bypass_job.get("logs") or [])[-120:],
            "result": _bypass_job.get("result") or "",
            "error": _bypass_job.get("error") or "",
            "launch": _bypass_job.get("launch") or {},
            "url": _bypass_job.get("url") or "",
        }
