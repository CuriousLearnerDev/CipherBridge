"""Web AI 实验室：会话素材 + 后台 Agent（不依赖 PyQt）。"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
import uuid
from typing import Any

from web.deps import ensure_sys_path

ensure_sys_path()

from core.agent_runner import (  # noqa: E402
    ANALYZE_KEY_GOAL,
    ANTI_DEBUG_GOAL,
    BOT_BYPASS_GOAL,
    CryptoAgent,
    FINGERPRINT_HOOK_GOAL,
    GENERATE_DECRYPT_GOAL,
    GENERATE_ENCRYPT_GOAL,
    HASH_HOOK_GOAL,
    JS_DEOBFUSCATE_GOAL,
    JS_REVERSE_GOAL,
    ProxiedLLMClient,
    RECOGNIZE_GOAL,
    build_agent_system_prompt,
)
from core.agent_tools import SessionData, build_crypto_tools  # noqa: E402
from core.ai_config import load_ai_config, resolve_agent_base_url, save_ai_config  # noqa: E402

logger = logging.getLogger(__name__)

AI_MODES: list[dict[str, str]] = [
    {"id": "recognize", "label": "识别加解密", "desc": "选字段 → 识别算法，输出 steps"},
    {"id": "generate", "label": "分析加解密", "desc": "选字段 → 分析并生成解密 plugin"},
    {"id": "analyze_key", "label": "分析密钥", "desc": "定位固定/动态密钥与来源"},
    {"id": "generate_encrypt", "label": "分析加密", "desc": "选字段 → 分析并生成加密 plugin"},
    {"id": "anti_debug", "label": "分析 debugger", "desc": "反调试 / inject_opts"},
    {"id": "bot_bypass", "label": "AI 绕过(Bot)", "desc": "独立悬浮窗：策略扫描+实时通关（同 GUI）"},
    {"id": "fingerprint_hook", "label": "指纹绕过 HOOK", "desc": "FingerprintJS/canvas 等"},
    {"id": "js_reverse", "label": "JS 逆向", "desc": "定位加解密业务函数"},
    {"id": "js_deobfuscate", "label": "JS 解密/解混淆", "desc": "解混淆并输出可读 JS"},
    {"id": "hash_hook", "label": "Hash Hook", "desc": "哈希/签名路径 Hook"},
]

# 需要弹出字段选择的模式（对齐 GUI）
FIELD_PICK_MODES = frozenset({"recognize", "generate", "generate_encrypt", "analyze_key"})

_DEFAULT_GOALS: dict[str, str] = {
    "recognize": RECOGNIZE_GOAL,
    "generate": GENERATE_DECRYPT_GOAL,
    "analyze_key": ANALYZE_KEY_GOAL,
    "generate_encrypt": GENERATE_ENCRYPT_GOAL,
    "anti_debug": ANTI_DEBUG_GOAL,
    "bot_bypass": BOT_BYPASS_GOAL,
    "fingerprint_hook": FINGERPRINT_HOOK_GOAL,
    "js_reverse": JS_REVERSE_GOAL,
    "js_deobfuscate": JS_DEOBFUSCATE_GOAL,
    "hash_hook": HASH_HOOK_GOAL,
    "chat": "请根据当前流量与 JS，说明你能观察到的加解密相关线索。",
}


def _proxy_url(cfg: dict) -> str | None:
    if not cfg.get("use_http_proxy"):
        return None
    p = str(cfg.get("http_proxy") or "").strip()
    if not p:
        return None
    return p if p.startswith("http") else f"http://{p}"


def mask_api_key(key: str) -> str:
    k = (key or "").strip()
    if not k:
        return ""
    if len(k) <= 8:
        return "*" * len(k)
    return k[:3] + "…" + k[-4:]


def json_dumps_safe(obj: Any) -> str:
    import json

    try:
        return json.dumps(obj, ensure_ascii=False, indent=2)
    except Exception:
        return str(obj)


class AiLabRuntime:
    """进程内单例：素材会话 + 一个 Agent 任务。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.flows: list[dict] = []
        self.hooks: list[str] = []
        self.scripts: dict[str, str] = {}
        # 勾选送 AI（None=尚未由用户设定，送全部；设定后只送勾选）
        self.selected_flow_indices: set[int] | None = None
        self.selected_script_urls: set[str] | None = None
        self.field_targets: dict[str, Any] | None = None
        self.job: dict[str, Any] = self._empty_job()
        self._thread: threading.Thread | None = None
        self._cancel = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._task: asyncio.Task | None = None

    @staticmethod
    def _empty_job() -> dict[str, Any]:
        return {
            "id": "",
            "status": "idle",  # idle|running|ok|failed|cancelled
            "mode": "",
            "goal": "",
            "logs": [],
            "result": "",
            "error": "",
            "started_at": 0.0,
            "finished_at": 0.0,
            "context": [],  # [{title, kind, request, response}]
            "code_locations": "",
            "plugin": "",
            "hook": "",
            "verify": None,  # 加解密验证报告（对齐 GUI）
            "steps": [],
            "encrypt_steps": [],
            "encrypt_verified": False,
        }

    def session_summary(self) -> dict[str, Any]:
        with self._lock:
            sel_f = self.selected_flow_indices
            sel_s = self.selected_script_urls
            return {
                "flows": len(self.flows),
                "hooks": len(self.hooks),
                "scripts": len(self.scripts),
                "flows_selected": len(sel_f) if sel_f is not None else len(self.flows),
                "scripts_selected": len(sel_s) if sel_s is not None else len(self.scripts),
                "script_urls": list(self.scripts.keys())[:40],
                "flow_preview": [
                    {
                        "method": f.get("method"),
                        "url": str(f.get("url") or "")[:160],
                        "status": f.get("status"),
                    }
                    for f in self.flows[:20]
                ],
            }

    def set_material_selection(
        self,
        *,
        flow_indices: list[int] | None = None,
        script_urls: list[str] | None = None,
    ) -> dict[str, Any]:
        """对齐 GUI：勾选流量/JS 后只送入 Agent。"""
        with self._lock:
            if flow_indices is not None:
                self.selected_flow_indices = {
                    int(i) for i in flow_indices if isinstance(i, (int, float)) and int(i) >= 0
                }
            if script_urls is not None:
                self.selected_script_urls = {str(u) for u in script_urls if str(u).strip()}
            return self.session_summary()

    def agent_flows(self) -> list[dict]:
        with self._lock:
            if self.selected_flow_indices is None:
                return list(self.flows)
            return [
                self.flows[i]
                for i in sorted(self.selected_flow_indices)
                if 0 <= i < len(self.flows)
            ]

    def agent_scripts(self) -> dict[str, str]:
        with self._lock:
            if self.selected_script_urls is None:
                return dict(self.scripts)
            return {
                u: self.scripts[u]
                for u in self.selected_script_urls
                if u in self.scripts
            }

    def set_session(
        self,
        *,
        flows: list[dict] | None = None,
        hooks: list[str] | None = None,
        scripts: dict[str, str] | None = None,
        replace: bool = True,
    ) -> dict[str, Any]:
        with self._lock:
            if flows is not None:
                self.flows = list(flows) if replace else (self.flows + list(flows))
            if hooks is not None:
                self.hooks = list(hooks) if replace else (self.hooks + list(hooks))
            if scripts is not None:
                if replace:
                    self.scripts = dict(scripts)
                else:
                    self.scripts.update(dict(scripts))
            return self.session_summary()

    def clear_session(self) -> dict[str, Any]:
        with self._lock:
            self.flows.clear()
            self.hooks.clear()
            self.scripts.clear()
            self.selected_flow_indices = None
            self.selected_script_urls = None
            self.field_targets = None
            return self.session_summary()

    def field_options(self) -> dict[str, Any]:
        """供 Web 字段选择弹窗：按请求列出可点字段（优先勾选流量）。"""
        from core.field_targets import collect_side_fields, flow_seq

        with self._lock:
            all_flows = list(self.flows)
            sel = self.selected_flow_indices
        items: list[dict[str, Any]] = []
        for i, flow in enumerate(all_flows):
            if sel is not None and i not in sel:
                continue
            seq = flow_seq(flow, i + 1)
            items.append(
                {
                    "index": i,
                    "seq": seq,
                    "method": flow.get("method") or "",
                    "url": str(flow.get("url") or ""),
                    "status": flow.get("status"),
                    "request": collect_side_fields(flow, i, "request"),
                    "response": collect_side_fields(flow, i, "response"),
                }
            )
        return {"ok": True, "count": len(items), "flows": items}

    def merge_scripts(self, scripts: dict[str, str], *, replace: bool = False) -> dict[str, Any]:
        with self._lock:
            if replace:
                self.scripts = dict(scripts or {})
            else:
                self.scripts.update(dict(scripts or {}))
            return self.session_summary()

    def add_flow_from_http(self, raw: str, *, url: str = "", method: str = "POST") -> dict:
        from web.services.http_parse import parse_http_raw

        parsed = parse_http_raw(raw, include_response=True)
        if not parsed.get("ok"):
            return parsed
        flow = {
            "method": parsed.get("method") or method or "POST",
            "url": parsed.get("url") or url or "",
            "request_headers": parsed.get("headers") or {},
            "request_body": parsed.get("body") or "",
            "status": (parsed.get("response") or {}).get("status"),
            "response_body": (parsed.get("response") or {}).get("body") or "",
            "_seq": len(self.flows) + 1,
        }
        with self._lock:
            self.flows.append(flow)
            return {"ok": True, "flow": flow, **self.session_summary()}

    def add_script(self, url: str, code: str) -> dict:
        url = (url or f"paste://script_{len(self.scripts)+1}.js").strip()
        with self._lock:
            self.scripts[url] = code or ""
            return {"ok": True, **self.session_summary()}

    def job_snapshot(self) -> dict[str, Any]:
        with self._lock:
            j = dict(self.job)
            j["logs"] = list(self.job.get("logs") or [])
            j["context"] = [dict(x) for x in (self.job.get("context") or [])]
            return j

    def _append_log(self, msg: str) -> None:
        with self._lock:
            logs = self.job.setdefault("logs", [])
            logs.append(str(msg))
            if len(logs) > 2000:
                del logs[:-1500]

    def _append_context(self, kind: str, text: str) -> None:
        """对齐 GUI：记录 LLM 请求/响应轮次，供「上下文」页展示。"""
        body = (text or "").rstrip()
        if not body:
            return
        title = "LLM 请求" if kind == "request" else "LLM 响应"
        low = body[:80]
        if "任务" in low or "======== Agent 任务" in body[:120]:
            title = "任务"
        elif "最终" in low or "======== Agent 最终" in body[:120]:
            title = "最终输出"
        with self._lock:
            ctx = self.job.setdefault("context", [])
            if kind == "request":
                ctx.append(
                    {
                        "title": title,
                        "kind": "task" if title == "任务" else "round",
                        "request": body + "\n",
                        "response": "",
                    }
                )
            else:
                last = ctx[-1] if ctx else None
                if (
                    last
                    and not (last.get("response") or "").strip()
                    and (last.get("request") or "").strip()
                    and title != "最终输出"
                ):
                    last["response"] = body + "\n"
                else:
                    ctx.append(
                        {
                            "title": title,
                            "kind": "final" if title == "最终输出" else "round",
                            "request": "",
                            "response": body + "\n",
                        }
                    )
            if len(ctx) > 80:
                del ctx[:-60]

    def _finalize_job_views(self, result_text: str) -> None:
        """从 Agent 原文解析源码位置 / 插件步骤 / Hook。"""
        from core.ai_analyzer import _extract_json, format_code_locations_text

        code_txt = ""
        plugin_txt = ""
        hook_txt = ""
        try:
            obj = _extract_json(result_text or "")
        except Exception:
            obj = None
        if isinstance(obj, dict):
            locs = obj.get("code_locations")
            if isinstance(locs, list) and locs:
                try:
                    code_txt = format_code_locations_text(locs)
                except Exception:
                    code_txt = json_dumps_safe(locs)
            steps = obj.get("steps")
            if isinstance(steps, list) and steps:
                plugin_txt = json_dumps_safe({"steps": steps, "summary": obj.get("summary")})
            for key in ("hook_js", "userscript", "hook_script", "tampermonkey"):
                v = obj.get(key)
                if isinstance(v, str) and v.strip():
                    hook_txt = v.strip()
                    break
            if not hook_txt and isinstance(obj.get("browser_opts"), dict):
                hook_txt = (
                    "// browser_opts\n"
                    + json_dumps_safe(obj.get("browser_opts"))
                    + ("\n\n// 无 hook_js" if not hook_txt else "")
                )
        # 会话里已有的 Hook 输出也拼上
        with self._lock:
            sess_hooks = list(self.hooks[-100:]) if self.hooks else []
            if sess_hooks and not hook_txt:
                hook_txt = "\n".join(sess_hooks)
            elif sess_hooks and hook_txt:
                hook_txt = hook_txt + "\n\n—— 会话 Hook 日志 ——\n" + "\n".join(sess_hooks[-40:])
            self.job["code_locations"] = code_txt or "（暂无源码位置；逆向/识别结果里带 code_locations 时显示）"
            self.job["plugin"] = plugin_txt or "（暂无 steps；分析加解密成功后显示步骤预览）"
            self.job["hook"] = hook_txt or "（暂无 Hook 脚本 / 日志）"
            if isinstance(obj, dict) and isinstance(obj.get("steps"), list):
                self.job["steps"] = list(obj.get("steps") or [])
            else:
                self.job["steps"] = []
        self._append_context(
            "response",
            "======== Agent 最终输出 ========\n\n" + (result_text or "").rstrip() + "\n",
        )

    @staticmethod
    def _side_to_dict(side) -> dict[str, Any]:
        if side is None:
            return {
                "side": "",
                "ok": None,
                "changed": False,
                "message": "",
                "before": "",
                "after": "",
                "fields": [],
            }
        fields = []
        for f in getattr(side, "fields", None) or []:
            fields.append(
                {
                    "side": getattr(f, "side", ""),
                    "field": getattr(f, "field", ""),
                    "op": getattr(f, "op", ""),
                    "ok": bool(getattr(f, "ok", False)),
                    "message": getattr(f, "message", "") or "",
                    "method": getattr(f, "method", "") or "",
                    "before": (getattr(f, "before", "") or "")[:800],
                    "after": (getattr(f, "after", "") or "")[:800],
                }
            )
        return {
            "side": getattr(side, "side", ""),
            "ok": getattr(side, "ok", None),
            "changed": bool(getattr(side, "changed", False)),
            "message": getattr(side, "message", "") or "",
            "before": (getattr(side, "before", "") or "")[:4000],
            "after": (getattr(side, "after", "") or "")[:4000],
            "fields": fields,
        }

    def _report_to_dict(self, report, *, attempt: int = 1, max_attempts: int = 5) -> dict[str, Any]:
        return {
            "overall_ok": bool(getattr(report, "overall_ok", False)),
            "summary": getattr(report, "summary", "") or "",
            "role": getattr(report, "role", "") or "",
            "plugin_notice": getattr(report, "plugin_notice", "") or "",
            "error": getattr(report, "error", "") or "",
            "request": self._side_to_dict(getattr(report, "request", None)),
            "response": self._side_to_dict(getattr(report, "response", None)),
            "attempt": attempt,
            "max_attempts": max_attempts,
        }

    def _role_for_mode(self, ui_mode: str) -> str:
        if ui_mode == "generate_encrypt":
            return "encrypt"
        ft = self.field_targets or {}
        if isinstance(ft, dict) and ft.get("analysis_role") == "encrypt":
            return "encrypt"
        return "decrypt"

    def _auto_verify_and_revise(self, *, ui_mode: str, result_text: str) -> None:
        """对齐 GUI：产出 steps 后自动验证，失败则回传 AI 修正（最多 5 次）。"""
        if ui_mode not in ("generate", "generate_encrypt", "recognize"):
            return
        from codegen import generate_code_from_steps
        from core.ai_analyzer import _extract_json, revise_steps_after_verify_failure
        from core.ai_project_writer import (
            detect_body_format,
            enrich_decrypt_input_fmt,
            guess_match_rules,
            guess_project_name,
            pick_sample_flow,
        )
        from core.crypto_verify import format_verify_feedback, verify_crypto

        try:
            obj = _extract_json(result_text or "")
        except Exception:
            obj = None
        if not isinstance(obj, dict):
            return
        steps = obj.get("steps")
        if not isinstance(steps, list) or not steps:
            self._append_log("未得到 steps，跳过加解密验证")
            return

        role = self._role_for_mode(ui_mode)
        flows = self.agent_flows() or list(self.flows)
        cur_steps = enrich_decrypt_input_fmt(list(steps), flows)
        body_format = detect_body_format(flows)
        preview_name = guess_project_name("", flows)
        match_rules = guess_match_rules(flows, "")
        sample_flow = pick_sample_flow(flows, cur_steps, preferred=None)
        max_attempts = 5
        last_report = None
        cfg = load_ai_config()

        self._append_log("Agent 已产出步骤，开始自动验证加解密…")
        for attempt in range(1, max_attempts + 1):
            if self._cancel:
                return
            preview_code = ""
            try:
                preview_code = generate_code_from_steps(
                    cur_steps,
                    body_format,
                    role=role,
                    profile_name=preview_name,
                    match_rules=match_rules,
                )
            except Exception as e:
                self._append_log(f"预览代码生成失败（仍做字段验证）: {e}")
            self._append_log(f"正在自动验证加解密…（第 {attempt}/{max_attempts} 次）")
            try:
                report = verify_crypto(
                    cur_steps,
                    sample_flow,
                    role=role,
                    plugin_code=preview_code or None,
                )
            except Exception as e:
                self._append_log(f"验证失败: {e}")
                with self._lock:
                    self.job["verify"] = {
                        "overall_ok": False,
                        "summary": f"验证出错: {e}",
                        "attempt": attempt,
                        "max_attempts": max_attempts,
                        "error": str(e),
                        "request": {},
                        "response": {},
                    }
                return
            last_report = report
            with self._lock:
                self.job["verify"] = self._report_to_dict(
                    report, attempt=attempt, max_attempts=max_attempts
                )
                self.job["steps"] = list(cur_steps)
                self.job["plugin"] = json_dumps_safe(
                    {"steps": cur_steps, "summary": (obj or {}).get("summary")}
                )
            self._append_log(report.summary or ("验证通过" if report.overall_ok else "验证未通过"))
            if report.overall_ok:
                with self._lock:
                    self.job["encrypt_steps"] = []
                    self.job["encrypt_verified"] = False
                self._append_log("✅ 加解密验证通过")
                return

            if attempt >= max_attempts:
                break
            if not str(cfg.get("api_key") or "").strip():
                self._append_log("无 API Key，无法回传 AI 修正")
                break

            feedback = format_verify_feedback(report)
            self._append_log(f"验证未通过，回传 AI 修正（第 {attempt}/{max_attempts}）…")
            self._append_context(
                "request",
                f"======== 验证失败回传修正 #{attempt} ========\n\n{feedback}\n",
            )
            try:
                revised = revise_steps_after_verify_failure(
                    cfg=cfg,
                    role=role,
                    previous_result=dict(obj or {}, steps=cur_steps),
                    verify_feedback=feedback,
                    attempt=attempt,
                    max_attempts=max_attempts,
                    hook_lines=list(self.hooks or []),
                    sample_flow=sample_flow,
                )
            except Exception as e:
                self._append_log(f"AI 修正失败: {e}")
                break
            new_steps = revised.get("steps") if isinstance(revised, dict) else None
            if not isinstance(new_steps, list) or not new_steps:
                self._append_log("AI 修正后仍无有效 steps")
                continue
            cur_steps = enrich_decrypt_input_fmt(list(new_steps), flows)
            if isinstance(revised, dict):
                obj = dict(obj or {})
                obj.update({k: v for k, v in revised.items() if k != "_revise_raw"})
                obj["steps"] = cur_steps
            self._append_log(f"AI 已修正为 {len(cur_steps)} 个步骤，重新验证…")
            self._append_context(
                "response",
                "======== AI 修正结果 ========\n\n" + json_dumps_safe(obj) + "\n",
            )
            with self._lock:
                self.job["result"] = json_dumps_safe(obj)
                self.job["plugin"] = json_dumps_safe(
                    {"steps": cur_steps, "summary": obj.get("summary")}
                )
                self.job["steps"] = list(cur_steps)

        if last_report is not None and not last_report.overall_ok:
            self._append_log(
                f"已连续验证 {max_attempts} 次仍未通过，停止自动判断（请检查密钥/模式或手动调整步骤）"
            )

    def stop(self) -> dict[str, Any]:
        self._cancel = True
        loop = self._loop
        task = self._task
        if loop is not None and task is not None and not task.done():
            try:
                loop.call_soon_threadsafe(task.cancel)
            except Exception:
                pass
        self._append_log("收到停止请求…")
        return self.job_snapshot()

    def start(
        self,
        *,
        mode: str,
        goal: str = "",
        field_targets: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        from core.field_targets import format_field_targets_hint, summarize_field_targets

        mode = (mode or "chat").strip()
        if mode == "generate_encrypt":
            run_mode = "generate"
            default_goal = GENERATE_ENCRYPT_GOAL
        else:
            run_mode = mode if mode in _DEFAULT_GOALS or mode == "generate" else "chat"
            if mode == "generate":
                run_mode = "generate"
            default_goal = _DEFAULT_GOALS.get(mode) or _DEFAULT_GOALS.get(run_mode) or ""
        goal = (goal or "").strip() or default_goal
        if not goal:
            return {"ok": False, "error": "缺少任务目标"}

        if field_targets is not None:
            self.field_targets = dict(field_targets)
            ft = dict(field_targets)
            ft.pop("analysis_role", None)
            hint = format_field_targets_hint(ft)
            if hint:
                goal = f"{goal}\n\n{hint}"

        with self._lock:
            if self.job.get("status") == "running":
                return {"ok": False, "error": "已有任务在运行，请先停止"}
            self._cancel = False
            self.job = {
                "id": uuid.uuid4().hex[:10],
                "status": "running",
                "mode": mode,
                "goal": goal,
                "logs": [],
                "result": "",
                "error": "",
                "started_at": time.time(),
                "finished_at": 0.0,
                "field_targets_summary": summarize_field_targets(self.field_targets),
                "context": [],
                "code_locations": "",
                "plugin": "",
                "hook": "",
                "verify": None,
                "steps": [],
            }

        def _run() -> None:
            try:
                self._run_agent(run_mode=run_mode, goal=goal, ui_mode=mode)
            except Exception as e:
                logger.exception("web ai job failed")
                with self._lock:
                    self.job["status"] = "failed"
                    self.job["error"] = str(e)
                    self.job["finished_at"] = time.time()

        self._thread = threading.Thread(target=_run, name="cb-web-ai", daemon=True)
        self._thread.start()
        return {"ok": True, **self.job_snapshot()}

    def _session_data(self) -> SessionData:
        return SessionData(
            flows_provider=self.agent_flows,
            hooks_provider=lambda: list(self.hooks),
            scripts_provider=self.agent_scripts,
        )

    def _run_agent(self, *, run_mode: str, goal: str, ui_mode: str) -> None:
        cfg = load_ai_config()
        api_key = str(cfg.get("api_key") or "").strip()
        if not api_key:
            with self._lock:
                self.job["status"] = "failed"
                self.job["error"] = "请先在 AI 配置填写 API Key"
                self.job["finished_at"] = time.time()
            return
        af = self.agent_flows()
        ascripts = self.agent_scripts()
        if not af and not ascripts:
            self._append_log(
                "提示: 当前无勾选流量/JS（或素材为空），Agent 可调查内容有限。请勾选列表项或粘贴导入。"
            )

        base = resolve_agent_base_url(cfg)
        model = str(cfg.get("model") or "deepseek-chat").strip()
        try:
            max_steps = int(cfg.get("agent_max_steps") or 50)
        except (TypeError, ValueError):
            max_steps = 50
        if run_mode in (
            "generate",
            "recognize",
            "analyze_key",
            "anti_debug",
            "hash_hook",
            "bot_bypass",
            "fingerprint_hook",
            "js_reverse",
            "js_deobfuscate",
        ):
            max_steps = max(max_steps, 50)
        max_steps = max(3, min(max_steps, 80))

        proxy = _proxy_url(cfg)
        self._append_log(f"模型: {model} · 模式: {ui_mode} → {run_mode}")
        self._append_log(f"Agent 端点: {base}/v1/messages")
        if proxy:
            self._append_log(f"代理: {proxy}")
        summ = self.session_summary()
        self._append_log(
            f"素材: 勾选流量 {len(af)}/{summ['flows']} · "
            f"勾选JS {len(ascripts)}/{summ['scripts']} · Hook {summ['hooks']}"
        )
        ft_sum = (self.job or {}).get("field_targets_summary") or ""
        if ft_sum:
            self._append_log(f"目标字段: {ft_sum}")

        llm = ProxiedLLMClient(
            api_key=api_key,
            base_url=base,
            model=model,
            max_tokens=4096,
            temperature=0.2,
            timeout=180.0,
            proxy=proxy,
            ai_cfg=cfg,
        )
        self._append_context("request", f"======== Agent 任务 ========\nmode: {ui_mode}\n\n{goal}\n")
        agent = CryptoAgent(
            llm=llm,
            max_steps=max_steps,
            system_prompt=build_agent_system_prompt(run_mode),
            cancel_check=lambda: self._cancel,
            on_step=lambda m: self._append_log(m),
            on_llm_io=lambda kind, text: self._append_context(kind, text),
            require_steps_json=run_mode in ("generate", "recognize", "analyze_key"),
            require_anti_debug_json=run_mode == "anti_debug",
            require_hash_hook_json=run_mode == "hash_hook",
            require_bot_bypass_json=run_mode == "bot_bypass",
            require_fingerprint_hook_json=run_mode == "fingerprint_hook",
            require_js_reverse_json=run_mode == "js_reverse",
            require_js_deobfuscate_json=run_mode == "js_deobfuscate",
        )
        for tool in build_crypto_tools(self._session_data()):
            agent.register_tool(tool)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:

            async def _amain() -> str:
                return await agent.run(goal)

            task = loop.create_task(_amain())
            self._task = task
            try:
                result = loop.run_until_complete(task)
            except asyncio.CancelledError:
                with self._lock:
                    self.job["status"] = "cancelled"
                    self.job["error"] = "已取消"
                    self.job["finished_at"] = time.time()
                return
            if self._cancel:
                with self._lock:
                    self.job["status"] = "cancelled"
                    self.job["error"] = "已取消"
                    self.job["finished_at"] = time.time()
                return
            with self._lock:
                self.job["result"] = result or ""
            self._finalize_job_views(result or "")
            # 对齐 GUI：分析加解密 / 识别 产出 steps 后自动验证并 AI 修正
            try:
                self._auto_verify_and_revise(ui_mode=ui_mode, result_text=result or "")
            except Exception as ve:
                logger.exception("auto verify error")
                self._append_log(f"自动验证异常: {ve}")
            with self._lock:
                self.job["status"] = "ok"
                self.job["finished_at"] = time.time()
            self._append_log("✅ 完成")
        except Exception as e:
            logger.exception("agent run error")
            with self._lock:
                self.job["status"] = "failed"
                self.job["error"] = str(e)
                self.job["finished_at"] = time.time()
            self._append_log(f"❌ {e}")
        finally:
            self._task = None
            self._loop = None
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:
                pass
            loop.close()


_RUNTIME: AiLabRuntime | None = None


def get_runtime() -> AiLabRuntime:
    global _RUNTIME
    if _RUNTIME is None:
        _RUNTIME = AiLabRuntime()
    return _RUNTIME


def get_config_public() -> dict[str, Any]:
    cfg = load_ai_config()
    out = dict(cfg)
    out["api_key"] = mask_api_key(str(cfg.get("api_key") or ""))
    out["api_key_set"] = bool(str(cfg.get("api_key") or "").strip())
    browser = dict(out.get("browser") or {})
    out["browser"] = browser
    return out


def update_config(patch: dict[str, Any]) -> dict[str, Any]:
    cfg = load_ai_config()
    for k, v in (patch or {}).items():
        if k == "browser" and isinstance(v, dict):
            cfg["browser"] = {**(cfg.get("browser") or {}), **v}
        elif k == "api_key":
            # 空或仍是掩码则不改
            s = str(v or "").strip()
            if not s or "…" in s or s == mask_api_key(str(cfg.get("api_key") or "")):
                continue
            cfg["api_key"] = s
        else:
            cfg[k] = v
    save_ai_config(cfg)
    return get_config_public()


def default_goal_for(mode: str) -> str:
    return _DEFAULT_GOALS.get(mode) or ""


def extract_steps_from_result(text: str) -> list[dict]:
    from core.ai_analyzer import _extract_json

    try:
        obj = _extract_json(text or "")
    except Exception:
        return []
    if not isinstance(obj, dict):
        return []
    steps = obj.get("steps")
    return list(steps) if isinstance(steps, list) else []
