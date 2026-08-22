"""加解密逆向 Agent 运行器 — QThread + agent-core ReAct."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Callable, Optional

import httpx
from PyQt6.QtCore import QThread, pyqtSignal

from core.ai_config import load_ai_config, resolve_agent_base_url
from core.agent_tools import SessionData, build_crypto_tools
from core.paths import get_app_root

from agent_core import Agent, LLMClient
from agent_core.tools.base import BaseTool

logger = logging.getLogger(__name__)

CRYPTO_SYSTEM_PROMPT = """你是 JavaScript 逆向与 HTTP 加解密分析专家（密桥 Agent）。

工作方式:
1. 必须先用工具只读查询：flow（流量）、hook（Hook 日志）、script（JS）。
2. flow.list/get 中 seq 是捕获顺序（与界面 #序号一致，#1 最早）；index 是当前送入列表的下标，get 请用 index。
3. Hook 非空时：优先 hook.search（Key/IV/AES/CryptoJS），直接采信 Hook 中的算法与密钥，再用 flow 确认字段名。
4. script.search 会返回 match_offset 与 approx_line；请用该 offset 调用 script.read，禁止对同一 url+offset 重复 read。
5. 禁止反复 script.read 同一片段；若已看到 AES/CBC/Pkcs7/Key，应立即给出结论，不要再翻页。
6. 小程序/页面里 crypto-js、NIM、libs 是库文件，不要翻页。
7. 不要编造密钥；不确定时 confidence=low。
8. 禁止声称已改写流量或已写入工程。
9. 调查够用就收工；最终回复必须含可解析的 JSON（含 steps 数组）。
10. JSON 另含 code_locations（源码位置，仅供人工跳转找代码），与 steps 无关，禁止把位置写进 steps.params。
"""

_STEPS_JSON_EXAMPLE = (
    '{"summary":"AES-CBC PKCS7 解密 body 字段 data","confidence":"high",'
    '"code_locations":[{"url":"https://example.com/app.js","approx_line":1284,'
    '"offset":45678,"what":"CryptoJS.AES.encrypt","snippet":"CryptoJS.AES.encrypt(pwd, key,{mode:CryptoJS.mode.CBC..."}],'
    '"steps":[{"type":"🔓 解密字段","params":{"field":"data","algo":"AES","mode":"CBC",'
    '"key":"从Hook填写","iv":"从Hook填写","padding":"PKCS7","scope":"📋 Body (Form)"}}]}'
)

RECOGNIZE_GOAL = (
    "请用 flow / hook / script 工具查阅当前素材，识别加解密算法、模式、padding、"
    "密钥/IV、密文字段与编码。先简短中文结论，**末尾必须附带唯一 JSON**："
    + _STEPS_JSON_EXAMPLE
    + " 策略：先 hook 与 flow；script.search 后按 match_offset 最多读一次。"
    "禁止重复 script.read；看到 Key/Mode 后立刻输出 JSON。"
    "type 必须是「🔓 解密字段」等带 emoji 的完整步骤名；Hook 的 Key 写入 params.key。"
    "有 JS 命中时必须填 code_locations（url + approx_line + what），与 steps 分开，不参与生成 plugin。"
)

GENERATE_DECRYPT_GOAL = (
    "目标：生成「解密端」代理步骤。"
    "请先用 flow/hook/script 调查，最终只输出一个 JSON（可先一句摘要），格式示例："
    + _STEPS_JSON_EXAMPLE
    + " 请求解密用 🔓 解密字段；响应密文用 🔓 解密响应字段。"
    "禁止 key/mode/padding/algo 为 unknown；Hook 含 Key 必须写入 steps。"
    "Form 登录体 scope 用 📋 Body (Form)；JSON 体用 📋 Body (JSON)。"
    "另填 code_locations（源码 url/行号），仅供找代码，勿写入 steps。"
)

GENERATE_ENCRYPT_GOAL = (
    "目标：生成「加密端」代理步骤。"
    "请先用 flow/hook/script 调查，最终只输出一个 JSON，格式示例："
    '{"summary":"...","confidence":"high",'
    '"code_locations":[{"url":"...","approx_line":100,"offset":0,"what":"加密调用","snippet":"..."}],'
    '"steps":[{"type":"🔒 加密字段","params":'
    '{"field":"data","algo":"AES","mode":"CBC","key":"...","iv":"...","padding":"PKCS7",'
    '"scope":"📋 Body (Form)"}}]}。'
    "请求加密用 🔒 加密字段；可含签名 Header。"
    "禁止 key/mode/padding/algo 为 unknown；Hook 含 Key 必须写入 steps。"
    "code_locations 仅供人工定位源码，与 steps/plugin 无关。"
)

_ANTI_DEBUG_JSON_EXAMPLE = (
    '{"summary":"字面量 debugger + 递归（sojson）",'
    '"confidence":"high",'
    '"patterns":["literal-debugger+recursion","empty-while"],'
    '"script_urls":["https://example.com/encrypt.html"],'
    '"inject_opts":{"functionHook":true,"evalHook":true,"timerHook":true,'
    '"timerNuke":false,"consoleClear":true,"sizeSpoof":true,'
    '"rewriteResponse":true,"anti_debug":true,"cdp_skip_pauses":true},'
    '"hook_js":"(function(){try{console.log(\\"[密桥] 站点补丁已加载\\");}catch(e){}})();",'
    '"advice":"勾选响应改写+CDP，已附 hook_js 站点补丁；重启浏览器后再分析加解密"}'
)

ANTI_DEBUG_GOAL = (
    "目标：分析当前采集的 JS / Hook 中「无限 debugger / 反调试」实现方式，"
    "给出「注入」勾选，并尽量写一段可注入的站点补丁 hook_js。"
    "不要分析加解密算法，不要输出 steps。"
    "请先 script.list，优先业务页 HTML 与 security/pack 类脚本，不要只看 CryptoJS。"
    "请用 script.search 搜索: debugger、\\u0064、\\x64、constructor、setInterval、setTimeout、eval、Devtools、"
    "outerWidth、console.clear；混淆站还要搜 fromCharCode、\"de\"+\"bugger\"。"
    "命中后按 match_offset 用 script.read 读相关片段（每个命中最多读一次）。"
    "先用简短中文说明触发方式与关键位置。"
    "**末尾必须附带唯一 JSON**（不要 markdown 代码块），格式示例："
    + _ANTI_DEBUG_JSON_EXAMPLE
    + " inject_opts 字段含义："
    "functionHook=Hook Function/constructor；evalHook=Hook eval；"
    "timerHook=温和定时器；timerNuke=定时器整段置空(激进)；"
    "consoleClear=禁清控制台；sizeSpoof=弱化尺寸检测；"
    "rewriteResponse=响应里 debugger→return（治字面量+递归，强烈推荐）；"
    "anti_debug=注入反调试脚本；cdp_skip_pauses=CDP跳过断点。"
    " hook_js：可选，纯 JS 字符串，document_start 额外注入的站点补丁（IIFE，勿含 markdown）；"
    "仅写防御性补丁（如加固 Function/定时器、打日志），禁止外联、禁止恶意代码；"
    "若是字面量 debugger+递归，inject_opts.rewriteResponse 必须为 true，hook_js 可只打日志。"
    "禁止编造不存在的脚本 URL；没找到时 confidence=low。"
)

ANTI_DEBUG_SYSTEM_PROMPT = """你是 Web 反调试 / 无限 debugger 分析专家（密桥 Agent · 反调试模式）。

工作方式:
1. 只用 script / hook 工具；不要分析加解密，不要输出 steps。
2. 必须 script.search: debugger、\\u0064、constructor、setInterval、setTimeout、eval、Devtools、outerWidth、console.clear；混淆再搜 fromCharCode。
3. 命中后按 match_offset script.read 一次；禁止重复 read。
4. HTML 页常有 inline 反调试，优先读业务页。
5. 识别后给出 inject_opts，并尽量给出短小 hook_js 补丁。
6. 禁止编造脚本 URL；不确定则 confidence=low。
7. 够用就收工；先短中文，末尾唯一 JSON（不要 markdown 代码块）。
"""

ANTI_DEBUG_SYSTEM_EXTRA = """
最终 JSON 字段: summary, confidence, patterns, inject_opts, advice；
可选 script_urls、hook_js（可注入的 JS 字符串）。
常见模式对照:
- setInterval 内 debugger → timerHook/timerNuke + cdp
- Function/constructor("debugger") → functionHook + cdp
- eval("debugger") → evalHook
- console.clear 循环 → consoleClear
- outerWidth 检测 → sizeSpoof
- 字面量 debugger + 递归 / while(!![]){}（sojson）→ rewriteResponse=true + cdp；hook_js 可选
hook_js 必须是合法 JS 单行或含 \\n 的 JSON 字符串，用 IIFE 包裹。
"""

FORCE_ANTI_DEBUG_JSON_USER = (
    "调查阶段结束。请勿再调用任何工具。"
    "现在只输出一个 JSON 对象（不要 markdown 代码块），必须含 summary/confidence/patterns/inject_opts/advice。"
    f"示例: {_ANTI_DEBUG_JSON_EXAMPLE}"
)

_HASH_HOOK_JSON_EXAMPLE = (
    '{"summary":"password 经 Encrypt.oldPwd；用 cbBypass.hookPath 延迟挂钩",'
    '"confidence":"high",'
    '"mode":"bypass",'
    '"fields":["password"],'
    '"targets":["Encrypt.oldPwd"],'
    '"hook_js":"(function(){cbBypass.hookPath(\\"Encrypt.oldPwd\\",'
    'function(orig,args){return cbBypass.keepPlain(\\"oldPwd\\",args[0]);});'
    'cbBypass.hookCryptoJSIdentity();cbBypass.hookGlobalHashIdentity();'
    'cbBypass.patchTransportLog([\\"password\\"]);})();",'
    '"advice":"重启浏览器复测；控制台应出现 hooked …；Burp 见明文后「生成加密」。"}'
)

HASH_HOOK_GOAL = (
    "目标：写 Bypass Hook，使选定字段以明文进入 HTTP 请求（Burp 可见），"
    "用户再用「生成加密」出站重算。不要 steps / 解密插件。"
    "调查：flow.list/get 看字段；script.search: encrypt,oldPwd,md5,hex_md5,CryptoJS,password,AES,sign；"
    "命中后 script.read 一次。"
    "运行时已注入 window.cbBypass（勿重复实现轮询）。hook_js 应调用："
    "cbBypass.hookPath('A.B.fn', function(orig,args){return cbBypass.keepPlain('fn', args[0]);})、"
    "cbBypass.hookCryptoJSIdentity()、cbBypass.hookGlobalHashIdentity()。"
    "禁止只写 if(window.X){...} 一次判断；包装函数必须 return 明文，禁止再调 orig 加密。"
    "**末尾唯一 JSON**（不要 markdown），示例："
    + _HASH_HOOK_JSON_EXAMPLE
)

HASH_HOOK_SYSTEM_PROMPT = """你是前端 Bypass Hook 专家（密桥 · 高成功率模式）。

优先级（从高到低）:
1. 从 JS 找到业务加密函数真实路径（如 Encrypt.oldPwd、u.a.encrypt）→ cbBypass.hookPath
2. CryptoJS → cbBypass.hookCryptoJSIdentity()
3. 全局 md5/hex_md5 → cbBypass.hookGlobalHashIdentity()
4. 仍不确定 → 仍输出 hookPath 候选 + 上述通用调用，confidence=low

硬性规则:
- 必须使用 window.cbBypass.*，禁止一次性 if(window.Encrypt) 无轮询
- identity：return 明文入参，不要 orig.apply
- JSON: summary, confidence, mode=bypass, fields, targets, hook_js, advice
- 禁止 steps / 外联 / 恶意代码
"""

HASH_HOOK_SYSTEM_EXTRA = """
hook_js 尽量短：只写 cbBypass.hookPath(...) 与通用 identity 调用。
日志前缀由运行时打印 [密桥·BypassHook]。
"""

FORCE_HASH_HOOK_JSON_USER = (
    "调查结束，勿再调工具。只输出 JSON："
    "summary/confidence/mode/fields/targets/hook_js/advice。"
    "hook_js 必须用 cbBypass.hookPath / hookCryptoJSIdentity / hookGlobalHashIdentity。"
    "示例: " + _HASH_HOOK_JSON_EXAMPLE
)

GENERATE_SYSTEM_EXTRA = """
完成工具调查后，最终回复必须包含一个完整 JSON 对象（可先有简短说明，但 JSON 不可省略）。
steps[].type 必须是密桥构建器步骤名（如 🔓 解密字段、🔒 加密字段、📝 签名(Hash) 等），带 emoji。
另输出 code_locations 数组（url、approx_line、offset、what、snippet），记录加解密相关源码位置，
仅供人工查找代码；与 steps / plugin 生成无关，禁止写入 steps.params。
有 script.search 命中时至少填 1 条；库文件(crypto-js 等)不要当作业务位置。
"""

FORCE_JSON_USER = (
    "调查阶段结束。请勿再调用任何工具。"
    "现在只输出一个 JSON 对象（不要 markdown 代码块），必须包含非空 steps 数组。"
    f"示例: {_STEPS_JSON_EXAMPLE}"
    "把 Hook 里的 Key/IV/Mode/Padding 与 flow 里的字段名写入 params；"
    "type 必须写成「🔓 解密字段」或「🔒 加密字段」这种完整名称。"
    "若调查过 JS，一并输出 code_locations（与 steps 分开）。"
)


def build_agent_system_prompt(mode: str = "chat") -> str:
    if mode in ("generate", "recognize"):
        return CRYPTO_SYSTEM_PROMPT + "\n" + GENERATE_SYSTEM_EXTRA
    if mode == "anti_debug":
        return ANTI_DEBUG_SYSTEM_PROMPT + "\n" + ANTI_DEBUG_SYSTEM_EXTRA
    if mode == "hash_hook":
        return HASH_HOOK_SYSTEM_PROMPT + "\n" + HASH_HOOK_SYSTEM_EXTRA
    return CRYPTO_SYSTEM_PROMPT



def default_workspace_root() -> str:
    """兼容旧调用；Agent 不再提供 file 工具."""
    return os.path.join(get_app_root(), "workspace")


def _proxy_url(cfg: dict) -> str | None:
    if not cfg.get("use_http_proxy"):
        return None
    p = str(cfg.get("http_proxy") or "").strip()
    if not p:
        return None
    if not p.startswith("http"):
        p = f"http://{p}"
    return p


class ProxiedLLMClient(LLMClient):
    """支持可选 HTTP 代理的 Anthropic Messages 客户端."""

    def __init__(self, *args: Any, proxy: str | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.proxy = proxy

    async def chat_raw(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        url = f"{self.base_url}/v1/messages"
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": messages,
            "system": system,
        }
        if tools:
            payload["tools"] = tools
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "anthropic-version": "2023-06-01",
        }
        async with httpx.AsyncClient(timeout=self.timeout, proxy=self.proxy) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code != 200:
                raise RuntimeError(
                    f"LLM API error [{resp.status_code}]: {resp.text[:500]}"
                )
            return resp.json()


class CryptoAgent(Agent):
    """专用工具 schema + 可取消的 ReAct 循环."""

    SYSTEM_PROMPT = CRYPTO_SYSTEM_PROMPT

    def __init__(
        self,
        *args: Any,
        cancel_check: Callable[[], bool] | None = None,
        on_step: Callable[[str], None] | None = None,
        require_steps_json: bool = False,
        require_anti_debug_json: bool = False,
        require_hash_hook_json: bool = False,
        **kwargs: Any,
    ) -> None:
        kwargs.setdefault("system_prompt", CRYPTO_SYSTEM_PROMPT)
        kwargs.setdefault("verbose", False)
        super().__init__(*args, **kwargs)
        self._cancel_check = cancel_check or (lambda: False)
        self._on_step = on_step
        self._require_steps_json = require_steps_json
        self._require_anti_debug_json = require_anti_debug_json
        self._require_hash_hook_json = require_hash_hook_json
        self._forced_json_once = False

    def _emit(self, msg: str) -> None:
        if self._on_step:
            try:
                self._on_step(msg)
            except Exception:
                pass

    def _build_tool_schemas(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "flow",
                "description": (
                    "只读查询已抓 HTTP 流量。list 摘要；get 需 index；"
                    "search 需 query（URL/Body 关键字）。"
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["list", "get", "search"],
                            "description": "list | get | search",
                        },
                        "query": {"type": "string", "description": "search 关键字"},
                        "index": {"type": "integer", "description": "get 时的流量下标"},
                        "limit": {"type": "integer", "description": "list 条数上限"},
                    },
                    "required": ["action"],
                },
            },
            {
                "name": "hook",
                "description": "只读查询 Hook 日志。list 最近行；search 需 query（AES/Key/IV 等）。",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["list", "search"],
                        },
                        "query": {"type": "string"},
                        "limit": {"type": "integer"},
                    },
                    "required": ["action"],
                },
            },
            {
                "name": "script",
                "description": (
                    "只读查询 JS/小程序源码。list；search 需 query"
                    "（返回 match_offset、approx_line、context）；"
                    "read 需 url + offset（用 search 的 match_offset，亦返回 approx_line）。"
                    "最终 JSON 的 code_locations 请填 url+approx_line+what；"
                    "code_locations 仅供人工找代码，禁止写入 steps。"
                    "禁止对同一 url+offset 重复 read。"
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["list", "search", "read"],
                        },
                        "query": {"type": "string"},
                        "url": {"type": "string", "description": "read 时的脚本 URL"},
                        "path": {"type": "string", "description": "url 别名"},
                        "offset": {
                            "type": "integer",
                            "description": "read 起始字符下标；请用 search 的 match_offset",
                        },
                    },
                    "required": ["action"],
                },
            },
        ]

    async def _execute(self, tool_name: str, action: str, inputs: dict) -> str:
        """覆盖默认截断：script/hook 结果需要更长，否则模型会反复空读同一段。"""
        try:
            tool = self._tools.get(tool_name)
            if tool is None:
                return (
                    f"Error: Tool '{tool_name}' not found. "
                    f"Available: {self._tools.list_tools()}"
                )
            args = {k: v for k, v in inputs.items() if k != "action"}
            if action:
                await tool.validate(action, **args)
            result = await tool.execute(action, **args)
            result_str = json.dumps(result, ensure_ascii=False)
            # script.read 内容大；默认 3000 会截断导致死循环
            limit = 18000 if tool_name in ("script", "hook", "flow") else 6000
            if len(result_str) > limit:
                result_str = (
                    result_str[:limit]
                    + f"...(truncated, total {len(result_str)} chars; "
                    "请换 offset 或改用 search 的 match_offset)"
                )
            return result_str
        except Exception as e:
            return f"Error: {e}"

    async def run(self, goal: str) -> str:
        if self._cancel_check():
            raise RuntimeError("已取消")

        system = self._build_system_prompt()
        messages: list[dict[str, Any]] = [{"role": "user", "content": goal}]
        tools = self._build_tool_schemas()
        await self._tools.initialize_all()
        seen_calls: dict[str, int] = {}

        for step in range(1, self.max_steps + 1):
            if self._cancel_check():
                await self._tools.shutdown_all()
                raise RuntimeError("已取消")

            self._emit(f"[step {step}] 思考中…")
            try:
                response = await self._call_llm(system, messages, tools)
            except Exception as e:
                logger.error("LLM call failed at step %d: %s", step, e)
                self._emit(f"[step {step}] API 错误，重试: {e}")
                await asyncio.sleep(2)
                if self._cancel_check():
                    await self._tools.shutdown_all()
                    raise RuntimeError("已取消")
                continue

            thought, tool_calls, _stop = self._parse(response)
            messages.append({"role": "assistant", "content": response.get("content", [])})

            if not tool_calls:
                if (
                    self._require_steps_json
                    and not self._forced_json_once
                    and not self._text_has_steps_json(thought or "")
                ):
                    self._forced_json_once = True
                    self._emit(f"[step {step}] 未含 steps JSON，强制补一轮…")
                    messages.append({"role": "user", "content": FORCE_JSON_USER})
                    continue
                if (
                    self._require_anti_debug_json
                    and not self._forced_json_once
                    and not self._text_has_anti_debug_json(thought or "")
                ):
                    self._forced_json_once = True
                    self._emit(f"[step {step}] 未含 inject_opts JSON，强制补一轮…")
                    messages.append({"role": "user", "content": FORCE_ANTI_DEBUG_JSON_USER})
                    continue
                if (
                    self._require_hash_hook_json
                    and not self._forced_json_once
                    and not self._text_has_hash_hook_json(thought or "")
                ):
                    self._forced_json_once = True
                    self._emit(f"[step {step}] 未含 hook_js JSON，强制补一轮…")
                    messages.append({"role": "user", "content": FORCE_HASH_HOOK_JSON_USER})
                    continue
                self._emit(f"[step {step}] 完成")
                await self._tools.shutdown_all()
                return thought or "任务完成。"

            tool_results = []
            for tc in tool_calls:
                if self._cancel_check():
                    await self._tools.shutdown_all()
                    raise RuntimeError("已取消")
                tool_name = tc["name"]
                tool_input = tc.get("input", {}) or {}
                action = tool_input.get("action", "")
                # 重复调用指纹：script.read 同 url+offset 计次
                sig = json.dumps(
                    {"t": tool_name, "a": action, "i": tool_input},
                    ensure_ascii=False,
                    sort_keys=True,
                )
                seen_calls[sig] = seen_calls.get(sig, 0) + 1
                if seen_calls[sig] >= 2 and tool_name == "script" and action == "read":
                    self._emit(
                        f"[step {step}] ⚠ 重复 script.read，跳过并要求下结论"
                    )
                    result = json.dumps(
                        {
                            "error": "同一 url+offset 已读过，禁止重复。",
                            "hint": (
                                "请综合已有 hook/flow/script 结果立即给出中文结论与 JSON，"
                                "不要再调用 script.read。系统将不再返回新脚本内容。"
                            ),
                        },
                        ensure_ascii=False,
                    )
                else:
                    self._emit(f"[step {step}] 🔧 {tool_name}.{action}")
                    result = await self._execute(tool_name, action, tool_input)
                    preview = result.replace("\n", " ")[:220]
                    self._emit(f"  → {preview}")
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tc.get("id", ""),
                        "content": result,
                    }
                )
            messages.append({"role": "user", "content": tool_results})

        await self._tools.shutdown_all()
        if self._require_steps_json:
            self._emit("步数用尽，强制补一轮 steps JSON…")
            try:
                messages.append({"role": "user", "content": FORCE_JSON_USER})
                response = await self._call_llm(system, messages, tools=[])
                thought, tool_calls, _stop = self._parse(response)
                if thought and self._text_has_steps_json(thought):
                    return thought
                if thought:
                    return thought
            except Exception as e:
                logger.error("force json failed: %s", e)
        if self._require_anti_debug_json:
            self._emit("步数用尽，强制补一轮 inject_opts JSON…")
            try:
                messages.append({"role": "user", "content": FORCE_ANTI_DEBUG_JSON_USER})
                response = await self._call_llm(system, messages, tools=[])
                thought, tool_calls, _stop = self._parse(response)
                if thought:
                    return thought
            except Exception as e:
                logger.error("force anti_debug json failed: %s", e)
        if self._require_hash_hook_json:
            self._emit("步数用尽，强制补一轮 hook_js JSON…")
            try:
                messages.append({"role": "user", "content": FORCE_HASH_HOOK_JSON_USER})
                response = await self._call_llm(system, messages, tools=[])
                thought, tool_calls, _stop = self._parse(response)
                if thought:
                    return thought
            except Exception as e:
                logger.error("force hash_hook json failed: %s", e)
        return (
            "已达最大步数仍未收工。常见原因：对同一脚本片段重复 read。"
            "请再跑一次；系统已禁止重复 read，并会优先采信 Hook 中的 Key。"
        )

    @staticmethod
    def _text_has_steps_json(text: str) -> bool:
        if not text or "steps" not in text:
            return False
        try:
            from core.ai_analyzer import _extract_json

            obj = _extract_json(text)
            steps = obj.get("steps")
            return isinstance(steps, list) and len(steps) > 0
        except Exception:
            return False

    @staticmethod
    def _text_has_anti_debug_json(text: str) -> bool:
        if not text or "inject_opts" not in text:
            return False
        try:
            from core.ai_analyzer import _extract_json

            obj = _extract_json(text)
            return isinstance(obj, dict) and isinstance(obj.get("inject_opts"), dict)
        except Exception:
            return False

    @staticmethod
    def _text_has_hash_hook_json(text: str) -> bool:
        if not text or "hook_js" not in text:
            return False
        try:
            from core.ai_analyzer import _extract_json

            obj = _extract_json(text)
            return isinstance(obj, dict) and bool(str(obj.get("hook_js") or "").strip())
        except Exception:
            return False


class AgentWorker(QThread):
    """后台运行加解密 Agent，不阻塞 GUI."""

    log = pyqtSignal(str)
    finished_ok = pyqtSignal(str)
    failed = pyqtSignal(str)

    def __init__(
        self,
        goal: str,
        session: SessionData,
        cfg: dict | None = None,
        *,
        mode: str = "chat",
        parent=None,
    ):
        super().__init__(parent)
        self.goal = (goal or "").strip()
        self.session = session
        self.cfg = dict(cfg or load_ai_config())
        self.mode = mode or "chat"
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:
        try:
            api_key = str(self.cfg.get("api_key") or "").strip()
            if not api_key:
                self.failed.emit("请先在「配置」填写 API Key")
                return
            if not self.goal:
                self.failed.emit("请输入 Agent 任务")
                return

            base = resolve_agent_base_url(self.cfg)
            model = str(self.cfg.get("model") or "deepseek-chat").strip()
            try:
                max_steps = int(self.cfg.get("agent_max_steps") or 50)
            except (TypeError, ValueError):
                max_steps = 50
            if self.mode in ("generate", "recognize", "anti_debug", "hash_hook"):
                max_steps = max(max_steps, 50)
            max_steps = max(3, min(max_steps, 80))

            proxy = _proxy_url(self.cfg)
            self.log.emit(f"模型: {model} · 模式: {self.mode}")
            self.log.emit(f"Agent 端点: {base}/v1/messages")
            if proxy:
                self.log.emit(f"代理: {proxy}")

            llm = ProxiedLLMClient(
                api_key=api_key,
                base_url=base,
                model=model,
                max_tokens=4096,
                temperature=0.2,
                timeout=180.0,
                proxy=proxy,
            )
            agent = CryptoAgent(
                llm=llm,
                max_steps=max_steps,
                system_prompt=build_agent_system_prompt(self.mode),
                cancel_check=lambda: self._cancelled,
                on_step=lambda m: self.log.emit(m),
                require_steps_json=self.mode in ("generate", "recognize"),
                require_anti_debug_json=self.mode == "anti_debug",
                require_hash_hook_json=self.mode == "hash_hook",
            )
            for tool in build_crypto_tools(self.session):
                agent.register_tool(tool)

            result = asyncio.run(agent.run(self.goal))
            if self._cancelled:
                self.failed.emit("已取消")
                return
            self.finished_ok.emit(result)
        except RuntimeError as e:
            msg = str(e)
            if "已取消" in msg or self._cancelled:
                self.failed.emit("已取消")
            else:
                self.failed.emit(msg)
        except Exception as e:
            logger.exception("AgentWorker failed")
            self.failed.emit(str(e))
