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
1. 必须先用工具只读查询当前会话素材：flow（流量）、hook（Hook 日志）、script（页面/小程序 JS 或 App 反编译 app:// 代码）。
2. 根据工具结果推断算法、模式、padding、密钥/IV 线索、字段名与编码（Base64/Hex）。
3. App 素材（app://…smali/java）常含 Cipher / SecretKeySpec / AESUtil，请优先对照。
4. 小程序 script 中 crypto-js / NIM / libs 仅为库，不要反复 offset 翻页；优先业务模块。
5. 不要编造密钥；Hook 有 Key 时优先引用；不确定时明确 confidence=low。
6. 禁止声称已改写流量、已写入 plugin、已修改工程文件。
7. 素材不足时说明还缺什么（例如再抓包、开 Hook、解包小程序、反编译 APK）。
8. 调查足够后尽快给出结论，不要把步数耗在无效翻页上。
"""

RECOGNIZE_GOAL = (
    "请用 flow / hook / script 工具查阅当前素材，识别加解密算法、模式、padding、"
    "密钥/IV、密文字段与编码。给出中文结论与证据出处；若步骤可确定，末尾附带 JSON："
    '{"summary":"...","confidence":"high|medium|low","steps":[...]}。'
    "注意：script.list 里 kind=library（crypto-js/NIM/libs）不要反复翻页；"
    "优先 search/read 业务脚本；hook 为空时明确说明，并结合 flow 请求体形态推断。"
)

GENERATE_DECRYPT_GOAL = (
    "目标：生成「解密端」代理步骤。"
    "请先用 flow/hook/script 工具调查，再输出唯一 JSON 对象（不要 markdown 代码块），格式："
    '{"summary":"简短中文","confidence":"high|medium|low","steps":[{"type":"🔓 解密字段","params":{...}}]}。'
    "请求解密用 🔓 解密字段；响应密文用 🔓 解密响应字段。"
    "禁止 key/mode/padding/algo 为 unknown；Hook 含 Key 必须写入 steps。"
)

GENERATE_ENCRYPT_GOAL = (
    "目标：生成「加密端」代理步骤。"
    "请先用 flow/hook/script 工具调查，再输出唯一 JSON 对象（不要 markdown 代码块），格式："
    '{"summary":"简短中文","confidence":"high|medium|low","steps":[{"type":"🔒 加密字段","params":{...}}]}。'
    "请求加密用 🔒 加密字段；需加密响应用 🔒 加密响应字段；可含签名 Header 步骤。"
    "禁止 key/mode/padding/algo 为 unknown；Hook 含 Key 必须写入 steps。"
)

GENERATE_SYSTEM_EXTRA = """
完成工具调查后，最终回复必须包含一个完整 JSON 对象（可先有简短说明，但 JSON 不可省略）。
steps[].type 必须是密桥构建器步骤名（如 🔓 解密字段、🔒 加密字段、📝 签名(Hash) 等）。
"""


def build_agent_system_prompt(mode: str = "chat") -> str:
    if mode in ("generate", "recognize"):
        return CRYPTO_SYSTEM_PROMPT + "\n" + GENERATE_SYSTEM_EXTRA
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
        **kwargs: Any,
    ) -> None:
        kwargs.setdefault("system_prompt", CRYPTO_SYSTEM_PROMPT)
        kwargs.setdefault("verbose", False)
        super().__init__(*args, **kwargs)
        self._cancel_check = cancel_check or (lambda: False)
        self._on_step = on_step

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
                    "只读查询 JS/小程序源码。list；search 需 query；"
                    "read 需 url（可子串匹配）。"
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
                        "offset": {"type": "integer"},
                    },
                    "required": ["action"],
                },
            },
        ]

    async def run(self, goal: str) -> str:
        if self._cancel_check():
            raise RuntimeError("已取消")

        system = self._build_system_prompt()
        messages: list[dict[str, Any]] = [{"role": "user", "content": goal}]
        tools = self._build_tool_schemas()
        await self._tools.initialize_all()

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
        return "已达最大步数，请缩小问题或补充素材后重试。"


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
                max_steps = int(self.cfg.get("agent_max_steps") or 12)
            except (TypeError, ValueError):
                max_steps = 12
            if self.mode in ("generate", "recognize"):
                max_steps = max(max_steps, 15)
            max_steps = max(3, min(max_steps, 40))

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
