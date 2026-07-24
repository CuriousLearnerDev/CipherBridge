"""加解密逆向 Agent 工具 — 只读查询流量 / Hook / JS，不改内容."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from agent_core.tools.base import BaseTool, ToolMetadata

MAX_LIST = 40
MAX_BODY = 8_000
MAX_SCRIPT_CHUNK = 12_000
MAX_SEARCH_HITS = 25
MAX_HOOK_LINES = 80


def _clip(text: str, n: int) -> str:
    s = text or ""
    if len(s) <= n:
        return s
    return s[:n] + f"…(+{len(s) - n})"


def _ci_contains(hay: str, needle: str) -> bool:
    if not needle:
        return True
    return needle.casefold() in (hay or "").casefold()


@dataclass
class SessionData:
    """GUI 注入的只读会话素材（勿在工具内写回改流量）."""

    flows_provider: Callable[[], list[dict]] = field(default_factory=lambda: (lambda: []))
    hooks_provider: Callable[[], list[str]] = field(default_factory=lambda: (lambda: []))
    scripts_provider: Callable[[], dict[str, str]] = field(default_factory=lambda: (lambda: {}))

    def flows(self) -> list[dict]:
        try:
            return list(self.flows_provider() or [])
        except Exception:
            return []

    def hooks(self) -> list[str]:
        try:
            return list(self.hooks_provider() or [])
        except Exception:
            return []

    def scripts(self) -> dict[str, str]:
        try:
            return dict(self.scripts_provider() or {})
        except Exception:
            return {}


class FlowTool(BaseTool):
    """只读查询已抓 HTTP 流量，找密文字段 / URL."""

    def __init__(self, session: SessionData) -> None:
        super().__init__()
        self._session = session

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="flow",
            description=(
                "只读查询当前会话已抓取的 HTTP 流量。"
                "list=摘要列表；get=按 index 取详情；search=按关键字搜 URL/Body。"
            ),
            actions=["list", "get", "search"],
            tags=["crypto", "readonly", "traffic"],
        )

    async def execute(self, action: str, **kwargs: Any) -> Any:
        flows = self._session.flows()
        if action == "list":
            limit = int(kwargs.get("limit") or MAX_LIST)
            items = []
            for i, f in enumerate(flows[: max(1, min(limit, 80))]):
                items.append(
                    {
                        "index": i,
                        "method": f.get("method"),
                        "url": _clip(str(f.get("url") or ""), 160),
                        "status": f.get("status"),
                    }
                )
            return {"total": len(flows), "items": items}

        if action == "get":
            try:
                idx = int(kwargs.get("index", kwargs.get("idx", -1)))
            except (TypeError, ValueError):
                return {"error": "index 必须是整数"}
            if idx < 0 or idx >= len(flows):
                return {"error": f"index 越界，共 {len(flows)} 条"}
            f = flows[idx]
            return {
                "index": idx,
                "method": f.get("method"),
                "url": f.get("url"),
                "status": f.get("status"),
                "request_headers": f.get("request_headers") or {},
                "response_headers": f.get("response_headers") or {},
                "request_body": _clip(str(f.get("request_body") or ""), MAX_BODY),
                "response_body": _clip(str(f.get("response_body") or ""), MAX_BODY),
            }

        if action == "search":
            query = str(kwargs.get("query") or kwargs.get("q") or kwargs.get("text") or "").strip()
            if not query:
                return {"error": "请提供 query"}
            hits = []
            for i, f in enumerate(flows):
                blob = " ".join(
                    [
                        str(f.get("method") or ""),
                        str(f.get("url") or ""),
                        str(f.get("request_body") or ""),
                        str(f.get("response_body") or ""),
                    ]
                )
                if not _ci_contains(blob, query):
                    continue
                hits.append(
                    {
                        "index": i,
                        "method": f.get("method"),
                        "url": _clip(str(f.get("url") or ""), 160),
                        "status": f.get("status"),
                    }
                )
                if len(hits) >= MAX_SEARCH_HITS:
                    break
            return {"query": query, "hit_count": len(hits), "hits": hits}

        raise ValueError(f"Unknown action: {action}")


class HookTool(BaseTool):
    """只读查询 Hook 日志（Key / IV / 算法痕迹）."""

    def __init__(self, session: SessionData) -> None:
        super().__init__()
        self._session = session

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="hook",
            description=(
                "只读查询 CryptoJS/RSA 等 Hook 日志。"
                "list=最近若干行；search=按关键字过滤（如 AES、Key、IV）。"
            ),
            actions=["list", "search"],
            tags=["crypto", "readonly", "hook"],
        )

    async def execute(self, action: str, **kwargs: Any) -> Any:
        lines = self._session.hooks()
        if action == "list":
            limit = int(kwargs.get("limit") or MAX_HOOK_LINES)
            tail = lines[-max(1, min(limit, 200)) :]
            return {"total": len(lines), "lines": [_clip(x, 400) for x in tail]}

        if action == "search":
            query = str(kwargs.get("query") or kwargs.get("q") or kwargs.get("text") or "").strip()
            if not query:
                return {"error": "请提供 query"}
            hits = []
            for i, line in enumerate(lines):
                if _ci_contains(line, query):
                    hits.append({"index": i, "line": _clip(line, 500)})
                    if len(hits) >= MAX_SEARCH_HITS:
                        break
            return {"query": query, "hit_count": len(hits), "hits": hits}

        raise ValueError(f"Unknown action: {action}")


class ScriptTool(BaseTool):
    """只读查询页面 / 小程序 JS 中的加解密实现."""

    def __init__(self, session: SessionData) -> None:
        super().__init__()
        self._session = session

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="script",
            description=(
                "只读查询已载入的页面 JS / 小程序源码 / App 反编译代码（app://）。"
                "list=脚本列表；search=关键字；read=按 url+offset 读片段。"
                "优先查业务脚本，不要反复翻页 crypto-js / NIM 等库文件。"
            ),
            actions=["list", "search", "read"],
            tags=["crypto", "readonly", "javascript"],
        )

    async def execute(self, action: str, **kwargs: Any) -> Any:
        scripts = self._session.scripts()
        if action == "list":
            items = []
            for u, c in list(scripts.items())[:80]:
                text = c or ""
                lib = any(
                    x in u.lower()
                    for x in ("crypto-js", "nim_web_", "/libs/", "miniprogram_npm")
                )
                items.append(
                    {
                        "url": u,
                        "chars": len(text),
                        "kind": "library" if lib else "business",
                        "hint": "库文件，勿反复分页" if lib else "优先分析",
                    }
                )
            return {"total": len(scripts), "items": items}

        if action == "search":
            query = str(kwargs.get("query") or kwargs.get("q") or kwargs.get("text") or "").strip()
            if not query:
                return {"error": "请提供 query"}
            # 业务文件优先
            ordered = sorted(
                scripts.items(),
                key=lambda kv: (
                    1
                    if any(
                        x in kv[0].lower()
                        for x in ("crypto-js", "nim_web_", "/libs/", "miniprogram_npm")
                    )
                    else 0,
                    kv[0],
                ),
            )
            hits = []
            for url, content in ordered:
                text = content or ""
                if not (_ci_contains(url, query) or _ci_contains(text, query)):
                    continue
                low = text.casefold()
                pos = low.find(query.casefold())
                snippet = ""
                if pos >= 0:
                    start = max(0, pos - 80)
                    snippet = _clip(text[start : pos + len(query) + 160], 500)
                hits.append(
                    {
                        "url": url,
                        "chars": len(text),
                        "snippet": snippet or _clip(text, 200),
                    }
                )
                if len(hits) >= MAX_SEARCH_HITS:
                    break
            return {"query": query, "hit_count": len(hits), "hits": hits}

        if action == "read":
            url = str(
                kwargs.get("url")
                or kwargs.get("path")
                or kwargs.get("name")
                or ""
            ).strip()
            if not url:
                return {"error": "请提供 url"}
            content = scripts.get(url)
            matched = url
            if content is None:
                for u, c in scripts.items():
                    if url in u or u.endswith(url):
                        content = c
                        matched = u
                        break
            if content is None:
                return {"error": f"未找到脚本: {url}", "available": list(scripts.keys())[:20]}
            total = len(content or "")
            offset = int(kwargs.get("offset") or 0)
            if offset < 0:
                offset = 0
            if offset >= total:
                return {
                    "url": matched,
                    "offset": offset,
                    "chars_total": total,
                    "content": "",
                    "truncated": False,
                    "error": (
                        f"offset 超出已载入长度({total})。"
                        "请换业务脚本 search/read，勿对 crypto-js 等库文件继续翻页。"
                    ),
                }
            chunk = (content or "")[offset : offset + MAX_SCRIPT_CHUNK]
            return {
                "url": matched,
                "offset": offset,
                "chars_total": total,
                "content": chunk,
                "truncated": total > offset + MAX_SCRIPT_CHUNK,
                "next_offset": offset + len(chunk) if total > offset + len(chunk) else None,
            }

        raise ValueError(f"Unknown action: {action}")


def build_crypto_tools(session: SessionData) -> list[BaseTool]:
    """注册只读加解密查询工具（无 http / file / 写操作）."""
    return [FlowTool(session), HookTool(session), ScriptTool(session)]
