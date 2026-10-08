"""加解密逆向 Agent 工具 — 只读查询流量 / Hook / JS，不改内容."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from agent_core.tools.base import BaseTool, ToolMetadata

MAX_LIST = 40
MAX_BODY = 12_000
MAX_SCRIPT_CHUNK = 8_000
MAX_SEARCH_HITS = 25
MAX_HOOK_LINES = 120
MAX_SEARCH_CONTEXT = 2_400


def _clip(text: str, n: int) -> str:
    s = text or ""
    if len(s) <= n:
        return s
    return s[:n] + f"…(+{len(s) - n})"


def _ci_contains(hay: str, needle: str) -> bool:
    if not needle:
        return True
    return needle.casefold() in (hay or "").casefold()


def _approx_line(text: str, offset: int) -> int:
    """字符 offset → 约第几行（1-based），便于人工定位源码。"""
    if not text:
        return 1
    off = max(0, min(int(offset or 0), len(text)))
    return text.count("\n", 0, off) + 1


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


def _flow_seq(flow: dict, fallback: int) -> int:
    s = flow.get("_seq")
    if isinstance(s, int) and s > 0:
        return s
    return fallback


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
                "每条含 seq=捕获顺序(#1 最早)，index=当前列表下标。"
            ),
            actions=["list", "get", "search"],
            tags=["crypto", "readonly", "traffic"],
        )

    def _summary(self, i: int, f: dict) -> dict:
        return {
            "index": i,
            "seq": _flow_seq(f, i + 1),
            "method": f.get("method"),
            "url": _clip(str(f.get("url") or ""), 160),
            "status": f.get("status"),
        }

    async def execute(self, action: str, **kwargs: Any) -> Any:
        flows = self._session.flows()
        if action == "list":
            limit = int(kwargs.get("limit") or MAX_LIST)
            items = [
                self._summary(i, f)
                for i, f in enumerate(flows[: max(1, min(limit, 80))])
            ]
            return {
                "total": len(flows),
                "note": "seq 为捕获顺序（与界面 #序号一致）；index 为本列表下标，get 时用 index",
                "items": items,
            }

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
                "seq": _flow_seq(f, idx + 1),
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
                hits.append(self._summary(i, f))
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
            # Key/IV 行尽量不截断
            out = []
            for x in tail:
                raw = x or ""
                low = raw.casefold()
                if any(k in low for k in ("key", "iv", "aes", "crypto", "mode", "padding")):
                    out.append(_clip(raw, 900))
                else:
                    out.append(_clip(raw, 400))
            return {"total": len(lines), "lines": out}

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


def _resolve_script(
    scripts: dict[str, str], ref: str
) -> tuple[str, str] | None:
    """Exact or fuzzy match url/filename → (matched_url, content)."""
    if not ref:
        return None
    content = scripts.get(ref)
    if content is not None:
        return ref, content
    for u, c in scripts.items():
        if ref in u or u.endswith(ref):
            return u, c or ""
    return None


def _business_scripts(scripts: dict[str, str]) -> list[tuple[str, str]]:
    from core.script_enrich import is_library_url

    ordered = sorted(
        scripts.items(),
        key=lambda kv: (1 if is_library_url(kv[0]) else 0, kv[0]),
    )
    return [(u, c or "") for u, c in ordered if not is_library_url(u)]


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
                "只读查询已载入 JS/HTML（全文在本地索引，勿通读）。"
                "硬顺序：list → enrich/outline → search → 定点 read；禁止把整文件贴进对话。"
                "enrich=API/加解密证据；search=关键字（搜全文）；read=约8k窗口。"
                "不要翻页 crypto-js / NIM / libs。"
            ),
            actions=["list", "enrich", "outline", "ast", "search", "read"],
            tags=["crypto", "readonly", "javascript"],
        )

    def _scripts_normalized(self) -> dict[str, str]:
        from core.script_enrich import normalize_script_text

        out: dict[str, str] = {}
        for u, c in self._session.scripts().items():
            out[u] = normalize_script_text(c or "")
        return out

    async def execute(self, action: str, **kwargs: Any) -> Any:
        scripts = self._scripts_normalized()
        if action == "list":
            from core.script_enrich import is_library_url, source_kind

            items = []
            for u, c in list(scripts.items())[:80]:
                text = c or ""
                lib = is_library_url(u)
                items.append(
                    {
                        "url": u,
                        "chars": len(text),
                        "source_kind": source_kind(u, text),
                        "kind": "library" if lib else "business",
                        "hint": "库文件，勿反复分页" if lib else "优先 enrich→search",
                    }
                )
            return {
                "total": len(scripts),
                "items": items,
                "note": "全文已索引；请 enrich/search，不要 read 通读。",
            }

        if action in ("enrich", "outline", "ast"):
            from core.script_enrich import (
                enrich_source,
                format_enrich,
                format_outline,
                outline_js,
                source_kind,
            )

            ref = str(
                kwargs.get("url")
                or kwargs.get("id")
                or kwargs.get("path")
                or kwargs.get("name")
                or ""
            ).strip()
            mode = "enrich" if action == "enrich" else "outline"

            if ref:
                hit = _resolve_script(scripts, ref)
                if hit is None:
                    return {
                        "error": f"未找到脚本: {ref}",
                        "available": list(scripts.keys())[:20],
                    }
                url, content = hit
                if mode == "enrich":
                    report = enrich_source(url, content)
                    return {
                        "action": "enrich",
                        "url": url,
                        "kind": report.get("kind"),
                        "report": report,
                        "summary": format_enrich(report),
                        "note": "enrich 仅为证据；细看再用 search/read",
                    }
                kind = source_kind(url, content)
                if kind == "html":
                    report = enrich_source(url, content)
                    html = report.get("html") or {}
                    scripts_info = html.get("scripts") or {}
                    outline = report.get("outline") or {}
                    text = format_outline(outline, url)
                    ext = scripts_info.get("external") or []
                    if ext:
                        text += "\n  external:\n" + "\n".join(f"    {s}" for s in ext[:40])
                    return {
                        "action": "outline",
                        "url": url,
                        "kind": kind,
                        "outline": outline,
                        "summary": text or f"{url}\n  (html)",
                    }
                outline = outline_js(content)
                return {
                    "action": "outline",
                    "url": url,
                    "kind": kind,
                    "outline": outline,
                    "summary": format_outline(outline, url),
                }

            # 无 url：业务脚本批量 enrich/outline（最多 5 个）
            biz = _business_scripts(scripts)[:5]
            if not biz:
                # 回退：任意前 3 个
                biz = [(u, c or "") for u, c in list(scripts.items())[:3]]
            if not biz:
                return {"error": "没有已载入脚本；请先采集网页 / 小程序 / App"}

            summaries: list[str] = []
            reports: list[dict] = []
            for url, content in biz:
                if mode == "enrich":
                    report = enrich_source(url, content)
                    reports.append(report)
                    summaries.append(format_enrich(report))
                else:
                    kind = source_kind(url, content)
                    if kind == "html":
                        report = enrich_source(url, content)
                        summaries.append(format_enrich(report))
                    else:
                        outline = outline_js(content)
                        summaries.append(format_outline(outline, url))
            return {
                "action": mode,
                "count": len(biz),
                "urls": [u for u, _ in biz],
                "reports": reports if mode == "enrich" else None,
                "summary": "\n\n".join(summaries),
                "note": (
                    "已摘要业务脚本前若干个；可对具体 url 再 enrich/outline，"
                    "或 search/read 细看。勿通读全文。"
                ),
            }

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
            qlow = query.casefold()
            for url, content in ordered:
                text = content or ""
                if not (_ci_contains(url, query) or _ci_contains(text, query)):
                    continue
                low = text.casefold()
                # 同一文件可返回多处命中（最多 3 处）
                pos = 0
                found_here = 0
                while found_here < 3:
                    pos = low.find(qlow, pos)
                    if pos < 0:
                        break
                    start = max(0, pos - 200)
                    end = min(len(text), pos + len(query) + MAX_SEARCH_CONTEXT)
                    hits.append(
                        {
                            "url": url,
                            "chars": len(text),
                            "match_offset": pos,
                            "approx_line": _approx_line(text, pos),
                            "read_hint": f"script.read url=... offset={max(0, pos - 200)}",
                            "context": text[start:end],
                        }
                    )
                    found_here += 1
                    pos += max(len(query), 1)
                    if len(hits) >= MAX_SEARCH_HITS:
                        break
                if found_here == 0 and _ci_contains(url, query):
                    hits.append(
                        {
                            "url": url,
                            "chars": len(text),
                            "match_offset": 0,
                            "approx_line": 1,
                            "context": _clip(text, 200),
                        }
                    )
                if len(hits) >= MAX_SEARCH_HITS:
                    break
            return {
                "query": query,
                "hit_count": len(hits),
                "hits": hits,
                "note": (
                    "请用 match_offset 作为 script.read 的 offset；"
                    "approx_line 写入最终 JSON 的 code_locations（仅供人工找代码，不进 steps）"
                ),
            }

        if action == "read":
            url = str(
                kwargs.get("url")
                or kwargs.get("path")
                or kwargs.get("name")
                or ""
            ).strip()
            if not url:
                return {"error": "请提供 url"}
            hit = _resolve_script(scripts, url)
            if hit is None:
                return {"error": f"未找到脚本: {url}", "available": list(scripts.keys())[:20]}
            matched, content = hit
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
                "approx_line": _approx_line(content or "", offset),
                "chars_total": total,
                "content": chunk,
                "truncated": total > offset + MAX_SCRIPT_CHUNK,
                "next_offset": offset + len(chunk) if total > offset + len(chunk) else None,
                "note": (
                    "仅窗口片段。请先 enrich/search 再定点 read；"
                    "禁止为通读整文件连续翻页。"
                ),
            }

        raise ValueError(f"Unknown action: {action}")


def build_crypto_tools(session: SessionData) -> list[BaseTool]:
    """注册只读加解密查询工具（无 http / file / 写操作）."""
    return [FlowTool(session), HookTool(session), ScriptTool(session)]
