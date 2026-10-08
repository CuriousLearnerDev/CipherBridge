"""JS/HTML 结构化摘要（outline / enrich）— 纯 Python 正则启发，零新依赖.

对齐 deepseek-harness tool-source-cache 的证据字段，精度低于真 AST，
供 Agent 先读摘要再定点 script.search / script.read。
"""

from __future__ import annotations

import re
from typing import Any

CAP = 80
EDGE_CAP = 40
INLINE_ENRICH_CAP = 8

# 内联 source map（尤其 data:application/json;base64,...）极长，占存储/干扰搜索
_RE_SOURCE_MAPPING = re.compile(
    r"(?://[#@]|/\*[#@])\s*sourceMappingURL\s*=\s*\S+",
    re.IGNORECASE,
)
_RE_SOURCE_MAPPING_BLOCK = re.compile(
    r"/\*[#@]\s*sourceMappingURL\s*=\s*[\s\S]*?\*/",
    re.IGNORECASE,
)


def strip_source_maps(text: str) -> tuple[str, int]:
    """去掉 sourceMappingURL（含巨型 base64 data URL）。返回 (正文, 去掉的字符数)."""
    raw = text or ""
    if not raw or "sourcemappingurl" not in raw.casefold():
        return raw, 0
    cleaned = _RE_SOURCE_MAPPING_BLOCK.sub("", raw)
    cleaned = _RE_SOURCE_MAPPING.sub("", cleaned)
    # 行尾残留空白行压缩一点
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).rstrip() + ("\n" if raw.endswith("\n") else "")
    removed = max(0, len(raw) - len(cleaned))
    return cleaned, removed


def normalize_script_text(text: str) -> str:
    """入库 / 检索前规范化：剥 source map。"""
    cleaned, _ = strip_source_maps(text or "")
    return cleaned

_RE_FN_DECL = re.compile(
    r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(",
    re.MULTILINE,
)
_RE_FN_ASSIGN = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)",
    re.MULTILINE,
)
_RE_CLASS = re.compile(r"\bclass\s+([A-Za-z_$][\w$]*)\b", re.MULTILINE)
_RE_IMPORT = re.compile(
    r"""(?:import\s+(?:[^'";]+?\s+from\s+)?|require\s*\(\s*)['"]([^'"]+)['"]""",
    re.MULTILINE,
)
_RE_PATH_STR = re.compile(r"""['"](/[^'"\s<>{}]{3,198})['"]""")
_RE_HTTP_STR = re.compile(r"""['"](https?://[^'"\s<>{}]{3,198})['"]""")

# callee('path') or callee("path") — first string arg
_RE_CALL_PATH = re.compile(
    r"""([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(\s*['"]([^'"]{3,200})['"]""",
)

_RE_FETCH = re.compile(
    r"""\bfetch\s*\(\s*['"]([^'"]+)['"](?:\s*,\s*\{([^}]{0,400})\})?""",
    re.IGNORECASE,
)
_RE_AXIOS_METHOD = re.compile(
    r"""\b(axios|\$|jQuery)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
_RE_AXIOS_AJAX = re.compile(
    r"""\b(axios(?:\.request)?|\$\.ajax|jQuery\.ajax)\s*\(\s*\{([^}]{0,500})\}""",
    re.IGNORECASE,
)
_RE_XHR_OPEN = re.compile(
    r"""\.open\s*\(\s*['"](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"]\s*,\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

_RE_CRYPTO_CALL = re.compile(
    r"""\b((?:CryptoJS(?:\.[A-Za-z_$][\w$]*)+)|(?:JSEncrypt(?:\.[A-Za-z_$][\w$]*)*)"""
    r"""|(?:[A-Za-z_$][\w$]*\.)?(?:aesEncrypt|rsaEncrypt|encryptData|decryptData|encrypt|decrypt|MD5|SHA(?:1|256|512)?|btoa|atob))"""
    r"""\s*\(""",
    re.IGNORECASE,
)

_RE_SCRIPT_TAG = re.compile(
    r"<script\b([^>]*)>([\s\S]*?)</script>",
    re.IGNORECASE,
)
_RE_SCRIPT_SRC_ATTR = re.compile(r"""\bsrc\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
_RE_DOC_WRITE_JS = re.compile(
    r"""src\s*=\s*['"]([^'"]+\.js(?:\?[^'"]*)?)['"]""",
    re.IGNORECASE,
)
_RE_FORM = re.compile(
    r"<form\b([^>]*)>([\s\S]*?)</form>",
    re.IGNORECASE,
)
_RE_ATTR = re.compile(r"""\b(action|method|name|type|id)\s*=\s*['"]([^'"]*)['"]""", re.IGNORECASE)
_RE_INPUT = re.compile(r"<input\b([^>]*)/?>", re.IGNORECASE)
_RE_META = re.compile(
    r"""<meta\b[^>]*\b(?:name|property)\s*=\s*['"]([^'"]+)['"][^>]*\bcontent\s*=\s*['"]([^'"]*)['"]""",
    re.IGNORECASE,
)

_LIB_URL_MARKERS = (
    "crypto-js",
    "nim_web_",
    "/libs/",
    "miniprogram_npm",
    "jquery",
    "vue.",
    "react.",
)


def _approx_line(text: str, offset: int) -> int:
    if not text:
        return 1
    off = max(0, min(int(offset or 0), len(text)))
    return text.count("\n", 0, off) + 1


def _push_unique(lst: list[str], value: str, cap: int = CAP) -> None:
    if not value or len(lst) >= cap or value in lst:
        return
    lst.append(value)


def looks_like_path(value: str) -> bool:
    text = (value or "").strip()
    if len(text) < 4 or len(text) > 200:
        return False
    if re.search(r"[\s*<>{}]", text):
        return False
    if text.startswith("./") or text.startswith("../") or text.startswith("//"):
        return False
    if not (text.startswith("/") or re.match(r"^https?://", text, re.I)):
        return False
    if re.search(r"\.(?:js|mjs|css|png|jpe?g|gif|svg|ico|map|html?)(?:\?|$)", text, re.I):
        return False
    return bool(re.search(r"[a-z]", text, re.I))


def source_kind(url: str, content: str = "") -> str:
    path = (url.split("?")[0] or "").lower()
    if path.endswith((".html", ".htm")) or url.startswith("http") and "<html" in (content or "")[:500].lower():
        if "<html" in (content or "")[:800].lower() or "<!doctype" in (content or "")[:200].lower():
            return "html"
        if path.endswith((".html", ".htm")):
            return "html"
    if path.endswith((".js", ".mjs", ".cjs")) or url.startswith("app://"):
        return "js"
    head = (content or "")[:400].lstrip().lower()
    if head.startswith("<!doctype") or head.startswith("<html") or "<script" in head[:200]:
        return "html"
    if path.endswith(".css"):
        return "css"
    if path.endswith(".json"):
        return "json"
    # default: treat as js if looks like code
    if "function" in (content or "")[:2000] or "=>" in (content or "")[:2000]:
        return "js"
    return "other"


def is_library_url(url: str) -> bool:
    low = (url or "").lower()
    return any(m in low for m in _LIB_URL_MARKERS)


def outline_js(source: str) -> dict[str, Any]:
    """Bounded JS outline (heuristic)."""
    text = source or ""
    functions: list[str] = []
    imports: list[str] = []
    calls: list[str] = []
    paths: list[str] = []
    call_sites: list[dict[str, Any]] = []

    for m in _RE_FN_DECL.finditer(text):
        _push_unique(functions, m.group(1))
    for m in _RE_FN_ASSIGN.finditer(text):
        _push_unique(functions, m.group(1))
    for m in _RE_CLASS.finditer(text):
        _push_unique(functions, m.group(1))
    for m in _RE_IMPORT.finditer(text):
        _push_unique(imports, m.group(1), cap=40)

    for m in _RE_CALL_PATH.finditer(text):
        callee, arg = m.group(1), m.group(2)
        _push_unique(calls, callee)
        if looks_like_path(arg) and len(call_sites) < CAP:
            call_sites.append(
                {
                    "callee": callee,
                    "arg": arg,
                    "line": _approx_line(text, m.start()),
                }
            )
            _push_unique(paths, arg)

    for m in _RE_PATH_STR.finditer(text):
        if looks_like_path(m.group(1)):
            _push_unique(paths, m.group(1))
    for m in _RE_HTTP_STR.finditer(text):
        if looks_like_path(m.group(1)):
            _push_unique(paths, m.group(1))

    return {
        "ok": True,
        "functions": functions,
        "imports": imports,
        "calls": calls[:CAP],
        "paths": paths,
        "callSites": call_sites,
    }


def _method_from_opts_blob(blob: str) -> str:
    m = re.search(r"""(?:method|type)\s*:\s*['"](\w+)['"]""", blob or "", re.I)
    return (m.group(1) if m else "GET").upper()


def _url_from_opts_blob(blob: str) -> str | None:
    m = re.search(r"""(?:url)\s*:\s*['"]([^'"]+)['"]""", blob or "", re.I)
    return m.group(1) if m else None


def _crypto_kind(name: str) -> str | None:
    if re.search(r"CryptoJS", name, re.I):
        return "CryptoJS"
    if re.search(r"JSEncrypt", name, re.I):
        return "RSA"
    base = name.rsplit(".", 1)[-1]
    if re.match(r"^AES$", base, re.I) or re.search(r"aesEncrypt", name, re.I):
        return "AES"
    if re.match(r"^RSA$", base, re.I) or re.search(r"rsaEncrypt", name, re.I):
        return "RSA"
    if re.match(r"^MD5$", base, re.I):
        return "MD5"
    if re.match(r"^SHA", base, re.I):
        return "hash"
    if re.search(r"encrypt", base, re.I):
        return "encrypt"
    if re.search(r"decrypt", base, re.I):
        return "decrypt"
    if re.match(r"^(?:btoa|atob)$", base, re.I):
        return "base64"
    return "crypto"


def _push_api(lst: list[dict], hint: dict) -> None:
    if len(lst) >= CAP:
        return
    for row in lst:
        if (
            row.get("callee") == hint.get("callee")
            and row.get("url") == hint.get("url")
            and row.get("method") == hint.get("method")
            and row.get("line") == hint.get("line")
        ):
            return
    lst.append(hint)


def _push_crypto(lst: list[dict], hint: dict) -> None:
    if len(lst) >= CAP:
        return
    for row in lst:
        if (
            row.get("kind") == hint.get("kind")
            and row.get("callee") == hint.get("callee")
            and row.get("line") == hint.get("line")
        ):
            return
    lst.append(hint)


def enrich_js(source: str, label: str = "") -> dict[str, Any]:
    """API / crypto / call-edge evidence for one JS body."""
    text = source or ""
    outline = outline_js(text)
    api_calls: list[dict[str, Any]] = []
    crypto_hints: list[dict[str, Any]] = []
    call_edges: list[dict[str, Any]] = []

    for m in _RE_FETCH.finditer(text):
        url = m.group(1)
        if not looks_like_path(url):
            continue
        method = "GET"
        opts = m.group(2) or ""
        if opts:
            method = _method_from_opts_blob(opts)
        _push_api(
            api_calls,
            {
                "callee": "fetch",
                "method": method,
                "url": url,
                "line": _approx_line(text, m.start()),
            },
        )

    for m in _RE_AXIOS_METHOD.finditer(text):
        callee = f"{m.group(1)}.{m.group(2)}"
        url = m.group(3)
        if not looks_like_path(url):
            continue
        _push_api(
            api_calls,
            {
                "callee": callee,
                "method": m.group(2).upper(),
                "url": url,
                "line": _approx_line(text, m.start()),
            },
        )

    for m in _RE_AXIOS_AJAX.finditer(text):
        url = _url_from_opts_blob(m.group(2) or "")
        if not url or not looks_like_path(url):
            continue
        _push_api(
            api_calls,
            {
                "callee": m.group(1),
                "method": _method_from_opts_blob(m.group(2) or ""),
                "url": url,
                "line": _approx_line(text, m.start()),
            },
        )

    for m in _RE_XHR_OPEN.finditer(text):
        url = m.group(2)
        if not looks_like_path(url):
            continue
        _push_api(
            api_calls,
            {
                "callee": "XMLHttpRequest.open",
                "method": m.group(1).upper(),
                "url": url,
                "line": _approx_line(text, m.start()),
            },
        )

    for m in _RE_CRYPTO_CALL.finditer(text):
        name = m.group(1)
        kind = _crypto_kind(name)
        # peek first string arg snippet
        rest = text[m.end() : m.end() + 80]
        snip_m = re.match(r"""\s*['"]([^'"]{0,80})['"]""", rest)
        hint: dict[str, Any] = {
            "kind": kind or "crypto",
            "callee": name,
            "line": _approx_line(text, m.start()),
        }
        if snip_m:
            hint["snippet"] = snip_m.group(1)
        _push_crypto(crypto_hints, hint)

    # Rough edges: inside function body, collect callee names (window ~800 chars)
    for m in _RE_FN_DECL.finditer(text):
        fname = m.group(1)
        body = text[m.end() : m.end() + 800]
        seen: set[str] = set()
        for cm in re.finditer(r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(", body):
            to = cm.group(1)
            if to == fname or to in ("if", "for", "while", "switch", "catch", "function"):
                continue
            key = f"{fname}->{to}"
            if key in seen:
                continue
            seen.add(key)
            if len(call_edges) >= EDGE_CAP:
                break
            call_edges.append(
                {
                    "from": fname,
                    "to": to,
                    "line": _approx_line(text, m.start() + cm.start()),
                }
            )

    return {
        "ok": True,
        "kind": "js",
        "label": label or "",
        "outline": outline,
        "apiCalls": api_calls,
        "cryptoHints": crypto_hints,
        "callEdges": call_edges,
    }


def html_scripts(html: str) -> dict[str, Any]:
    external: list[str] = []
    inline: list[str] = []
    for m in _RE_SCRIPT_TAG.finditer(html or ""):
        attrs, body = m.group(1) or "", (m.group(2) or "").strip()
        src_m = _RE_SCRIPT_SRC_ATTR.search(attrs)
        if src_m:
            src = src_m.group(1)
            if src and src not in external:
                external.append(src)
        elif body:
            inline.append(body)
    for m in _RE_DOC_WRITE_JS.finditer(html or ""):
        src = m.group(1)
        if src and src not in external:
            external.append(src)
    return {"external": external, "inline": inline}


def enrich_html(html: str, label: str = "") -> dict[str, Any]:
    text = html or ""
    scripts = html_scripts(text)
    forms: list[dict[str, Any]] = []
    for m in _RE_FORM.finditer(text):
        attrs, body = m.group(1) or "", m.group(2) or ""
        action, method = "", "GET"
        for am in _RE_ATTR.finditer(attrs):
            key, val = am.group(1).lower(), am.group(2)
            if key == "action":
                action = val
            elif key == "method":
                method = val.upper() or "GET"
        inputs: list[str] = []
        for im in _RE_INPUT.finditer(body):
            name = ""
            for am in _RE_ATTR.finditer(im.group(1) or ""):
                if am.group(1).lower() in ("name", "id") and am.group(2):
                    name = am.group(2)
                    break
            if name and name not in inputs:
                inputs.append(name)
            if len(inputs) >= 20:
                break
        if len(forms) < 40:
            forms.append({"action": action, "method": method, "inputs": inputs})

    meta: list[str] = []
    for m in _RE_META.finditer(text):
        _push_unique(meta, f"{m.group(1)}={m.group(2)}", cap=30)

    inline_reports: list[dict[str, Any]] = []
    for i, body in enumerate(scripts["inline"][:INLINE_ENRICH_CAP]):
        inline_reports.append(
            enrich_js(body, f"{label or 'html'}#inline{i + 1}")
        )

    # merge top-level crypto/api from inlines
    api_calls: list[dict] = []
    crypto_hints: list[dict] = []
    call_edges: list[dict] = []
    for rep in inline_reports:
        for row in rep.get("apiCalls") or []:
            _push_api(api_calls, row)
        for row in rep.get("cryptoHints") or []:
            _push_crypto(crypto_hints, row)
        for row in rep.get("callEdges") or []:
            if len(call_edges) < EDGE_CAP:
                call_edges.append(row)

    empty_outline = {
        "ok": True,
        "functions": [],
        "imports": [],
        "calls": [],
        "paths": [],
        "callSites": [],
    }
    return {
        "ok": True,
        "kind": "html",
        "label": label or "",
        "outline": empty_outline,
        "apiCalls": api_calls,
        "cryptoHints": crypto_hints,
        "callEdges": call_edges,
        "html": {
            "scripts": {
                "external": scripts["external"][:40],
                "inlineCount": len(scripts["inline"]),
            },
            "forms": forms,
            "meta": meta,
        },
        "inline": inline_reports,
    }


def enrich_source(url: str, content: str) -> dict[str, Any]:
    kind = source_kind(url, content)
    if kind == "html":
        return enrich_html(content, url)
    if kind == "js":
        return enrich_js(content, url)
    return {
        "ok": True,
        "kind": kind,
        "label": url,
        "outline": outline_js(content) if content else {
            "ok": True,
            "functions": [],
            "imports": [],
            "calls": [],
            "paths": [],
            "callSites": [],
        },
        "apiCalls": [],
        "cryptoHints": [],
        "callEdges": [],
        "error": f"kind={kind}；请用 search/read，不要只靠 enrich",
    }


def format_outline(outline: dict[str, Any], label: str) -> str:
    if not outline.get("ok", True) and outline.get("error"):
        return f"{label}\n  parse error: {outline.get('error')}"
    sites = outline.get("callSites") or []
    site_lines = [
        f"  {s.get('callee')}({s.get('arg') or ''}) @{s.get('line')}"
        for s in sites[:40]
    ]
    parts = [label]
    fns = outline.get("functions") or []
    if fns:
        parts.append(f"  fn: {', '.join(fns[:30])}")
    imps = outline.get("imports") or []
    if imps:
        parts.append(f"  import: {', '.join(imps[:20])}")
    if site_lines:
        parts.append("  calls:\n" + "\n".join(site_lines))
    paths = outline.get("paths") or []
    if paths:
        parts.append(f"  paths: {' | '.join(paths[:40])}")
    return "\n".join(parts) if len(parts) > 1 else f"{label}\n  (empty outline)"


def format_enrich(report: dict[str, Any]) -> str:
    label = str(report.get("label") or report.get("kind") or "source")
    lines = [f"[enrich] {label}  kind={report.get('kind')}"]
    if report.get("error"):
        lines.append(f"  note: {report['error']}")

    outline = report.get("outline") or {}
    fns = outline.get("functions") or []
    if fns:
        lines.append(f"  fn: {', '.join(fns[:24])}")

    apis = report.get("apiCalls") or []
    if apis:
        lines.append("  apiCalls:")
        for a in apis[:30]:
            lines.append(
                f"    {a.get('method') or ''} {a.get('callee')} {a.get('url')} @{a.get('line')}"
            )

    cryptos = report.get("cryptoHints") or []
    if cryptos:
        lines.append("  cryptoHints:")
        for c in cryptos[:30]:
            snip = f"  «{c.get('snippet')}»" if c.get("snippet") else ""
            lines.append(f"    [{c.get('kind')}] {c.get('callee')} @{c.get('line')}{snip}")

    edges = report.get("callEdges") or []
    if edges:
        lines.append("  callEdges:")
        for e in edges[:24]:
            lines.append(f"    {e.get('from')} -> {e.get('to')} @{e.get('line')}")

    html = report.get("html")
    if isinstance(html, dict):
        scripts = html.get("scripts") or {}
        ext = scripts.get("external") or []
        if ext:
            lines.append("  external scripts:")
            for s in ext[:30]:
                lines.append(f"    {s}")
        ic = scripts.get("inlineCount")
        if ic:
            lines.append(f"  inline scripts: {ic}")
        forms = html.get("forms") or []
        if forms:
            lines.append("  forms:")
            for f in forms[:15]:
                lines.append(
                    f"    {f.get('method')} {f.get('action') or '(no action)'} "
                    f"inputs={','.join(f.get('inputs') or [])}"
                )

    if len(lines) == 1:
        lines.append("  (no api/crypto/html hints; try search/read)")
    lines.append("  → enrich 仅为证据；需要源码时再用 script.search / script.read")
    return "\n".join(lines)
