"""反调试文本改写：字面量 / 转义 / 拼接形式的 debugger，以及空死循环.

对 sojson 一类「两侧都 debugger + 递归」的代码：
  仅删除 debugger 仍会递归爆栈；改成 return 可打断后续递归。
混淆常见写法也会尝试覆盖（unicode / hex / "de"+"bugger"）。
"""

from __future__ import annotations

import re

# 明文 debugger
_RE_DEBUGGER = re.compile(r"\bdebugger\b", re.IGNORECASE)

# \u0064\u0065\u0062\u0075\u0067\u0067\u0065\u0072 （大小写十六进制）
_RE_DEBUGGER_UNICODE = re.compile(
    r"(?:\\u0064|\\u0044)(?:\\u0065|\\u0045)(?:\\u0062|\\u0042)"
    r"(?:\\u0075|\\u0055)(?:\\u0067|\\u0047){2}(?:\\u0065|\\u0045)(?:\\u0072|\\u0052)",
    re.IGNORECASE,
)

# \x64\x65\x62\x75\x67\x67\x65\x72
_RE_DEBUGGER_HEX = re.compile(
    r"(?:\\x64|\\x44)(?:\\x65|\\x45)(?:\\x62|\\x42)"
    r"(?:\\x75|\\x55)(?:\\x67|\\x47){2}(?:\\x65|\\x45)(?:\\x72|\\x52)",
    re.IGNORECASE,
)

# "de"+"bugger" / 'de'+'bugger' / "deb"+"ugger" 等简单拼接
_RE_DEBUGGER_CONCAT = re.compile(
    r"""(['"])de\1\s*\+\s*\1bugger\1"""
    r"""|(['"])deb\2\s*\+\s*\2ugger\2"""
    r"""|(['"])debug\3\s*\+\s*\3ger\3""",
    re.IGNORECASE,
)

# while(true){} / while(!![]){} / while(!0){}
_RE_EMPTY_WHILE = re.compile(
    r"while\s*\(\s*(?:!!\s*\[\s*\]|!0|true)\s*\)\s*\{\s*\}",
    re.IGNORECASE,
)


def rewrite_anti_debug_js(text: str) -> tuple[str, dict]:
    """改写 JS/HTML 文本。返回 (新文本, 统计)."""
    if not text:
        return text, {"debugger": 0, "unicode": 0, "hex": 0, "concat": 0, "empty_while": 0}

    n_dbg = len(_RE_DEBUGGER.findall(text))
    out = _RE_DEBUGGER.sub("return", text)

    n_uni = len(_RE_DEBUGGER_UNICODE.findall(out))
    out = _RE_DEBUGGER_UNICODE.sub("return", out)

    n_hex = len(_RE_DEBUGGER_HEX.findall(out))
    out = _RE_DEBUGGER_HEX.sub("return", out)

    n_cat = len(_RE_DEBUGGER_CONCAT.findall(out))
    out = _RE_DEBUGGER_CONCAT.sub('"return"', out)

    n_while = len(_RE_EMPTY_WHILE.findall(out))
    out = _RE_EMPTY_WHILE.sub("/*cb-loop*/", out)

    return out, {
        "debugger": n_dbg,
        "unicode": n_uni,
        "hex": n_hex,
        "concat": n_cat,
        "empty_while": n_while,
    }


def should_rewrite_url(url: str, content_type: str = "") -> bool:
    low = (url or "").lower().split("?", 1)[0]
    ct = (content_type or "").lower()
    if any(x in ct for x in ("javascript", "ecmascript", "html", "xml")):
        return True
    if low.endswith((".js", ".mjs", ".cjs", ".html", ".htm", ".xhtml")):
        return True
    if "javascript" in ct or "html" in ct:
        return True
    return False
