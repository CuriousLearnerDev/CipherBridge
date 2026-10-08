"""自测 script enrich / outline（无 GUI、无网络）。

用法:
  python scripts/selftest_script_enrich.py
"""

from __future__ import annotations

import asyncio
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "vendor"))
sys.path.insert(0, ROOT)

from core.script_enrich import (  # noqa: E402
    enrich_html,
    enrich_js,
    enrich_source,
    format_enrich,
    format_outline,
    outline_js,
)
from core.agent_tools import ScriptTool, SessionData  # noqa: E402

SAMPLE_JS = """
function login() {
  const body = { user: 'a' };
  fetch('/api/login', { method: 'POST', body: JSON.stringify(body) });
  const cipher = CryptoJS.AES.encrypt('secret', 'key123');
  return cipher.toString();
}
const aesEncrypt = (t) => CryptoJS.AES.encrypt(t, key);
axios.post('/api/v1/user', data);
"""

SAMPLE_HTML = """
<!DOCTYPE html>
<html>
<head><meta name="viewport" content="width=device-width"></head>
<body>
<form action="/login" method="post">
  <input name="username" type="text"/>
  <input name="password" type="password"/>
</form>
<script src="/static/app.js"></script>
<script>
function boot() {
  fetch('/api/boot');
  MD5('x');
}
</script>
</body>
</html>
"""


def test_outline_js() -> None:
    o = outline_js(SAMPLE_JS)
    assert o["ok"]
    assert "login" in o["functions"]
    assert any("/api/login" in p for p in o["paths"]) or any(
        s.get("arg") == "/api/login" for s in o["callSites"]
    ), o
    text = format_outline(o, "sample.js")
    assert "login" in text
    print("ok outline_js")


def test_enrich_js() -> None:
    r = enrich_js(SAMPLE_JS, "sample.js")
    assert r["ok"]
    urls = [a.get("url") for a in r["apiCalls"]]
    assert "/api/login" in urls or "/api/v1/user" in urls, r["apiCalls"]
    kinds = [c.get("kind") for c in r["cryptoHints"]]
    assert any(k in ("CryptoJS", "AES", "encrypt", "crypto") for k in kinds), r["cryptoHints"]
    summary = format_enrich(r)
    assert "apiCalls" in summary or "cryptoHints" in summary
    print("ok enrich_js")


def test_enrich_html() -> None:
    r = enrich_html(SAMPLE_HTML, "page.html")
    assert r["ok"]
    html = r["html"]
    assert "/static/app.js" in html["scripts"]["external"]
    assert html["scripts"]["inlineCount"] >= 1
    assert any(f.get("action") == "/login" for f in html["forms"]), html["forms"]
    assert any(a.get("url") == "/api/boot" for a in r["apiCalls"]), r["apiCalls"]
    print("ok enrich_html")


def test_enrich_source_dispatch() -> None:
    js = enrich_source("https://a.com/app.js", SAMPLE_JS)
    assert js["kind"] == "js"
    html = enrich_source("https://a.com/index.html", SAMPLE_HTML)
    assert html["kind"] == "html"
    print("ok enrich_source")


def test_strip_source_maps() -> None:
    from core.script_enrich import normalize_script_text, strip_source_maps

    huge = "A" * 5000
    raw = (
        "function foo(){ return 1; }\n"
        f"//# sourceMappingURL=data:application/json;base64,{huge}\n"
    )
    cleaned, removed = strip_source_maps(raw)
    assert "sourceMappingURL" not in cleaned
    assert "function foo" in cleaned
    assert removed > 1000
    assert "sourceMappingURL" not in normalize_script_text(raw)
    print("ok strip_source_maps")


async def test_script_tool() -> None:
    session = SessionData(
        scripts_provider=lambda: {
            "https://a.com/app.js": SAMPLE_JS,
            "https://a.com/index.html": SAMPLE_HTML,
            "https://cdn.com/crypto-js.min.js": "/* lib */",
        }
    )
    tool = ScriptTool(session)
    listed = await tool.execute("list")
    assert listed["total"] == 3

    en = await tool.execute("enrich", url="app.js")
    assert en.get("action") == "enrich"
    assert "CryptoJS" in en.get("summary", "") or "apiCalls" in en.get("summary", "")

    ol = await tool.execute("outline", url="https://a.com/app.js")
    assert "login" in ol.get("summary", "")

    batch = await tool.execute("enrich")
    assert batch.get("count", 0) >= 1
    assert "crypto-js" not in " ".join(batch.get("urls") or []).lower() or batch["count"] >= 1

    ast = await tool.execute("ast", url="app.js")
    assert ast.get("action") == "outline"
    print("ok ScriptTool enrich/outline/ast")


def main() -> int:
    test_outline_js()
    test_enrich_js()
    test_enrich_html()
    test_enrich_source_dispatch()
    test_strip_source_maps()
    asyncio.run(test_script_tool())
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
