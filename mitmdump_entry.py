"""mitmdump 入口 — 供打包为独立 mitmdump.exe，与 GUI 绿色版同目录."""

from mitmproxy.tools.main import mitmdump

if __name__ == "__main__":
    mitmdump()
