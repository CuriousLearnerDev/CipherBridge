"""密桥 CipherBridge — Web 界面入口（与 gui.py 并行）。

  python web_app.py
  python web_app.py --port 8787
  CB_WEB_ALLOW_PROXY=1 python web_app.py   # 允许网页启停代理

桌面版:
  python gui.py
"""

from web.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
