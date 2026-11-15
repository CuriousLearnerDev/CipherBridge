"""python -m web"""

from __future__ import annotations

import argparse
import os
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="密桥 CipherBridge Web UI")
    parser.add_argument("--host", default="127.0.0.1", help="绑定地址（默认本机）")
    parser.add_argument("--port", type=int, default=8787, help="端口，默认 8787")
    parser.add_argument("--reload", action="store_true", help="开发热重载")
    args = parser.parse_args(argv)

    # 保证仓库根在 path
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)

    import uvicorn

    print(f"密桥 Web: http://{args.host}:{args.port}")
    print("桌面 GUI 仍可用: python gui.py")
    uvicorn.run(
        "web.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        factory=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
