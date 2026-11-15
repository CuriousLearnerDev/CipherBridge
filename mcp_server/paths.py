"""路径与环境：以仓库根为工作目录。"""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILES_DIR = ROOT / "profiles"
PLUGINS_DIR = ROOT / "plugins"

# 写操作（启停代理）需显式打开，默认只读更安全
ALLOW_PROXY_CTRL = os.environ.get("CB_MCP_ALLOW_PROXY", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}


def ensure_sys_path() -> None:
    """让 sdk / core / analyzer 可被 import。"""
    import sys

    root = str(ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
