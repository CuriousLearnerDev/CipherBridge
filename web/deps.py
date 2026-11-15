"""Web 与 GUI / MCP 共用路径与配置。"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def ensure_sys_path() -> Path:
    root = str(ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    vendor = ROOT / "vendor"
    if vendor.is_dir():
        v = str(vendor)
        if v not in sys.path:
            sys.path.insert(0, v)
    return ROOT


def allow_proxy_ctrl() -> bool:
    return os.environ.get("CB_WEB_ALLOW_PROXY", os.environ.get("CB_MCP_ALLOW_PROXY", "")).strip() in (
        "1",
        "true",
        "yes",
        "on",
    )
