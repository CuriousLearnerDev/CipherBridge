"""应用根目录 — 开发 / PyInstaller 打包统一解析."""

from __future__ import annotations

import os
import sys


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def get_app_root() -> str:
    """项目根目录（可读写）。打包后为 exe 所在目录."""
    if is_frozen():
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_bundle_root() -> str:
    """PyInstaller 解压目录；开发模式与 get_app_root 相同."""
    if is_frozen() and hasattr(sys, "_MEIPASS"):
        return sys._MEIPASS  # type: ignore[attr-defined]
    return get_app_root()
