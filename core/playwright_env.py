"""Playwright 浏览器 — 绿色版内置 Chromium 路径."""

from __future__ import annotations

import os

from core.paths import get_app_root


def bundled_browsers_dir() -> str:
    return os.path.join(get_app_root(), "ms-playwright")


def setup_playwright_browsers_path() -> bool:
    """若存在内置 ms-playwright，设置 PLAYWRIGHT_BROWSERS_PATH."""
    path = bundled_browsers_dir()
    if os.path.isdir(path):
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = path
        return True
    return False


def has_bundled_chromium() -> bool:
    """是否已打包 Chromium（存在 chromium-* 目录）."""
    root = bundled_browsers_dir()
    if not os.path.isdir(root):
        return False
    try:
        for name in os.listdir(root):
            if name.startswith("chromium-"):
                return True
    except OSError:
        pass
    return False


def apply_launch_channel(opts: dict, channel: str | None) -> dict:
    """写入 Playwright channel；chromium 不传 channel（用内置/下载的）。"""
    from core.ai_config import normalize_browser_channel

    out = dict(opts)
    ch = normalize_browser_channel(channel)
    if ch in ("chrome", "msedge"):
        out["channel"] = ch
    else:
        out.pop("channel", None)
    return out


def channel_label(channel: str | None) -> str:
    from core.ai_config import normalize_browser_channel

    ch = normalize_browser_channel(channel)
    if ch == "chrome":
        return "本机 Chrome"
    if ch == "msedge":
        return "本机 Edge"
    return "Chromium（内置）"


def profile_dir_for_channel(channel: str | None) -> str:
    """不同浏览器通道使用不同持久目录，避免 Profile 互踩。"""
    from core.ai_config import normalize_browser_channel
    from core.browser_ext_manager import PROFILE_DIR

    ch = normalize_browser_channel(channel)
    if ch == "chrome":
        return os.path.join(get_app_root(), "data", "browser_profile_chrome")
    if ch == "msedge":
        return os.path.join(get_app_root(), "data", "browser_profile_msedge")
    return PROFILE_DIR


def real_browser_channel_attempts(preferred: str | None = None) -> list[str]:
    """呜呼思路：优先本机 Edge/Chrome，最后才内置 Chromium。"""
    from core.ai_config import normalize_browser_channel

    pref = normalize_browser_channel(preferred)
    order: list[str] = []
    for ch in (pref, "msedge", "chrome", "chromium"):
        if ch not in order:
            order.append(ch)
    # 真实浏览器模式下跳过内置（易被挑战页识别）；仅当前面都失败时才用
    return order
