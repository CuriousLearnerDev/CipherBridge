"""抓包域名/关键字过滤 — 系统代理仍会接管流量，但只记录匹配项."""

from __future__ import annotations

import fnmatch
import os
from urllib.parse import urlparse

# 开启「屏蔽系统噪音」时排除的子串（小写）；不碰微信业务域名以免误杀
DEFAULT_NOISE_KEYWORDS = (
    "windowsupdate",
    "microsoft.com",
    "office.com",
    "live.com",
    "msftconnecttest",
    "bing.com",
    "google.com",
    "gstatic.com",
    "googleapis.com",
    "gvt1.com",
    "doubleclick",
    "googlesyndication",
    "apple.com",
    "icloud.com",
    "mzstatic.com",
    "cursor.sh",
    "cursor.com",
    "github.com",
    "githubusercontent.com",
    "npmjs.org",
    "pypi.org",
    "python.org",
    "vscode-",
    "update.code.visualstudio",
)


def parse_filter_patterns(text: str | None) -> list[str]:
    raw = (text or "").replace("\n", ",").replace(";", ",")
    return [p.strip() for p in raw.split(",") if p.strip()]


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def url_matches_allow(url: str, patterns: list[str]) -> bool:
    """留空 patterns = 全部通过；否则 host/url 命中任一模式即可."""
    if not patterns:
        return True
    u = (url or "").lower()
    host = _host_of(u) or _host_of("http://" + u)
    for p in patterns:
        pl = p.lower().strip()
        if not pl:
            continue
        if pl.startswith("*."):
            suffix = pl[1:]  # .example.com
            bare = pl[2:]
            if host == bare or host.endswith(suffix) or bare in u:
                return True
            continue
        if "*" in pl:
            if fnmatch.fnmatch(host, pl) or fnmatch.fnmatch(u, pl):
                return True
            continue
        if pl in host or pl in u:
            return True
    return False


def url_is_noise(url: str, noise_keywords: tuple[str, ...] | list[str] = DEFAULT_NOISE_KEYWORDS) -> bool:
    u = (url or "").lower()
    host = _host_of(u)
    blob = f"{host} {u}"
    for kw in noise_keywords:
        if kw and kw.lower() in blob:
            return True
    return False


def should_capture_url(
    url: str,
    *,
    allow_patterns: list[str] | None = None,
    block_noise: bool = False,
) -> bool:
    if block_noise and url_is_noise(url):
        return False
    return url_matches_allow(url, allow_patterns or [])


def load_allow_from_env(env_key: str = "CB_CAPTURE_HOST_FILTER") -> list[str]:
    return parse_filter_patterns(os.environ.get(env_key, ""))


def load_block_noise_from_env(env_key: str = "CB_CAPTURE_BLOCK_NOISE") -> bool:
    v = (os.environ.get(env_key) or "").strip().lower()
    return v in ("1", "true", "yes", "on")
