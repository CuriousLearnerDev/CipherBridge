"""从本机微信缓存提取小程序名称与头像."""

from __future__ import annotations

import json
import os
import re
from glob import glob

from core.wxapkg.decrypt import decrypt_wxapkg, is_encrypted, looks_like_wxapkg
from core.wxapkg.unpack import parse_file_table


_APPID_RE = re.compile(r"^wx[0-9a-zA-Z]{16}$")


def find_applet_icon(appid: str, app_dir: str) -> str:
    """在 packages 同级的 icon/ 目录查找 {appid}_*.png."""
    if not appid:
        return ""
    # .../applet/packages/wxXXXX -> .../applet/icon
    packages_root = os.path.dirname(os.path.abspath(app_dir))
    applet_root = os.path.dirname(packages_root)
    icon_dir = os.path.join(applet_root, "icon")
    if not os.path.isdir(icon_dir):
        # 再往上兜底搜一层
        icon_dir = os.path.join(os.path.dirname(applet_root), "icon")
    if not os.path.isdir(icon_dir):
        return ""
    matches = sorted(glob(os.path.join(icon_dir, f"{appid}_*.png")))
    matches += sorted(glob(os.path.join(icon_dir, f"{appid}_*.jpg")))
    matches += sorted(glob(os.path.join(icon_dir, f"{appid}.png")))
    return matches[0] if matches else ""


def _pick_main_wxapkg(app_dir: str) -> str:
    preferred = []
    others = []
    for dirpath, _dirs, files in os.walk(app_dir):
        for name in files:
            if not name.lower().endswith(".wxapkg"):
                continue
            path = os.path.join(dirpath, name)
            upper = name.upper()
            if upper in ("__APP__.WXAPKG", "APP.WXAPKG"):
                preferred.append(path)
            elif "PLUGIN" in upper:
                continue
            else:
                others.append(path)
    if preferred:
        # 取最新修改的主包
        preferred.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return preferred[0]
    if others:
        others.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return others[0]
    return ""


def _title_from_config_bytes(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8", errors="ignore").strip()
        if not text:
            return ""
        data = json.loads(text)
    except Exception:
        return ""
    if not isinstance(data, dict):
        return ""

    for key in ("accountInfo", "appLaunchInfo"):
        info = data.get(key)
        if isinstance(info, dict):
            for k in ("nickname", "appName", "userName", "nickName"):
                val = info.get(k)
                if val:
                    return str(val).strip()

    skip = {"", "loading", "null", "undefined", "index", "首页"}

    # 入口页标题
    entry = str(data.get("entryPagePath") or "").replace(".html", "")
    page_map = data.get("page")
    if isinstance(page_map, dict) and entry:
        # entry 可能带 .html
        for key, meta in page_map.items():
            k = str(key).replace(".html", "")
            if k != entry and not str(key).startswith(entry):
                continue
            if isinstance(meta, dict):
                win = meta.get("window") if isinstance(meta.get("window"), dict) else meta
                title = str((win or {}).get("navigationBarTitleText") or "").strip()
                if title and title.lower() not in skip:
                    return title

    # tabBar 文字（常能代表小程序名）
    tab = data.get("tabBar")
    if isinstance(tab, dict):
        items = tab.get("list")
        if isinstance(items, list) and items:
            first = items[0]
            if isinstance(first, dict) and first.get("text"):
                return str(first["text"]).strip()

    # 全局 window
    win = data.get("window")
    if isinstance(win, dict) and win.get("navigationBarTitleText"):
        title = str(win["navigationBarTitleText"]).strip()
        if title.lower() not in skip:
            return title

    # 任意页面里第一个像样的标题
    if isinstance(page_map, dict):
        for meta in page_map.values():
            if not isinstance(meta, dict):
                continue
            win = meta.get("window") if isinstance(meta.get("window"), dict) else meta
            title = str((win or {}).get("navigationBarTitleText") or "").strip()
            if title and title.lower() not in skip:
                return title
    return ""


def peek_title_from_wxapkg(app_dir: str, appid: str) -> str:
    """解密主包并只读取 app-config.json / app.json 取名称（不解完整目录）."""
    pkg = _pick_main_wxapkg(app_dir)
    if not pkg:
        return ""
    try:
        with open(pkg, "rb") as f:
            raw = f.read()
        if not looks_like_wxapkg(raw):
            return ""
        if is_encrypted(raw):
            if not appid:
                return ""
            plain = decrypt_wxapkg(raw, appid)
        else:
            plain = raw
        entries = parse_file_table(plain)
    except Exception:
        return ""

    prefer_names = (
        "/app-config.json",
        "app-config.json",
        "/app.json",
        "app.json",
    )
    by_name = {e.name.lstrip("/").replace("\\", "/"): e for e in entries}
    # also keep original keys
    for e in entries:
        by_name[e.name] = e

    for name in prefer_names:
        ent = by_name.get(name) or by_name.get(name.lstrip("/"))
        if not ent:
            continue
        chunk = plain[ent.offset : ent.offset + ent.size]
        title = _title_from_config_bytes(chunk)
        if title:
            return title
    # 兜底：任意 config json
    for e in entries:
        n = e.name.lower()
        if n.endswith("app-config.json") or n.endswith("/app.json"):
            title = _title_from_config_bytes(plain[e.offset : e.offset + e.size])
            if title:
                return title
    return ""


def resolve_miniprogram_meta(appid: str, app_dir: str, *, peek_pkg: bool = True) -> tuple[str, str]:
    """返回 (title, icon_path)."""
    from core.wxapkg.pipeline import guess_miniprogram_title

    title = guess_miniprogram_title(appid)
    icon = find_applet_icon(appid, app_dir)
    if not title and peek_pkg:
        title = peek_title_from_wxapkg(app_dir, appid)
    return title, icon
