"""小程序 / APK 反编译 — Web 侧封装（无 Qt）。"""

from __future__ import annotations

import os
from typing import Any

from web.deps import ensure_sys_path

ensure_sys_path()


def list_miniprograms(extra_roots: list[str] | None = None) -> dict[str, Any]:
    from core.wxapkg import discover_miniprograms, default_package_roots

    apps = discover_miniprograms(extra_roots)
    roots = list(default_package_roots())
    if extra_roots:
        for r in extra_roots:
            r = os.path.abspath(r)
            if os.path.isdir(r) and r not in roots:
                roots.append(r)
    return {
        "ok": True,
        "count": len(apps),
        "roots": roots,
        "apps": [
            {
                "appid": a.appid,
                "path": a.path,
                "pkg_count": a.pkg_count,
                "title": a.title or "",
                "display_name": a.display_name,
                "icon_path": a.icon_path or "",
            }
            for a in apps
        ],
    }


def decompile_miniprogram(*, path: str, appid: str = "") -> dict[str, Any]:
    from core.wxapkg import decompile_wxapkg, WxapkgDecryptError, WxapkgUnpackError

    path = os.path.abspath((path or "").strip())
    if not path or not os.path.exists(path):
        return {"ok": False, "error": f"路径不存在: {path}"}
    try:
        result = decompile_wxapkg(
            path,
            appid=appid or "",
            out_dir=None,
            split_modules=True,
            scan_crypto=True,
        )
    except (WxapkgDecryptError, WxapkgUnpackError, FileNotFoundError, OSError) as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"未预期错误: {e}"}

    scripts = result.scripts_for_ai()
    hits = [
        {"score": getattr(h, "score", 0), "relpath": getattr(h, "relpath", ""), "path": getattr(h, "path", "")}
        for h in (result.crypto_hits or [])
    ]
    return {
        "ok": True,
        "appid": result.appid,
        "out_dir": result.out_dir,
        "decrypted": result.decrypted,
        "messages": list(result.messages or []),
        "hits": hits,
        "scripts": scripts,
        "script_count": len(scripts),
    }


def app_tools_status() -> dict[str, Any]:
    from core.app_reverse import (
        ensure_tools_dirs,
        missing_required_tools,
        tools_setup_message,
        tools_status,
        default_apk_workspace,
    )

    ensure_tools_dirs()
    st = tools_status()
    return {
        "ok": True,
        "tools": st,
        "missing": missing_required_tools(),
        "message": tools_setup_message(),
        "workspace": default_apk_workspace(),
    }


def decode_apk_file(apk_path: str) -> dict[str, Any]:
    from core.app_reverse import (
        ApkReverseError,
        decode_apk,
        ensure_tools_dirs,
        missing_required_tools,
        resolve_apktool_jar,
        resolve_jadx_gui,
        resolve_java,
    )

    apk_path = os.path.abspath((apk_path or "").strip())
    if not apk_path or not os.path.isfile(apk_path):
        return {"ok": False, "error": f"APK 不存在: {apk_path}"}

    ensure_tools_dirs()
    resolve_java.cache_clear()
    resolve_apktool_jar.cache_clear()
    resolve_jadx_gui.cache_clear()
    miss = missing_required_tools()
    if miss:
        return {
            "ok": False,
            "error": f"缺少工具: {', '.join(miss)}",
            "missing": miss,
            "tools": app_tools_status(),
        }

    try:
        result = decode_apk(apk_path)
    except ApkReverseError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"未预期错误: {e}"}

    scripts = result.scripts_for_ai()
    hits = [
        {
            "score": getattr(h, "score", 0),
            "relpath": getattr(h, "relpath", ""),
            "path": getattr(h, "path", ""),
        }
        for h in (result.crypto_hits or [])
    ]
    return {
        "ok": True,
        "apk": result.apk_path,
        "out_dir": result.out_dir,
        "package": result.package_name,
        "label": result.app_label,
        "messages": list(result.messages or []),
        "hits": hits,
        "scripts": scripts,
        "script_count": len(scripts),
    }


def read_hit_preview(path: str, limit: int = 80_000) -> dict[str, Any]:
    path = os.path.abspath((path or "").strip())
    if not path or not os.path.isfile(path):
        return {"ok": False, "error": "文件不存在"}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read(limit)
    except OSError as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True, "path": path, "code": text, "truncated": len(text) >= limit}
