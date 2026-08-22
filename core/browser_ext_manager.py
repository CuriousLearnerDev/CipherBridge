"""浏览器扩展管理：油猴(Violentmonkey) + ReRes + Hook 用户脚本生成."""

from __future__ import annotations

import io
import json
import os
import shutil
import zipfile
from typing import Any
from urllib.request import ProxyHandler, Request, build_opener

from core.paths import get_app_root

ROOT = get_app_root()
EXT_ROOT = os.path.join(ROOT, "browser_ext")
VENDOR_DIR = os.path.join(EXT_ROOT, "vendor")
SCRIPTS_DIR = os.path.join(EXT_ROOT, "scripts")
CB_HOOK_DIR = os.path.join(EXT_ROOT, "cb_hook")
PROFILE_DIR = os.path.join(ROOT, "data", "browser_profile")
PENDING_INSTALL_FLAG = os.path.join(SCRIPTS_DIR, ".pending_install")

VM_DIR = os.path.join(VENDOR_DIR, "violentmonkey")
# 原版 ReRes 为 MV2，新 Chromium 无法加载；优先用密桥内置 MV3 版
RERES_MV3_DIR = os.path.join(EXT_ROOT, "reres")
RERES_DIR = os.path.join(VENDOR_DIR, "reres")

USERSCRIPT_NAME = "cipherbridge_hooks.user.js"
USERSCRIPT_PATH = os.path.join(SCRIPTS_DIR, USERSCRIPT_NAME)

HOOK_FILES = {
    "anti_debug": os.path.join(ROOT, "hooks", "anti_debug.js"),
    "crypto_hook": os.path.join(ROOT, "hooks", "crypto_hook.js"),
}

# Violentmonkey MV3 + ReRes（GitHub）
_VM_API = "https://api.github.com/repos/violentmonkey/violentmonkey/releases/latest"
_RERES_ZIP = "https://github.com/annnhan/ReRes/archive/refs/heads/master.zip"

_DEFAULT_PROXY = "http://127.0.0.1:7897"


def _proxy_url(proxy: str | None) -> str | None:
    p = (proxy or "").strip()
    if not p:
        return None
    if not p.startswith("http"):
        p = f"http://{p}"
    return p


def _opener(proxy: str | None = None):
    handlers = []
    pu = _proxy_url(proxy)
    if pu:
        handlers.append(ProxyHandler({"http": pu, "https": pu}))
    return build_opener(*handlers) if handlers else build_opener()


def _http_get(url: str, proxy: str | None = None, timeout: int = 120) -> bytes:
    req = Request(url, headers={"User-Agent": "CipherBridge-ExtManager/1.0"})
    with _opener(proxy).open(req, timeout=timeout) as resp:
        return resp.read()


def ensure_dirs() -> None:
    for d in (EXT_ROOT, VENDOR_DIR, SCRIPTS_DIR, CB_HOOK_DIR, PROFILE_DIR):
        os.makedirs(d, exist_ok=True)


def extension_ready(path: str) -> bool:
    return os.path.isfile(os.path.join(path, "manifest.json"))


def list_extension_paths(
    *,
    load_violentmonkey: bool = True,
    load_reres: bool = True,
    load_cb_hook: bool = True,
) -> list[str]:
    """返回可 --load-extension 的绝对路径列表（仅 MV3）。"""
    ensure_dirs()
    ensure_cb_hook_extension()
    ensure_reres_mv3()
    out: list[str] = []
    if load_cb_hook and extension_ready(CB_HOOK_DIR):
        out.append(os.path.abspath(CB_HOOK_DIR))
    if load_violentmonkey and extension_ready(VM_DIR):
        out.append(os.path.abspath(VM_DIR))
    # 绝不加载 vendor/reres（GitHub 原版 MV2，新 Chromium 会报「不受支持的清单版本」）
    if load_reres and extension_ready(RERES_MV3_DIR):
        out.append(os.path.abspath(RERES_MV3_DIR))
    return out


def ensure_reres_mv3() -> str:
    """确保内置 MV3 ReRes 目录可用；停用 vendor 下的旧 MV2。"""
    ensure_dirs()
    os.makedirs(RERES_MV3_DIR, exist_ok=True)
    # 把旧 MV2 挪走，避免被误加载或残留在配置里
    disable_vendor_reres_mv2()
    return RERES_MV3_DIR


def disable_vendor_reres_mv2() -> None:
    """vendor/reres 为 Manifest V2，重命名以免 Chromium 尝试加载。"""
    if not os.path.isdir(RERES_DIR):
        return
    manifest = os.path.join(RERES_DIR, "manifest.json")
    if not os.path.isfile(manifest):
        return
    try:
        with open(manifest, encoding="utf-8") as f:
            data = json.load(f)
        if int(data.get("manifest_version") or 0) >= 3:
            return
    except Exception:
        pass
    dead = RERES_DIR + "_mv2_unsupported"
    try:
        if os.path.isdir(dead):
            shutil.rmtree(dead, ignore_errors=True)
        os.rename(RERES_DIR, dead)
    except OSError:
        # 重命名失败则写个空标记文件提示
        try:
            with open(os.path.join(RERES_DIR, "DISABLED_MV2.txt"), "w", encoding="utf-8") as f:
                f.write(
                    "此目录为 ReRes Manifest V2，新 Chromium 无法加载。\n"
                    "请使用 browser_ext/reres（密桥内置 MV3）。\n"
                )
        except OSError:
            pass


_CB_HOOK_DEFAULT_OPTS: dict[str, Any] = {
    "functionHook": True,
    "evalHook": True,
    "timerHook": True,
    "timerNuke": False,
    "consoleClear": True,
    "sizeSpoof": True,
    "rewriteResponse": False,
}


def _write_cb_hook_static_files() -> None:
    """写入 popup / bootstrap 等静态文件（保证目录完整）。"""
    # bootstrap / popup 以仓库内文件为准；若缺失则写最小占位
    bootstrap = os.path.join(CB_HOOK_DIR, "bootstrap.js")
    popup_html = os.path.join(CB_HOOK_DIR, "popup.html")
    popup_js = os.path.join(CB_HOOK_DIR, "popup.js")
    options = os.path.join(CB_HOOK_DIR, "options.json")
    if not os.path.isfile(options):
        with open(options, "w", encoding="utf-8") as f:
            json.dump(_CB_HOOK_DEFAULT_OPTS, f, ensure_ascii=False, indent=2)
    # 占位：防止用户误删后扩展挂掉
    if not os.path.isfile(bootstrap):
        with open(bootstrap, "w", encoding="utf-8") as f:
            f.write(
                "/* missing bootstrap.js — reinstall CipherBridge */\n"
                "console.warn('[CipherBridge] bootstrap.js missing');\n"
            )
    if not os.path.isfile(popup_html):
        with open(popup_html, "w", encoding="utf-8") as f:
            f.write("<!DOCTYPE html><title>CipherBridge</title><body>popup missing</body>")
    if not os.path.isfile(popup_js):
        with open(popup_js, "w", encoding="utf-8") as f:
            f.write("/* popup.js missing */\n")


def write_proxy_pref(
    *,
    mode: str = "direct",
    host: str = "127.0.0.1",
    port: int = 8083,
) -> str:
    """写入扩展启动时读取的代理偏好（popup / background 用）。"""
    ensure_cb_hook_extension()
    path = os.path.join(CB_HOOK_DIR, "proxy_pref.json")
    data = {
        "mode": mode or "direct",
        "host": (host or "127.0.0.1").strip() or "127.0.0.1",
        "port": int(port or 8083),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return path


def ensure_cb_hook_extension() -> str:
    """密桥 Hook 扩展：弹窗勾选功能 + 代理切换 + document_start 注入。"""
    ensure_dirs()
    _write_cb_hook_static_files()
    bg = os.path.join(CB_HOOK_DIR, "background.js")
    if not os.path.isfile(bg):
        with open(bg, "w", encoding="utf-8") as f:
            f.write("/* background.js missing */\n")
    pref = os.path.join(CB_HOOK_DIR, "proxy_pref.json")
    if not os.path.isfile(pref):
        with open(pref, "w", encoding="utf-8") as f:
            json.dump(
                {"mode": "direct", "host": "127.0.0.1", "port": 8083},
                f,
                ensure_ascii=False,
                indent=2,
            )
    manifest = {
        "manifest_version": 3,
        "name": "CipherBridge Hook",
        "version": "1.2.0",
        "description": "密桥：页面 Hook 注入 + 代理切换（直连/解密端/Burp）",
        "permissions": ["storage", "proxy"],
        "host_permissions": ["<all_urls>"],
        "background": {"service_worker": "background.js"},
        "action": {
            "default_title": "CipherBridge Hook",
            "default_popup": "popup.html",
        },
        "content_scripts": [
            {
                "matches": ["<all_urls>"],
                "js": ["bootstrap.js"],
                "run_at": "document_start",
                "all_frames": True,
            }
        ],
        "web_accessible_resources": [
            {
                "resources": ["inject.js", "options.json", "proxy_pref.json"],
                "matches": ["<all_urls>"],
            }
        ],
    }
    with open(os.path.join(CB_HOOK_DIR, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    inject = os.path.join(CB_HOOK_DIR, "inject.js")
    if not os.path.isfile(inject):
        with open(inject, "w", encoding="utf-8") as f:
            f.write(
                "/* CipherBridge Hook — 请在 AI 实验室点「生成」更新 */\n"
                "(function(){try{console.log('[CipherBridge] cb_hook 已加载(空脚本)');}catch(e){}})();\n"
            )
    return CB_HOOK_DIR


def write_cb_hook_options(inject_opts: dict | None) -> str:
    """把 GUI 勾选同步到扩展 options.json（弹窗无 storage 时作默认值）。"""
    ensure_cb_hook_extension()
    opts = dict(_CB_HOOK_DEFAULT_OPTS)
    if isinstance(inject_opts, dict):
        opts.update({k: bool(v) for k, v in inject_opts.items() if k in opts})
    path = os.path.join(CB_HOOK_DIR, "options.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(opts, f, ensure_ascii=False, indent=2)
    return path


def _unzip_to(data: bytes, dest: str, *, strip_single_root: bool = True) -> None:
    if os.path.isdir(dest):
        shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(dest, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = zf.namelist()
        root_prefix = ""
        if strip_single_root:
            tops = {n.split("/")[0] for n in names if n and not n.endswith("/")}
            # also dirs
            tops |= {n.split("/")[0] for n in names if "/" in n}
            if len(tops) == 1:
                root_prefix = next(iter(tops)) + "/"
        for info in zf.infolist():
            name = info.filename
            if root_prefix and name.startswith(root_prefix):
                name = name[len(root_prefix) :]
            if not name or name.endswith("/"):
                continue
            target = os.path.join(dest, name.replace("/", os.sep))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)


def _find_manifest_dir(base: str) -> str | None:
    if extension_ready(base):
        return base
    for root, _dirs, files in os.walk(base):
        if "manifest.json" in files:
            return root
    return None


def download_violentmonkey(proxy: str | None = _DEFAULT_PROXY, log=None) -> str:
    """下载 Violentmonkey MV3 到 vendor/violentmonkey."""
    ensure_dirs()
    _log = log or (lambda m: None)
    _log("正在下载油猴 Violentmonkey（GitHub）…")
    meta = json.loads(_http_get(_VM_API, proxy=proxy).decode("utf-8"))
    assets = meta.get("assets") or []
    asset = next(
        (a for a in assets if "mv3" in (a.get("name") or "").lower() and str(a.get("name")).endswith(".zip")),
        None,
    )
    if not asset:
        raise RuntimeError("未找到 Violentmonkey-mv3 zip 资源")
    url = asset["browser_download_url"]
    _log(f"  → {asset.get('name')}")
    data = _http_get(url, proxy=proxy)
    tmp = os.path.join(VENDOR_DIR, "_vm_tmp")
    _unzip_to(data, tmp, strip_single_root=True)
    found = _find_manifest_dir(tmp)
    if not found:
        raise RuntimeError("Violentmonkey zip 内无 manifest.json")
    if os.path.isdir(VM_DIR):
        shutil.rmtree(VM_DIR, ignore_errors=True)
    shutil.move(found, VM_DIR)
    shutil.rmtree(tmp, ignore_errors=True)
    # 若 move 把父目录掏空，清理
    if os.path.isdir(tmp):
        shutil.rmtree(tmp, ignore_errors=True)
    _log(f"油猴已就绪: {VM_DIR}")
    return VM_DIR


def download_reres(proxy: str | None = _DEFAULT_PROXY, log=None) -> str:
    """不再下载 GitHub MV2 ReRes；改用内置 MV3。"""
    _log = log or (lambda m: None)
    ensure_reres_mv3()
    _log(f"ReRes 使用内置 MV3（不再下载 GitHub MV2）: {RERES_MV3_DIR}")
    return RERES_MV3_DIR


def ensure_vendor_extensions(
    *,
    want_vm: bool = True,
    want_reres: bool = True,
    proxy: str | None = _DEFAULT_PROXY,
    force: bool = False,
    log=None,
) -> dict[str, Any]:
    """按需下载油猴；ReRes 只用内置 MV3。"""
    _log = log or (lambda m: None)
    ensure_dirs()
    ensure_cb_hook_extension()
    result = {"violentmonkey": False, "reres": False, "errors": []}
    if want_vm:
        if force or not extension_ready(VM_DIR):
            try:
                download_violentmonkey(proxy=proxy, log=_log)
            except Exception as e:
                result["errors"].append(f"油猴: {e}")
                _log(f"油猴下载失败: {e}")
        result["violentmonkey"] = extension_ready(VM_DIR)
    if want_reres:
        try:
            ensure_reres_mv3()
            if not extension_ready(RERES_MV3_DIR):
                result["errors"].append("ReRes MV3 目录缺少 manifest.json")
                _log("ReRes MV3 未就绪，请确认 browser_ext/reres/manifest.json 存在")
            else:
                _log(f"ReRes MV3 已就绪: {RERES_MV3_DIR}")
        except Exception as e:
            result["errors"].append(f"ReRes: {e}")
            _log(f"ReRes 准备失败: {e}")
        result["reres"] = extension_ready(RERES_MV3_DIR)
    return result


def _read_hook(path: str) -> str:
    if not os.path.isfile(path):
        return ""
    with open(path, encoding="utf-8") as f:
        return f.read()


def build_hook_bundle(
    *,
    include_anti_debug: bool = True,
    include_crypto_hook: bool = True,
    inject_opts: dict | None = None,
    extra_js: str = "",
) -> str:
    """拼出可注入的 JS 正文（无 userscript 头）。"""
    # 若扩展 bootstrap 已写入 __cbInjectOpts（弹窗勾选），勿覆盖
    parts: list[str] = [
        "/* Auto-generated by CipherBridge — do not edit by hand */",
        "(function(){",
        "'use strict';",
        "try{if(!window.__cbInjectOpts){"
        f"window.__cbInjectOpts={json.dumps(inject_opts or {}, ensure_ascii=False)};"
        "}}catch(e){}",
    ]
    if include_anti_debug:
        body = _read_hook(HOOK_FILES["anti_debug"])
        if body:
            parts.append("try{")
            parts.append(body)
            parts.append("}catch(e){try{console.warn('[CipherBridge] anti_debug',e);}catch(_){}}")
    if include_crypto_hook:
        body = _read_hook(HOOK_FILES["crypto_hook"])
        if body:
            parts.append("try{")
            parts.append(body)
            parts.append("}catch(e){try{console.warn('[CipherBridge] crypto_hook',e);}catch(_){}}")
    extra = (extra_js or "").strip()
    if extra:
        # 去掉可能的 markdown 围栏
        if extra.startswith("```"):
            lines = extra.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            extra = "\n".join(lines).strip()
        parts.append("/* --- AI 站点补丁 hook_js --- */")
        parts.append("try{")
        parts.append(extra)
        parts.append("}catch(e){try{console.warn('[CipherBridge] hook_js',e);}catch(_){}}")
    parts.append("try{console.log('[CipherBridge] Hook 用户脚本已执行');}catch(e){}")
    parts.append("})();")
    return "\n".join(parts)


def wrap_userscript(body: str, *, name: str = "CipherBridge Hooks") -> str:
    header = f"""// ==UserScript==
// @name         {name}
// @namespace    https://cipherbridge.local/
// @version      1.0.0
// @description  密桥自动生成：加解密 Hook + 反调试（document-start）
// @author       CipherBridge
// @match        *://*/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

"""
    return header + body


def export_hooks_to_userscript(
    *,
    include_anti_debug: bool = True,
    include_crypto_hook: bool = True,
    inject_opts: dict | None = None,
    extra_js: str = "",
    mark_pending_install: bool = True,
) -> dict[str, str]:
    """生成油猴用户脚本，并同步到 cb_hook 扩展（下次启动浏览器生效）。"""
    ensure_dirs()
    ensure_cb_hook_extension()
    body = build_hook_bundle(
        include_anti_debug=include_anti_debug,
        include_crypto_hook=include_crypto_hook,
        inject_opts=inject_opts,
        extra_js=extra_js,
    )
    script = wrap_userscript(body)
    with open(USERSCRIPT_PATH, "w", encoding="utf-8") as f:
        f.write(script)
    # 扩展 content_script 不需要 GM 头
    with open(os.path.join(CB_HOOK_DIR, "inject.js"), "w", encoding="utf-8") as f:
        f.write(body)
    write_cb_hook_options(inject_opts)
    if mark_pending_install:
        with open(PENDING_INSTALL_FLAG, "w", encoding="utf-8") as f:
            f.write(USERSCRIPT_PATH)
    return {
        "userscript": USERSCRIPT_PATH,
        "cb_hook_inject": os.path.join(CB_HOOK_DIR, "inject.js"),
        "cb_hook_options": os.path.join(CB_HOOK_DIR, "options.json"),
    }


def consume_pending_userscript_install() -> str | None:
    """若有待安装标记，返回 userscript 路径并清除标记。"""
    if not os.path.isfile(PENDING_INSTALL_FLAG):
        return None
    try:
        with open(PENDING_INSTALL_FLAG, encoding="utf-8") as f:
            path = f.read().strip()
    except OSError:
        path = USERSCRIPT_PATH
    try:
        os.remove(PENDING_INSTALL_FLAG)
    except OSError:
        pass
    return path if path and os.path.isfile(path) else None


def status_summary() -> dict[str, Any]:
    ensure_dirs()
    return {
        "violentmonkey": extension_ready(VM_DIR),
        "reres": extension_ready(RERES_MV3_DIR),
        "reres_mv3": extension_ready(RERES_MV3_DIR),
        "cb_hook": extension_ready(CB_HOOK_DIR),
        "userscript": os.path.isfile(USERSCRIPT_PATH),
        "userscript_path": USERSCRIPT_PATH,
        "vm_dir": VM_DIR,
        "reres_dir": RERES_MV3_DIR,
    }
