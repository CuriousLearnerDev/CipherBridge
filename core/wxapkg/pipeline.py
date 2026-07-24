"""小程序反编译流水线：解密 → 解包 → 可选拆分 JS → 扫描加解密相关文件."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from core.paths import get_app_root
from core.wxapkg.decrypt import (
    decrypt_wxapkg,
    guess_appid_from_path,
    is_encrypted,
    looks_like_wxapkg,
    WxapkgDecryptError,
)
from core.wxapkg.scanner import ScriptHit, collect_crypto_scripts, scripts_as_dict
from core.wxapkg.split_js import split_all_app_services
from core.wxapkg.unpack import UnpackResult, unpack_bytes, WxapkgUnpackError


@dataclass
class DecompileResult:
    appid: str
    source_files: list[str]
    out_dir: str
    decrypted: bool
    unpack: UnpackResult | None = None
    split_files: list[str] = field(default_factory=list)
    crypto_hits: list[ScriptHit] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)

    def scripts_for_ai(self, max_chars: int = 120_000) -> dict[str, str]:
        return scripts_as_dict(self.crypto_hits, max_chars=max_chars)


def default_workspace() -> str:
    return os.path.join(get_app_root(), "workspace", "miniprogram")


def default_package_roots() -> list[str]:
    """本机常见小程序包目录（存在才返回）。

    对齐新版微信 / wedecode 扫描习惯：
    - xwechat/radium/users/<账号>/applet/packages   （微信 4.x 主路径）
    - xwechat/radium/Applet/packages                （旧路径）
    - Documents/WeChat Files/Applet                 （更旧 PC 微信）
    """
    home = os.path.expanduser("~")
    roots: list[str] = []
    seen: set[str] = set()

    def _add(path: str) -> None:
        path = os.path.normpath(path)
        if path in seen or not os.path.isdir(path):
            return
        seen.add(path)
        roots.append(path)

    # 新版微信 4.x（xwechat）
    xwechat_radium = os.path.join(home, "AppData", "Roaming", "Tencent", "xwechat", "radium")
    _add(os.path.join(xwechat_radium, "Applet", "packages"))
    users_dir = os.path.join(xwechat_radium, "users")
    if os.path.isdir(users_dir):
        try:
            for uid in os.listdir(users_dir):
                _add(os.path.join(users_dir, uid, "applet", "packages"))
        except OSError:
            pass

    # 旧版 WeChat 目录下若有类似结构也扫
    wechat_radium = os.path.join(home, "AppData", "Roaming", "Tencent", "WeChat", "radium")
    _add(os.path.join(wechat_radium, "Applet", "packages"))
    wechat_users = os.path.join(wechat_radium, "users")
    if os.path.isdir(wechat_users):
        try:
            for uid in os.listdir(wechat_users):
                _add(os.path.join(wechat_users, uid, "applet", "packages"))
        except OSError:
            pass

    # Documents 旧缓存
    _add(os.path.join(home, "Documents", "WeChat Files", "Applet"))
    docs_wx = os.path.join(home, "Documents", "WeChat Files")
    if os.path.isdir(docs_wx):
        try:
            for name in os.listdir(docs_wx):
                if name.startswith("wxid_") or name.startswith("wx"):
                    _add(os.path.join(docs_wx, name, "Applet"))
        except OSError:
            pass
    _add(os.path.join(home, "Documents", "xwechat_files"))

    # macOS 新版路径（跨平台兼容）
    mac_users = os.path.join(
        home, "Library", "Containers", "com.tencent.xinWeChat",
        "Data", "Documents", "app_data", "radium", "users",
    )
    if os.path.isdir(mac_users):
        try:
            for uid in os.listdir(mac_users):
                _add(os.path.join(mac_users, uid, "applet", "packages"))
        except OSError:
            pass
    _add(os.path.join(
        home, "Library", "Containers", "com.tencent.xinWeChat",
        "Data", "Documents", "app_data", "radium", "Applet", "packages",
    ))

    return roots


_APPID_RE = re.compile(r"^wx[0-9a-zA-Z]{16}$")


@dataclass
class MiniprogramInfo:
    """本机扫描到的可反编译小程序."""

    appid: str
    path: str
    pkg_count: int
    title: str = ""
    icon_path: str = ""

    @property
    def display_name(self) -> str:
        if self.title and self.title != self.appid:
            return self.title
        return self.appid


def _count_wxapkg(dir_path: str, max_depth: int = 3) -> int:
    count = 0
    root_depth = dir_path.rstrip(os.sep).count(os.sep)
    for dirpath, _dirs, files in os.walk(dir_path):
        if dirpath.count(os.sep) - root_depth > max_depth:
            continue
        for name in files:
            if name.lower().endswith(".wxapkg"):
                count += 1
    return count


def guess_miniprogram_title(appid: str) -> str:
    """若已反编译过，尝试从 app-config.json 读名称."""
    cfg = os.path.join(default_workspace(), _safe_appid_dir(appid), "app-config.json")
    if not os.path.isfile(cfg):
        return ""
    try:
        import json
        with open(cfg, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        if isinstance(data, dict):
            for key in ("window",):
                win = data.get(key)
                if isinstance(win, dict) and win.get("navigationBarTitleText"):
                    return str(win["navigationBarTitleText"]).strip()
            for key in ("accountInfo", "appLaunchInfo"):
                info = data.get(key)
                if isinstance(info, dict):
                    for k in ("nickname", "appName", "userName"):
                        if info.get(k):
                            return str(info[k]).strip()
    except Exception:
        pass
    return ""


def discover_miniprograms(extra_roots: list[str] | None = None) -> list[MiniprogramInfo]:
    """扫描本机微信包目录，列出含 .wxapkg 的小程序（按 AppID 去重）."""
    from core.wxapkg.meta import resolve_miniprogram_meta

    roots = list(default_package_roots())
    if extra_roots:
        for r in extra_roots:
            r = os.path.abspath(r)
            if os.path.isdir(r) and r not in roots:
                roots.append(r)

    found: dict[str, MiniprogramInfo] = {}
    for root in roots:
        try:
            names = os.listdir(root)
        except OSError:
            continue
        for name in names:
            if not _APPID_RE.match(name):
                continue
            app_dir = os.path.join(root, name)
            if not os.path.isdir(app_dir):
                continue
            pkg_count = _count_wxapkg(app_dir)
            if pkg_count <= 0:
                continue
            prev = found.get(name)
            if prev is None or pkg_count > prev.pkg_count:
                title, icon = resolve_miniprogram_meta(name, app_dir, peek_pkg=True)
                found[name] = MiniprogramInfo(
                    appid=name,
                    path=app_dir,
                    pkg_count=pkg_count,
                    title=title,
                    icon_path=icon,
                )
    return sorted(found.values(), key=lambda x: (x.title or x.appid).lower())


def list_wxapkg_files(path: str) -> list[str]:
    path = os.path.abspath(path)
    if os.path.isfile(path) and path.lower().endswith(".wxapkg"):
        return [path]
    found: list[str] = []
    if os.path.isdir(path):
        for dirpath, _dirs, files in os.walk(path):
            for name in files:
                if name.lower().endswith(".wxapkg"):
                    found.append(os.path.join(dirpath, name))
    return sorted(found)


def _safe_appid_dir(appid: str) -> str:
    name = re.sub(r"[^\w\-]+", "_", (appid or "unknown").strip()) or "unknown"
    return name[:64]


def decompile_wxapkg(
    path: str,
    *,
    appid: str = "",
    out_dir: str | None = None,
    split_modules: bool = True,
    scan_crypto: bool = True,
) -> DecompileResult:
    """
    反编译单个文件或目录下全部 .wxapkg。
    输出目录默认: workspace/miniprogram/{appid}/
    """
    path = os.path.abspath(path)
    files = list_wxapkg_files(path)
    if not files:
        raise FileNotFoundError(f"未找到 .wxapkg: {path}")

    aid = (appid or guess_appid_from_path(files[0]) or guess_appid_from_path(path)).strip()
    workspace = out_dir or os.path.join(default_workspace(), _safe_appid_dir(aid or "pkg"))
    os.makedirs(workspace, exist_ok=True)

    messages: list[str] = []
    any_decrypted = False
    last_unpack: UnpackResult | None = None
    used_appid = aid

    for i, pkg in enumerate(files):
        with open(pkg, "rb") as f:
            raw = f.read()
        if not looks_like_wxapkg(raw):
            messages.append(f"跳过（不像 wxapkg）: {pkg}")
            continue

        need_id = is_encrypted(raw)
        pkg_appid = aid or guess_appid_from_path(pkg)
        if need_id and not pkg_appid:
            raise WxapkgDecryptError(
                f"加密包需要 AppID，无法从路径推断: {pkg}\n"
                "请填写小程序 AppID（通常是上级文件夹名，形如 wx........）"
            )
        if pkg_appid:
            used_appid = pkg_appid

        try:
            plain = decrypt_wxapkg(raw, pkg_appid)
        except WxapkgDecryptError as e:
            raise WxapkgDecryptError(f"{pkg}: {e}") from e

        if need_id:
            any_decrypted = True
            messages.append(f"已解密: {os.path.basename(pkg)} (AppID={pkg_appid})")
        else:
            messages.append(f"明文包: {os.path.basename(pkg)}")

        # 多包：主包 __APP__ 解到根，分包解到子目录
        base = os.path.splitext(os.path.basename(pkg))[0]
        if len(files) == 1 or base.upper() in ("__APP__", "APP"):
            target = workspace
        else:
            target = os.path.join(workspace, base)
        os.makedirs(target, exist_ok=True)
        try:
            last_unpack = unpack_bytes(plain, target)
        except WxapkgUnpackError as e:
            raise WxapkgUnpackError(f"{pkg}: {e}") from e
        messages.append(f"解包 {last_unpack.file_count} 个文件 → {target}")

    split_files: list[str] = []
    if split_modules:
        split_files = split_all_app_services(workspace)
        if split_files:
            messages.append(f"已从 app-service.js 拆出 {len(split_files)} 个模块")

    hits: list[ScriptHit] = []
    if scan_crypto:
        hits = collect_crypto_scripts(workspace)
        messages.append(f"疑似加解密相关文件: {len(hits)} 个")

    return DecompileResult(
        appid=used_appid,
        source_files=files,
        out_dir=workspace,
        decrypted=any_decrypted,
        unpack=last_unpack,
        split_files=split_files,
        crypto_hits=hits,
        messages=messages,
    )


# 兼容旧调用名
decompile = decompile_wxapkg
