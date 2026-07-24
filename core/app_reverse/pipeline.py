"""APK 反编译 pipeline — apktool decode + 加解密代码筛选."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import zipfile
from dataclasses import dataclass, field

from core.app_reverse.scanner import CodeHit, collect_crypto_code, scripts_as_dict
from core.app_reverse.tools import resolve_apktool_jar, resolve_java
from core.paths import get_app_root


class ApkReverseError(RuntimeError):
    pass


@dataclass
class ApkDecodeResult:
    apk_path: str
    out_dir: str
    package_name: str = ""
    app_label: str = ""
    messages: list[str] = field(default_factory=list)
    crypto_hits: list[CodeHit] = field(default_factory=list)

    def scripts_for_ai(self) -> dict[str, str]:
        return scripts_as_dict(self.crypto_hits)


def default_apk_workspace() -> str:
    path = os.path.join(get_app_root(), "workspace", "apk_decode")
    os.makedirs(path, exist_ok=True)
    return path


def _safe_name(name: str) -> str:
    name = re.sub(r"[^\w.\-]+", "_", name.strip()) or "app"
    return name[:80]


def _read_apktool_yml(out_dir: str) -> tuple[str, str]:
    yml = os.path.join(out_dir, "apktool.yml")
    pkg = ""
    label = ""
    if not os.path.isfile(yml):
        return pkg, label
    try:
        with open(yml, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read(8000)
    except OSError:
        return pkg, label
    m = re.search(r"apkFileName:\s*['\"]?([^'\"\n]+)", text)
    if m:
        label = os.path.splitext(os.path.basename(m.group(1).strip()))[0]
    # package 常在 AndroidManifest
    man = os.path.join(out_dir, "AndroidManifest.xml")
    if os.path.isfile(man):
        try:
            with open(man, "r", encoding="utf-8", errors="ignore") as f:
                mt = f.read(200_000)
            m2 = re.search(r'package="([^"]+)"', mt)
            if m2:
                pkg = m2.group(1)
        except OSError:
            pass
    return pkg, label


def _decode_with_apktool(apk_path: str, out_dir: str, log) -> None:
    java = resolve_java()
    jar = resolve_apktool_jar()
    if not java or not jar:
        raise ApkReverseError(
            "未找到 Java 或 apktool。请安装 JDK，或将统领 storage 下的 "
            "jadx-gui/jre 与 apktool 放到可探测路径（TONGLING_STORAGE）。"
        )
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(os.path.dirname(out_dir) or ".", exist_ok=True)
    cmd = [java, "-jar", jar, "d", "-f", "--only-main-classes", "-o", out_dir, apk_path]
    log(f"执行: {' '.join(cmd)}")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
        )
    except subprocess.TimeoutExpired as e:
        raise ApkReverseError("apktool 超时（>10 分钟）") from e
    except OSError as e:
        raise ApkReverseError(f"无法启动 apktool: {e}") from e
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()[-800:]
        raise ApkReverseError(f"apktool 失败 (code={proc.returncode}): {err}")
    if proc.stdout:
        for line in proc.stdout.splitlines()[-8:]:
            log(line)


def _fallback_unzip_strings(apk_path: str, out_dir: str, log) -> None:
    """无 apktool 时：解压 APK，从 dex 抽可打印串写入伪 smali 文本供扫描."""
    log("回退：仅解压 APK 并抽取 dex 字符串（精度低于 apktool）")
    os.makedirs(out_dir, exist_ok=True)
    with zipfile.ZipFile(apk_path, "r") as zf:
        zf.extractall(out_dir)
    strings_dir = os.path.join(out_dir, "_dex_strings")
    os.makedirs(strings_dir, exist_ok=True)
    for name in os.listdir(out_dir):
        if not name.lower().endswith(".dex"):
            continue
        dex_path = os.path.join(out_dir, name)
        try:
            raw = open(dex_path, "rb").read()
        except OSError:
            continue
        # 抽较长 ASCII/UTF-8 串
        parts = re.findall(rb"[\x20-\x7e]{6,}", raw)
        lines = []
        for p in parts:
            try:
                s = p.decode("ascii")
            except Exception:
                continue
            low = s.lower()
            if any(k in low for k in ("aes", "cipher", "encrypt", "decrypt", "rsa", "secret", "hmac", "md5", "sha")):
                lines.append(s)
        out_txt = os.path.join(strings_dir, name + ".strings.txt")
        with open(out_txt, "w", encoding="utf-8") as f:
            f.write("\n".join(lines[:5000]))
        log(f"已抽取 {name} 可疑字符串 {min(len(lines), 5000)} 条")


def decode_apk(
    apk_path: str,
    *,
    out_dir: str | None = None,
    on_log=None,
) -> ApkDecodeResult:
    def log(msg: str):
        if on_log:
            on_log(msg)

    apk_path = os.path.abspath(apk_path)
    if not os.path.isfile(apk_path):
        raise ApkReverseError(f"文件不存在: {apk_path}")
    if not apk_path.lower().endswith(".apk"):
        raise ApkReverseError("请选择 .apk 文件")

    base = os.path.splitext(os.path.basename(apk_path))[0]
    if not out_dir:
        out_dir = os.path.join(default_apk_workspace(), _safe_name(base))
    out_dir = os.path.abspath(out_dir)

    messages: list[str] = []
    messages.append(f"APK: {apk_path}")
    messages.append(f"输出: {out_dir}")

    java = resolve_java()
    jar = resolve_apktool_jar()
    if java and jar:
        _decode_with_apktool(apk_path, out_dir, lambda m: (log(m), messages.append(m)))
    else:
        messages.append("未找到 apktool/Java，使用解压回退")
        if os.path.isdir(out_dir):
            shutil.rmtree(out_dir, ignore_errors=True)
        _fallback_unzip_strings(apk_path, out_dir, lambda m: (log(m), messages.append(m)))

    pkg, label = _read_apktool_yml(out_dir)
    log("扫描加解密相关代码…")
    hits = collect_crypto_code(out_dir)
    messages.append(f"命中可疑文件 {len(hits)} 个")
    for h in hits[:8]:
        messages.append(f"  [{h.score}] {h.relpath}")

    return ApkDecodeResult(
        apk_path=apk_path,
        out_dir=out_dir,
        package_name=pkg,
        app_label=label or base,
        messages=messages,
        crypto_hits=hits,
    )
