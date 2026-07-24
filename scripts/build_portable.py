#!/usr/bin/env python3
"""打包密桥 CipherBridge 绿色版（Windows）.

输出目录默认: D:\\桌面\\代码\\加解密框架打包版
双击 密桥.exe 即可运行，无需安装 Python。

用法:
    python scripts/build_portable.py
    python scripts/build_portable.py --out "D:\\其它路径"
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = Path(r"D:\桌面\代码\加解密框架打包版")

# mitmdump 子进程需从磁盘加载（plugin.py / main.py 模式）
RUNTIME_DIRS = ("sdk", "core", "extensions", "hooks", "img", "config", "profiles", "plugins", "analyzer")
RUNTIME_FILES = (
    "main.py", "codegen.py", "algorithms.py", "body_parser.py", "config.yaml",
    "encoding_utils.py", "forwarder.py", "handler.py", "signers.py", "sm_crypto.py",
    "mitmdump_entry.py", "plugins/plugin.py",
)

EXCLUDE_COPY = {
    "__pycache__", ".git", ".idea", ".venv", "venv",
    "config/ai.yaml",  # 本地密钥，不带入绿色版
}


def _ignore_copy(dir_path: str, names: list[str]) -> set[str]:
    ignored = set()
    for n in names:
        if n in ("__pycache__", ".git") or n.endswith((".pyc", ".pyo")):
            ignored.add(n)
    return ignored


def _write_spec(build_dir: Path) -> Path:
    spec = build_dir / "cipherbridge.spec"
    proj = str(PROJECT).replace("\\", "/")
    content = f'''# -*- mode: python ; coding: utf-8 -*-
import os
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None
proj = r"{PROJECT}"

hidden_gui = (
    collect_submodules("core")
    + collect_submodules("sdk")
    + collect_submodules("analyzer")
    + collect_submodules("playwright")
    + ["PyQt6.QtSvg", "yaml", "Crypto", "Crypto.Cipher", "requests"]
)
hidden_mitm = collect_submodules("mitmproxy") + ["mitmproxy.tools.main"]

qt_excludes = ["PyQt5", "PySide2", "PySide6", "tkinter"]

a_gui = Analysis(
    [os.path.join(proj, "gui.py")],
    pathex=[proj],
    binaries=[],
    datas=[],
    hiddenimports=hidden_gui,
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=qt_excludes,
    noarchive=False,
)

a_mitm = Analysis(
    [os.path.join(proj, "mitmdump_entry.py")],
    pathex=[proj],
    binaries=[],
    datas=[],
    hiddenimports=hidden_mitm,
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=qt_excludes + ["PyQt6"],
    noarchive=False,
)

MERGE((a_gui, "gui", "gui"), (a_mitm, "mitm", "mitm"))

pyz_gui = PYZ(a_gui.pure)
pyz_mitm = PYZ(a_mitm.pure)

exe_gui = EXE(
    pyz_gui,
    a_gui.scripts,
    [],
    exclude_binaries=True,
    name="密桥",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon=None,
)

exe_mitm = EXE(
    pyz_mitm,
    a_mitm.scripts,
    [],
    exclude_binaries=True,
    name="mitmdump",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)

coll = COLLECT(
    exe_gui,
    exe_mitm,
    a_gui.binaries,
    a_gui.zipfiles,
    a_gui.datas,
    a_mitm.binaries,
    a_mitm.zipfiles,
    a_mitm.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="CipherBridge",
)
'''
    spec.write_text(content, encoding="utf-8")
    return spec


def _copy_runtime(dest: Path) -> None:
    for d in RUNTIME_DIRS:
        src = PROJECT / d
        if not src.is_dir():
            continue
        dst = dest / d
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst, ignore=_ignore_copy)
    for rel in RUNTIME_FILES:
        src = PROJECT / rel
        if src.is_file():
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest / rel)
    # 确保 AI 配置示例存在
    example = PROJECT / "config" / "ai.yaml.example"
    if example.is_file():
        shutil.copy2(example, dest / "config" / "ai.yaml.example")
    ai_local = dest / "config" / "ai.yaml"
    if not ai_local.is_file() and example.is_file():
        text = example.read_text(encoding="utf-8").replace("your-api-key-here", "")
        ai_local.write_text(text, encoding="utf-8")


def _bundle_chromium(dest: Path, *, skip: bool = False) -> None:
    """下载并复制 Chromium 到绿色版 ms-playwright/（约 +150MB）."""
    if skip:
        print(">>> 跳过 Chromium 打包（--skip-chromium）")
        return

    try:
        import playwright  # noqa: F401
    except ImportError:
        print(">>> 未安装 playwright，跳过 Chromium 打包")
        return

    cache = PROJECT / "build" / "playwright-browsers"
    if cache.exists():
        shutil.rmtree(cache)
    cache.mkdir(parents=True)

    print(">>> 下载 Chromium（playwright install，需联网，约 1–3 分钟）…")
    env = os.environ.copy()
    env["PLAYWRIGHT_BROWSERS_PATH"] = str(cache)
    subprocess.check_call(
        [sys.executable, "-m", "playwright", "install", "chromium"],
        env=env,
    )

    dest_browsers = dest / "ms-playwright"
    if dest_browsers.exists():
        shutil.rmtree(dest_browsers)
    dest_browsers.mkdir(parents=True)

    total = 0
    for item in cache.iterdir():
        if item.name.startswith("chromium_headless_shell"):
            continue
        dst = dest_browsers / item.name
        if item.is_dir():
            shutil.copytree(item, dst)
        else:
            shutil.copy2(item, dst)
        if item.is_dir():
            total += sum(f.stat().st_size for f in item.rglob("*") if f.is_file())
        else:
            total += item.stat().st_size

    size_mb = total / 1024 / 1024
    print(f">>> Chromium 已内置: {dest_browsers} ({size_mb:.0f} MB，已省略 headless-shell)")


def _write_readme(dest: Path, *, with_chromium: bool) -> None:
    chromium_line = (
        "  - AI 浏览器 Hook：已内置 Chromium（ms-playwright/），开箱即用\n"
        if with_chromium and (dest / "ms-playwright").is_dir()
        else "  - AI 浏览器 Hook：需完整版绿色包（含 ms-playwright/）\n"
    )
    dest.joinpath("使用说明.txt").write_text(
        f"""密桥 CipherBridge — 绿色版

【启动】
  双击 密桥.exe

【说明】
  - 无需安装 Python，profiles / plugins / config 与本目录同级，可整夹拷贝
  - 代理功能依赖同目录 mitmdump.exe（已一并打包）
  - HTTPS 抓包：设置 → 安装 HTTPS 证书
{chromium_line}
【目录】
  config/         主题、AI 配置
  profiles/       项目配置
  plugins/        生成的代理插件
  sdk/            加解密函数库（插件引用）
  ms-playwright/  内置 Chromium（AI 自动化分析）

作者：W啥都学
""",
        encoding="utf-8",
    )


def build(out_dir: Path, *, skip_chromium: bool = False) -> None:
    if sys.platform != "win32":
        print("当前脚本面向 Windows 绿色版；其它平台请手动使用 PyInstaller。")
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("正在安装 PyInstaller…")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller>=6.0"])

    build_dir = PROJECT / "build" / "portable"
    dist_dir = build_dir / "dist"
    work_dir = build_dir / "work"
    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True)
    dist_dir.mkdir()
    work_dir.mkdir()

    spec = _write_spec(build_dir)
    print(">>> PyInstaller 打包中（约 3–8 分钟）…")
    subprocess.check_call(
        [
            sys.executable, "-m", "PyInstaller",
            str(spec),
            "--distpath", str(dist_dir),
            "--workpath", str(work_dir),
            "--noconfirm",
            "--clean",
        ],
        cwd=str(build_dir),
    )

    bundle = dist_dir / "CipherBridge"
    if not bundle.is_dir():
        raise SystemExit(f"未找到打包输出: {bundle}")

    out_dir = out_dir.resolve()
    if out_dir.exists():
        print(f">>> 清理旧目录: {out_dir}")
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    print(f">>> 复制到: {out_dir}")
    for item in bundle.iterdir():
        dest = out_dir / item.name
        if item.is_dir():
            shutil.copytree(item, dest)
        else:
            shutil.copy2(item, dest)

    print(">>> 复制运行时资源（sdk / plugins / config …）")
    _copy_runtime(out_dir)
    _bundle_chromium(out_dir, skip=skip_chromium)
    _write_readme(out_dir, with_chromium=not skip_chromium)

    # 清理临时 build
    shutil.rmtree(build_dir, ignore_errors=True)

    exe = out_dir / "密桥.exe"
    mitm = out_dir / "mitmdump.exe"
    pw = out_dir / "ms-playwright"
    print("\n打包完成!")
    print(f"  主程序: {exe} ({'存在' if exe.is_file() else '缺失'})")
    print(f"  代理:   {mitm} ({'存在' if mitm.is_file() else '缺失'})")
    print(f"  浏览器: {pw} ({'已内置' if pw.is_dir() else '未打包'})")
    print(f"  大小约: {sum(f.stat().st_size for f in out_dir.rglob('*') if f.is_file()) / 1024 / 1024:.0f} MB")


def main() -> None:
    parser = argparse.ArgumentParser(description="打包密桥绿色版")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="输出目录")
    parser.add_argument(
        "--skip-chromium",
        action="store_true",
        help="不打包 Chromium（体积更小，AI 浏览器 Hook 不可用）",
    )
    args = parser.parse_args()
    build(args.out, skip_chromium=args.skip_chromium)


if __name__ == "__main__":
    main()
