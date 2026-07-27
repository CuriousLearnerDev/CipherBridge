"""定位本机 Java / apktool / jadx（优先项目 tools/；大文件不随仓库分发）."""

from __future__ import annotations

import os
import shutil
from functools import lru_cache

from core.paths import get_app_root

SETUP_HELP = """App 逆向工具需自行配置（体积较大，不随 GitHub 源码分发）：

1. Java（必需）
   · 安装 JDK 8+，终端执行 java -version 能通过
   · 或设置环境变量 JAVA_HOME

2. apktool（必需）
   · 下载：https://apktool.org/
   · 将 apktool_*.jar 放到：tools/apktool/

3. jadx-gui（可选，图形查看）
   · 下载：https://github.com/skylot/jadx/releases
   · 将 jadx-gui-*.exe 放到：tools/jadx-gui/

也可设置环境变量：
  APKTOOL_JAR = jar 完整路径
  CIPHERBRIDGE_TOOLS = 工具根目录
  JAVA_HOME = JDK 目录

详见项目内 tools/README.md
"""


def project_tools_root() -> str:
    """密桥项目内工具目录：<app>/tools/."""
    return os.path.join(get_app_root(), "tools")


def ensure_tools_dirs() -> str:
    """确保 tools/apktool、tools/jadx-gui 存在，返回 tools 根路径."""
    root = project_tools_root()
    for sub in ("apktool", "jadx-gui"):
        os.makedirs(os.path.join(root, sub), exist_ok=True)
    return root


def _candidate_storage_roots() -> list[str]:
    """探测顺序：项目 tools → 环境变量 → 统领 storage（兼容旧布局）."""
    roots: list[str] = [project_tools_root()]

    env = os.environ.get("CIPHERBRIDGE_TOOLS") or os.environ.get("TONGLING_STORAGE")
    if env:
        roots.append(os.path.abspath(env))

    app = get_app_root()
    code_dir = os.path.abspath(os.path.join(app, "..", "..", ".."))
    for name in ("统领", "TongLing"):
        roots.append(os.path.join(code_dir, name, "storage"))
    desktop = os.path.abspath(os.path.join(app, "..", "..", "..", ".."))
    roots.append(os.path.join(desktop, "代码", "统领", "storage"))

    seen: set[str] = set()
    out: list[str] = []
    for r in roots:
        r = os.path.abspath(r)
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


@lru_cache(maxsize=1)
def resolve_java() -> str | None:
    env = os.environ.get("JAVA_HOME")
    if env:
        cand = os.path.join(env, "bin", "java.exe" if os.name == "nt" else "java")
        if os.path.isfile(cand):
            return cand
    which = shutil.which("java")
    if which:
        return which
    for root in _candidate_storage_roots():
        for rel in (
            os.path.join("jadx-gui", "jre", "bin", "java.exe"),
            os.path.join("jre", "bin", "java.exe"),
        ):
            cand = os.path.join(root, rel)
            if os.path.isfile(cand):
                return cand
    return None


@lru_cache(maxsize=1)
def resolve_apktool_jar() -> str | None:
    env = os.environ.get("APKTOOL_JAR")
    if env and os.path.isfile(env):
        return env
    for root in _candidate_storage_roots():
        d = os.path.join(root, "apktool")
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d), reverse=True):
            if name.lower().startswith("apktool") and name.lower().endswith(".jar"):
                return os.path.join(d, name)
    return None


@lru_cache(maxsize=1)
def resolve_jadx_gui() -> str | None:
    for root in _candidate_storage_roots():
        d = os.path.join(root, "jadx-gui")
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            low = name.lower()
            if low.startswith("jadx-gui") and low.endswith(".exe"):
                return os.path.join(d, name)
    return shutil.which("jadx-gui")


def tools_status() -> dict[str, str]:
    return {
        "java": resolve_java() or "",
        "apktool": resolve_apktool_jar() or "",
        "jadx_gui": resolve_jadx_gui() or "",
    }


def missing_required_tools() -> list[str]:
    """返回缺失的必需工具名：java / apktool."""
    st = tools_status()
    miss: list[str] = []
    if not st["java"]:
        miss.append("Java")
    if not st["apktool"]:
        miss.append("apktool")
    return miss


def tools_setup_message(*, missing: list[str] | None = None) -> str:
    miss = missing if missing is not None else missing_required_tools()
    head = ""
    if miss:
        head = f"缺少：{', '.join(miss)}\n\n"
    return head + SETUP_HELP + f"\n工具目录：{project_tools_root()}"
