"""定位本机 Java / apktool / jadx（优先统领 storage 绿色版）."""

from __future__ import annotations

import os
import shutil
from functools import lru_cache

from core.paths import get_app_root


def _candidate_storage_roots() -> list[str]:
    roots: list[str] = []
    app = get_app_root()
    code_dir = os.path.abspath(os.path.join(app, "..", "..", ".."))
    for name in ("统领", "TongLing"):
        roots.append(os.path.join(code_dir, name, "storage"))
    desktop = os.path.abspath(os.path.join(app, "..", "..", "..", ".."))
    roots.append(os.path.join(desktop, "代码", "统领", "storage"))
    env = os.environ.get("TONGLING_STORAGE") or os.environ.get("CIPHERBRIDGE_TOOLS")
    if env:
        roots.insert(0, env)
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
    for root in _candidate_storage_roots():
        for rel in (
            os.path.join("jadx-gui", "jre", "bin", "java.exe"),
            os.path.join("jre", "bin", "java.exe"),
        ):
            cand = os.path.join(root, rel)
            if os.path.isfile(cand):
                return cand
    return shutil.which("java")


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
