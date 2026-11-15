"""从 app-service.js 拆出 define("path", ...) 模块，便于查看与 AI 分析."""

from __future__ import annotations

import os
import re


def split_app_service_js(service_path: str, out_dir: str | None = None) -> list[str]:
    """
    将微信打包的 app-service.js 按 define("xxx", ...) 拆成独立 JS。
    返回写出的文件路径列表（不含美化，保持原片段）。
    """
    if not os.path.isfile(service_path):
        return []
    with open(service_path, "rb") as f:
        data = f.read()
    if b'define("' not in data:
        return []

    root = out_dir or os.path.join(os.path.dirname(service_path), "_modules")
    os.makedirs(root, exist_ok=True)

    # 按 define(" 切割
    parts = data.split(b'define("')
    written: list[str] = []
    for part in parts[1:]:
        # name", <body>
        try:
            name_bytes, rest = part.split(b'",', 1)
        except ValueError:
            continue
        name = name_bytes.decode("utf-8", errors="replace").strip()
        if not name or ".." in name:
            continue
        # 取到匹配的 }); 末尾（宽松：最后一个 });）
        end = rest.rfind(b"});")
        body = rest[: end + 2] if end >= 0 else rest
        # 去掉可能的 function(...){ 包装由原包决定，原样写出
        rel = name.lstrip("/\\").replace("\\", "/")
        dest = os.path.normpath(os.path.join(root, *rel.split("/")))
        if not dest.startswith(os.path.normpath(root)):
            continue
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if not dest.endswith((".js", ".wxs")):
            dest = dest + ".js"
        with open(dest, "wb") as f:
            f.write(body.strip())
        written.append(dest)
    return written


def find_app_service_files(root: str) -> list[str]:
    hits: list[str] = []
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if name == "app-service.js":
                hits.append(os.path.join(dirpath, name))
    return hits


def split_all_app_services(root: str) -> list[str]:
    out: list[str] = []
    for svc in find_app_service_files(root):
        out.extend(split_app_service_js(svc))
    return out
