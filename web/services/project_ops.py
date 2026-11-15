"""项目新建 / 保存 — 与 GUI 文件布局一致。"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from mcp_server.paths import PLUGINS_DIR, PROFILES_DIR, ROOT
from mcp_server.projects import get_project, resolve_plugin_path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore


def _safe_name(name: str) -> str:
    name = (name or "").strip()
    name = re.sub(r"[^\w\u4e00-\u9fff\-]+", "_", name, flags=re.UNICODE)
    name = name.strip("._") or "project"
    return name[:64]


def create_project(
    name: str,
    *,
    roles: list[str] | None = None,
    description: str = "",
) -> dict[str, Any]:
    from codegen import blank_plugin_template, default_profile_match_yaml

    name = _safe_name(name)
    if not name:
        return {"ok": False, "error": "名称无效"}
    profile_path = PROFILES_DIR / f"{name}.yaml"
    if profile_path.is_file():
        return {"ok": False, "error": f"项目已存在: {name}"}

    roles = roles or ["decrypt"]
    roles = [r for r in roles if r in ("decrypt", "encrypt")] or ["decrypt"]

    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    plugin_dir = PLUGINS_DIR / name
    plugin_dir.mkdir(parents=True, exist_ok=True)
    plugin_path = plugin_dir / "plugin.py"
    plugin_path.write_text(blank_plugin_template(name), encoding="utf-8")

    match_yaml = default_profile_match_yaml()
    # 拼完整 profile
    head = (
        f"name: {name}\n"
        f"description: {json.dumps(description or '', ensure_ascii=False)}\n"
        f"plugin: {name}\n"
        f"roles: {roles}\n"
    )
    profile_path.write_text(head + match_yaml, encoding="utf-8")
    state = {"steps": [], "parsed_fields": {}, "body_format": "json"}
    (plugin_dir / "state.json").write_text(
        json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return {
        "ok": True,
        "id": name,
        "profile": str(profile_path.relative_to(ROOT)).replace("\\", "/"),
        "plugin": str(plugin_path.relative_to(ROOT)).replace("\\", "/"),
    }


def save_plugin_code(name: str, code: str) -> dict[str, Any]:
    info = get_project(name)
    if info.get("error"):
        return {"ok": False, "error": info["error"]}
    plugin_field = (info.get("profile") or {}).get("plugin") or name
    path = resolve_plugin_path(plugin_field, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code or "", encoding="utf-8")
    return {"ok": True, "plugin_path": str(path.relative_to(ROOT)).replace("\\", "/")}


def save_project_state(
    name: str,
    *,
    steps: list | None = None,
    parsed_fields: dict | None = None,
    body_format: str = "json",
    raw_http: str = "",
    write_plugin: bool = True,
) -> dict[str, Any]:
    from codegen import codegen_for_pipeline

    info = get_project(name)
    if info.get("error"):
        return {"ok": False, "error": info["error"]}
    plugin_field = (info.get("profile") or {}).get("plugin") or name
    path = resolve_plugin_path(plugin_field, name)
    path.parent.mkdir(parents=True, exist_ok=True)

    steps = list(steps or [])
    raw = raw_http or ""
    state = {
        "steps": steps,
        "parsed_fields": dict(parsed_fields or {}),
        "body_format": body_format or "json",
        # Web 用 raw_http；GUI 用 raw_input — 双写便于互通
        "raw_http": raw,
        "raw_input": raw,
    }
    (path.parent / "state.json").write_text(
        json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    code = ""
    if write_plugin:
        if steps:
            code = codegen_for_pipeline(steps, body_format or "json", profile_name=name)
        else:
            # 保留已有代码；若无文件则写空白模板
            if path.is_file():
                code = path.read_text(encoding="utf-8", errors="replace")
            else:
                from codegen import blank_plugin_template

                code = blank_plugin_template(name)
        path.write_text(code, encoding="utf-8")
    return {
        "ok": True,
        "plugin_path": str(path.relative_to(ROOT)).replace("\\", "/"),
        "steps": len(steps),
        "plugin_code": code if write_plugin else None,
    }


def save_profile_match(name: str, match: dict[str, Any]) -> dict[str, Any]:
    if yaml is None:
        return {"ok": False, "error": "缺少 PyYAML"}
    profile = PROFILES_DIR / f"{name}.yaml"
    if not profile.is_file():
        return {"ok": False, "error": f"项目不存在: {name}"}
    data = yaml.safe_load(profile.read_text(encoding="utf-8")) or {}
    data["match"] = match
    profile.write_text(
        yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    return {"ok": True}


def delete_project(name: str) -> dict[str, Any]:
    name = _safe_name(name)
    if name.startswith("_template"):
        return {"ok": False, "error": "不能删除模板"}
    profile = PROFILES_DIR / f"{name}.yaml"
    if not profile.is_file():
        return {"ok": False, "error": f"项目不存在: {name}"}
    info = get_project(name)
    plugin_field = (info.get("profile") or {}).get("plugin") or name
    path = resolve_plugin_path(plugin_field, name)
    try:
        profile.unlink(missing_ok=True)
    except Exception as e:
        return {"ok": False, "error": str(e)}
    # 仅删 plugins/{name}/ 目录内容（短名项目）
    plugin_dir = path.parent
    if plugin_dir.is_dir() and plugin_dir.resolve().is_relative_to(PLUGINS_DIR.resolve()):
        for f in plugin_dir.glob("*"):
            try:
                if f.is_file():
                    f.unlink()
            except Exception:
                pass
        try:
            plugin_dir.rmdir()
        except Exception:
            pass
    return {"ok": True, "id": name}
