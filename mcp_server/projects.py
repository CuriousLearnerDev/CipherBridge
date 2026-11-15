"""项目 / 插件查询（与 GUI 一致：plugin 字段可为短名）。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp_server.paths import PLUGINS_DIR, PROFILES_DIR, ROOT

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore


def resolve_plugin_path(plugin_field: str | None, project_name: str = "") -> Path:
    """与 GUI PluginLoader 一致：短名 → plugins/{name}/plugin.py。"""
    raw = (plugin_field or project_name or "").strip().replace("\\", "/")
    if not raw:
        raw = (project_name or "").strip()
    if not raw:
        return PLUGINS_DIR / "_missing" / "plugin.py"
    p = Path(raw)
    if p.is_absolute():
        return p if p.suffix else p / "plugin.py"
    # 已是相对路径且带 plugin.py
    if raw.endswith(".py") or "/" in raw or "\\" in raw:
        return ROOT / raw
    # 短名：bachang → plugins/bachang/plugin.py
    return PLUGINS_DIR / raw / "plugin.py"


def plugin_rel_display(plugin_path: Path) -> str:
    try:
        return str(plugin_path.relative_to(ROOT)).replace("\\", "/")
    except Exception:
        return str(plugin_path).replace("\\", "/")


def list_projects() -> list[dict[str, Any]]:
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    items: list[dict[str, Any]] = []
    for p in sorted(PROFILES_DIR.glob("*.yaml")):
        name = p.stem
        roles: list[str] = []
        plugin_field = name
        desc = ""
        if yaml:
            try:
                data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
                roles = list(data.get("roles") or [])
                plugin_field = data.get("plugin") or name
                desc = str(data.get("description") or "")
            except Exception:
                pass
        plugin_path = resolve_plugin_path(plugin_field, name)
        items.append(
            {
                "id": name,
                "name": name,
                "roles": roles,
                "description": desc,
                "profile": str(p.relative_to(ROOT)).replace("\\", "/"),
                "plugin": plugin_rel_display(plugin_path),
                "plugin_exists": plugin_path.is_file(),
                "is_template": name.startswith("_template"),
            }
        )
    return items


def get_project(name: str) -> dict[str, Any]:
    name = (name or "").strip()
    if not name:
        return {"error": "name 不能为空"}
    profile = PROFILES_DIR / f"{name}.yaml"
    if not profile.is_file():
        return {"error": f"项目不存在: {name}", "hint": "先 list_projects"}
    raw = profile.read_text(encoding="utf-8")
    data: dict[str, Any] = {}
    if yaml:
        try:
            data = yaml.safe_load(raw) or {}
        except Exception as e:
            return {"error": f"YAML 解析失败: {e}"}
    plugin_field = data.get("plugin") or name
    plugin_path = resolve_plugin_path(plugin_field, name)
    code = ""
    if plugin_path.is_file():
        code = plugin_path.read_text(encoding="utf-8", errors="replace")
        if len(code) > 40_000:
            code = code[:40_000] + "\n…(+truncated)"
    state_path = plugin_path.parent / "state.json"
    state: dict[str, Any] | None = None
    if state_path.is_file():
        try:
            import json

            state = json.loads(state_path.read_text(encoding="utf-8"))
        except Exception:
            state = None
    return {
        "id": name,
        "profile_path": str(profile.relative_to(ROOT)).replace("\\", "/"),
        "profile": data,
        "plugin_path": plugin_rel_display(plugin_path),
        "plugin_exists": plugin_path.is_file(),
        "plugin_code": code,
        "state": state,
        "has_state": state is not None,
    }


def get_plugin_code(name: str, max_chars: int = 40_000) -> dict[str, Any]:
    name = (name or "").strip()
    info = get_project(name)
    if info.get("error"):
        # 无 profile 时仍尝试短名路径
        path = PLUGINS_DIR / name / "plugin.py"
        if not path.is_file():
            return info if info.get("error") else {"error": f"未找到插件: plugins/{name}/plugin.py"}
    else:
        path = resolve_plugin_path((info.get("profile") or {}).get("plugin") or name, name)
        if not path.is_file():
            return {"error": f"未找到插件: {plugin_rel_display(path)}"}
    code = path.read_text(encoding="utf-8", errors="replace")
    n = max(1000, min(int(max_chars or 40_000), 200_000))
    truncated = len(code) > n
    if truncated:
        code = code[:n] + "\n…(+truncated)"
    return {
        "name": name,
        "path": plugin_rel_display(path),
        "truncated": truncated,
        "code": code,
    }
