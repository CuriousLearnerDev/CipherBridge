"""项目 / 插件只读查询。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp_server.paths import PLUGINS_DIR, PROFILES_DIR, ROOT

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore


def list_projects() -> list[dict[str, Any]]:
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    items: list[dict[str, Any]] = []
    for p in sorted(PROFILES_DIR.glob("*.yaml")):
        name = p.stem
        roles: list[str] = []
        plugin = f"plugins/{name}/plugin.py"
        desc = ""
        if yaml:
            try:
                data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
                roles = list(data.get("roles") or [])
                plugin = data.get("plugin") or plugin
                desc = str(data.get("description") or "")
            except Exception:
                pass
        plugin_path = ROOT / plugin if not Path(plugin).is_absolute() else Path(plugin)
        items.append(
            {
                "id": name,
                "name": name,
                "roles": roles,
                "description": desc,
                "profile": str(p.relative_to(ROOT)).replace("\\", "/"),
                "plugin": str(Path(plugin).as_posix()),
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
    plugin_rel = data.get("plugin") or f"plugins/{name}/plugin.py"
    plugin_path = ROOT / plugin_rel
    code = ""
    if plugin_path.is_file():
        code = plugin_path.read_text(encoding="utf-8", errors="replace")
        if len(code) > 40_000:
            code = code[:40_000] + "\n…(+truncated)"
    return {
        "id": name,
        "profile_path": str(profile.relative_to(ROOT)).replace("\\", "/"),
        "profile": data,
        "plugin_path": str(Path(plugin_rel).as_posix()),
        "plugin_exists": plugin_path.is_file(),
        "plugin_code": code,
    }


def get_plugin_code(name: str, max_chars: int = 40_000) -> dict[str, Any]:
    name = (name or "").strip()
    path = PLUGINS_DIR / name / "plugin.py"
    if not path.is_file():
        # 模板或自定义 plugin 字段
        info = get_project(name)
        if info.get("error"):
            return info
        code = info.get("plugin_code") or ""
        if not code:
            return {"error": f"未找到插件: plugins/{name}/plugin.py"}
        return {"name": name, "path": info.get("plugin_path"), "code": code}
    code = path.read_text(encoding="utf-8", errors="replace")
    n = max(1000, min(int(max_chars or 40_000), 200_000))
    truncated = len(code) > n
    if truncated:
        code = code[:n] + "\n…(+truncated)"
    return {
        "name": name,
        "path": f"plugins/{name}/plugin.py",
        "truncated": truncated,
        "code": code,
    }
