"""项目导出/导入 — 打包 plugin.py + profile.yaml + state.json 便于分享."""

from __future__ import annotations

import json
import os
import zipfile
from datetime import datetime, timezone

import yaml

from core.brand import APP_NAME_EN
from core.project_name import normalize_project_name

FORMAT_ID = "cipherbridge-project"
FORMAT_VERSION = 1
PACKAGE_SUFFIX = ".cbproj.zip"


class ProjectPackageError(Exception):
    """项目包读写错误."""


def package_extension() -> str:
    return PACKAGE_SUFFIX


def default_export_filename(profile_name: str) -> str:
    return f"{profile_name}{PACKAGE_SUFFIX}"


def project_exists(
    profile_name: str,
    *,
    profiles_dir: str,
    plugins_dir: str,
) -> bool:
    if os.path.isfile(os.path.join(profiles_dir, f"{profile_name}.yaml")):
        return True
    return os.path.isdir(os.path.join(plugins_dir, profile_name))


def resolve_project_files(
    profile_name: str,
    *,
    profiles_dir: str,
    plugins_dir: str,
) -> tuple[str, str, str | None]:
    """返回 (profile_path, plugin_path, state_path|None)."""
    profile_path = os.path.join(profiles_dir, f"{profile_name}.yaml")
    if not os.path.isfile(profile_path):
        raise ProjectPackageError(f"找不到项目配置: profiles/{profile_name}.yaml")

    with open(profile_path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    plugin_name = cfg.get("plugin", profile_name)
    plugin_path = os.path.join(plugins_dir, plugin_name, "plugin.py")
    if not os.path.isfile(plugin_path):
        raise ProjectPackageError(f"找不到插件代码: plugins/{plugin_name}/plugin.py")

    state_path = os.path.join(plugins_dir, plugin_name, "state.json")
    return profile_path, plugin_path, state_path if os.path.isfile(state_path) else None


def export_project(
    profile_name: str,
    dest_path: str,
    *,
    profiles_dir: str,
    plugins_dir: str,
) -> list[str]:
    """导出 zip，返回包含的文件名列表."""
    profile_path, plugin_path, state_path = resolve_project_files(
        profile_name,
        profiles_dir=profiles_dir,
        plugins_dir=plugins_dir,
    )

    with open(profile_path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    plugin_name = cfg.get("plugin", profile_name)

    included = ["profile.yaml", "plugin.py"]
    if state_path:
        included.append("state.json")

    manifest = {
        "format": FORMAT_ID,
        "format_version": FORMAT_VERSION,
        "app": APP_NAME_EN,
        "exported_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "profile_name": profile_name,
        "plugin_name": plugin_name,
        "files": included,
    }

    if not dest_path.lower().endswith(".zip"):
        dest_path = dest_path + PACKAGE_SUFFIX

    parent = os.path.dirname(os.path.abspath(dest_path))
    if parent:
        os.makedirs(parent, exist_ok=True)

    with zipfile.ZipFile(dest_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "manifest.json",
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        )
        zf.write(profile_path, "profile.yaml")
        zf.write(plugin_path, "plugin.py")
        if state_path:
            zf.write(state_path, "state.json")

    return included


def inspect_package(src_path: str) -> dict:
    """读取包信息，不写入磁盘."""
    if not os.path.isfile(src_path):
        raise ProjectPackageError("文件不存在")

    with zipfile.ZipFile(src_path, "r") as zf:
        names = zf.namelist()
        if "profile.yaml" not in names or "plugin.py" not in names:
            raise ProjectPackageError("无效的项目包：缺少 profile.yaml 或 plugin.py")

        try:
            profile_data = yaml.safe_load(zf.read("profile.yaml").decode("utf-8")) or {}
        except yaml.YAMLError as e:
            raise ProjectPackageError(f"profile.yaml 格式无效: {e}") from e

        manifest: dict = {}
        if "manifest.json" in names:
            try:
                manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
            except json.JSONDecodeError:
                pass

        has_state = "state.json" in names

    raw_name = profile_data.get("name") or manifest.get("profile_name") or ""
    raw_plugin = profile_data.get("plugin") or manifest.get("plugin_name") or raw_name
    return {
        "profile_name": normalize_project_name(str(raw_name)),
        "plugin_name": normalize_project_name(str(raw_plugin)),
        "roles": profile_data.get("roles", []),
        "description": (profile_data.get("description") or "").strip(),
        "has_state": has_state,
        "manifest": manifest,
    }


def import_project(
    src_path: str,
    *,
    profiles_dir: str,
    plugins_dir: str,
    profile_name: str | None = None,
    overwrite: bool = False,
) -> str:
    """导入项目包，返回实际使用的 profile 名."""
    info = inspect_package(src_path)
    name = normalize_project_name(profile_name or info["profile_name"])
    if not name:
        raise ProjectPackageError("无法确定项目名称")

    if project_exists(name, profiles_dir=profiles_dir, plugins_dir=plugins_dir) and not overwrite:
        raise FileExistsError(name)

    profile_path = os.path.join(profiles_dir, f"{name}.yaml")
    plugin_dir = os.path.join(plugins_dir, name)
    os.makedirs(profiles_dir, exist_ok=True)
    os.makedirs(plugin_dir, exist_ok=True)

    with zipfile.ZipFile(src_path, "r") as zf:
        try:
            profile_text = zf.read("profile.yaml").decode("utf-8")
            cfg = yaml.safe_load(profile_text) or {}
        except (UnicodeDecodeError, yaml.YAMLError) as e:
            raise ProjectPackageError(f"无法解析 profile.yaml: {e}") from e

        cfg["name"] = name
        cfg["plugin"] = name

        with open(profile_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(
                cfg, f, allow_unicode=True, default_flow_style=False, sort_keys=False,
            )

        with open(os.path.join(plugin_dir, "plugin.py"), "wb") as f:
            f.write(zf.read("plugin.py"))

        state_out = os.path.join(plugin_dir, "state.json")
        if "state.json" in zf.namelist():
            with open(state_out, "wb") as f:
                f.write(zf.read("state.json"))
        elif overwrite and os.path.isfile(state_out):
            os.remove(state_out)

    return name
