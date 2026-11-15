"""Profile 匹配规则读写与插件同步."""

from __future__ import annotations

import json
import os

import yaml

from codegen import codegen_for_pipeline, parse_code_to_steps
from core.paths import get_app_root

ROOT = get_app_root()
PROFILES_DIR = os.path.join(ROOT, "profiles")
PLUGINS_DIR = os.path.join(ROOT, "plugins")


def profile_yaml_path(profile_name: str) -> str:
    return os.path.join(PROFILES_DIR, f"{profile_name}.yaml")


def load_profile_config(profile_name: str) -> dict:
    path = profile_yaml_path(profile_name)
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_match_rules(profile_name: str) -> dict:
    return load_profile_config(profile_name).get("match", {})


def save_match_rules(profile_name: str, match: dict) -> None:
    """更新 profiles/*.yaml 中的 match 段."""
    path = profile_yaml_path(profile_name)
    cfg = load_profile_config(profile_name)
    if not cfg:
        raise FileNotFoundError(f"项目配置不存在: {path}")
    cfg["match"] = match
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False, default_flow_style=False)


def get_plugin_dir(profile_name: str) -> str:
    cfg = load_profile_config(profile_name)
    plugin_name = cfg.get("plugin", profile_name)
    return os.path.join(PLUGINS_DIR, plugin_name)


def regenerate_plugin_with_match(profile_name: str) -> bool:
    """按最新 match 规则重新生成 plugin.py."""
    plugin_dir = get_plugin_dir(profile_name)
    plugin_path = os.path.join(plugin_dir, "plugin.py")
    state_path = os.path.join(plugin_dir, "state.json")

    steps: list = []
    body_format = "json"
    if os.path.exists(state_path):
        with open(state_path, encoding="utf-8") as f:
            state = json.load(f)
        steps = state.get("steps", [])
        body_format = state.get("body_format", "json")
    elif os.path.exists(plugin_path):
        with open(plugin_path, encoding="utf-8") as f:
            steps = parse_code_to_steps(f.read())

    if not steps:
        return False

    code = codegen_for_pipeline(steps, body_format, profile_name)
    os.makedirs(plugin_dir, exist_ok=True)
    with open(plugin_path, "w", encoding="utf-8") as f:
        f.write(code)
    return True
