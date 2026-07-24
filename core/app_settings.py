"""应用全局配置 — config/settings.yaml."""

from __future__ import annotations

import os

import yaml

from core.paths import get_app_root

ROOT = get_app_root()
SETTINGS_PATH = os.path.join(ROOT, "config", "settings.yaml")

_DEFAULTS = {
    "app": {"name": "密桥", "name_en": "CipherBridge", "version": "3.1"},
    "proxy": {
        "default_decrypt_port": 8080,
        "default_encrypt_port": 8081,
        "default_burp_address": "http://127.0.0.1:8083",
        "timeout": 30,
    },
    "gui": {"theme": "dark", "font_size": 11, "max_log_lines": 5000},
    "analyzer": {"auto_detect": True, "entropy_threshold": 0.8},
    "replay": {"auto_sign": True, "auto_encrypt": True},
}


def load_settings() -> dict:
    if not os.path.isfile(SETTINGS_PATH):
        return dict(_DEFAULTS)
    with open(SETTINGS_PATH, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    cfg = dict(_DEFAULTS)
    for key, val in data.items():
        if isinstance(val, dict) and isinstance(cfg.get(key), dict):
            merged = dict(cfg[key])
            merged.update(val)
            cfg[key] = merged
        else:
            cfg[key] = val
    return cfg


def save_settings(updates: dict) -> None:
    cfg = load_settings()
    for key, val in updates.items():
        if isinstance(val, dict) and isinstance(cfg.get(key), dict):
            cfg[key] = {**cfg[key], **val}
        else:
            cfg[key] = val
    os.makedirs(os.path.dirname(SETTINGS_PATH), exist_ok=True)
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, default_flow_style=False, sort_keys=False)


def get_theme() -> str:
    theme = (load_settings().get("gui") or {}).get("theme", "dark")
    return theme if theme in ("dark", "light") else "dark"


def set_theme(theme: str) -> None:
    if theme not in ("dark", "light"):
        theme = "dark"
    save_settings({"gui": {"theme": theme}})
