"""AI / 浏览器实验室配置."""

from __future__ import annotations

import os
import yaml

from core.paths import get_app_root

ROOT = get_app_root()
AI_CONFIG_PATH = os.path.join(ROOT, "config", "ai.yaml")

DEFAULT = {
    "provider": "deepseek",
    "api_key": "",
    "base_url": "https://api.deepseek.com/v1",
    "model": "deepseek-chat",
    "http_proxy": "127.0.0.1:7897",
    "use_http_proxy": False,
    # Agent（Anthropic Messages + tools）；空则从 base_url 推导
    "agent_base_url": "",
    "agent_max_steps": 15,
    "browser": {
        "hook_enabled": True,
        "headless": False,
        "use_mitm_proxy": False,
        "mitm_port": 8080,
        "last_url": "",
    },
}


def resolve_agent_base_url(cfg: dict) -> str:
    """一键分析用 OpenAI /v1；Agent 用 Anthropic 兼容端点."""
    explicit = str(cfg.get("agent_base_url") or "").strip().rstrip("/")
    if explicit:
        return explicit
    base = str(cfg.get("base_url") or "").strip().rstrip("/")
    if not base:
        return "https://api.deepseek.com/anthropic"
    low = base.lower()
    if "deepseek.com" in low:
        # https://api.deepseek.com/v1 → /anthropic
        if low.endswith("/v1"):
            return base[: -len("/v1")] + "/anthropic"
        if low.endswith("/anthropic"):
            return base
        return base + "/anthropic"
    if low.endswith("/v1"):
        # 其它 OpenAI 风格网关：尝试同主机 /anthropic（调用方仍可写 agent_base_url）
        return base
    return base


def load_ai_config() -> dict:
    if not os.path.isfile(AI_CONFIG_PATH):
        return dict(DEFAULT)
    with open(AI_CONFIG_PATH, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    cfg = dict(DEFAULT)
    cfg.update({k: v for k, v in data.items() if k != "browser"})
    cfg["browser"] = {**DEFAULT["browser"], **(data.get("browser") or {})}
    return cfg


def save_ai_config(cfg: dict) -> None:
    os.makedirs(os.path.dirname(AI_CONFIG_PATH), exist_ok=True)
    with open(AI_CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, default_flow_style=False)
