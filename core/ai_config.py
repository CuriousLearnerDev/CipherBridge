"""AI / 浏览器实验室配置."""

from __future__ import annotations

import os
import uuid
import yaml

from core.paths import get_app_root

ROOT = get_app_root()
AI_CONFIG_PATH = os.path.join(ROOT, "config", "ai.yaml")

# 进程内稳定的 OpenCode 会话 ID（同一次运行路由亲和）
_OPENCODE_SESSION_ID: str | None = None

DEFAULT = {
    "provider": "deepseek",
    # 分析始终走 OpenAI /v1/chat/completions；此项只影响 Agent 的 Anthropic 端点推导
    # deepseek | newapi | custom
    "api_format": "deepseek",
    "api_key": "",
    "base_url": "https://api.deepseek.com/v1",
    "model": "deepseek-chat",
    "http_proxy": "127.0.0.1:7897",
    "use_http_proxy": False,
    # Agent（Anthropic Messages + tools）；api_format=custom 时必填，其它可留空自动推导
    "agent_base_url": "",
    "agent_max_steps": 50,
    # OpenCode Go/Zen：可手写固定会话；空则进程内自动生成
    "opencode_session": "",
    "browser": {
        # 默认只开密钥 Hook；反调试相关需在「注入」菜单手动勾选
        "hook_enabled": True,
        "anti_debug": False,
        "cdp_skip_pauses": False,
        "inject_opts": {
            "functionHook": True,
            "evalHook": True,
            "timerHook": True,
            "timerNuke": False,
            "consoleClear": True,
            "sizeSpoof": True,
            # 响应里 debugger→return（默认关，需要时在注入菜单勾选）
            "rewriteResponse": False,
        },
        # 默认加载油猴(Violentmonkey) + ReRes；首次启动经代理拉 GitHub
        "load_violentmonkey": True,
        "load_reres": True,
        "load_cb_hook": True,
        "ext_proxy": "127.0.0.1:7897",
        "headless": False,
        "use_mitm_proxy": False,
        "mitm_port": 8083,
        # 记录模式：固定 data/browser_profile 长期复用（Cookie/登录态/扩展）；关闭则每次临时目录
        "record_mode": True,
        # chromium=Playwright 内置；chrome=本机 Chrome；msedge=本机 Edge
        "browser_channel": "chromium",
        # 真实浏览器（旧名 proxy_only）：本机 Chrome/Edge，不注入任何脚本/扩展（呜呼有头持久）
        "real_browser": False,
        "proxy_only": False,  # 兼容旧配置，读时与 real_browser 合并
        "last_url": "",
    },
}

# UI / yaml 取值
API_FORMATS = ("deepseek", "newapi", "custom")
BROWSER_CHANNELS = ("chromium", "chrome", "msedge")


def normalize_browser_channel(value: str | None) -> str:
    v = str(value or "chromium").strip().lower().replace("_", "-")
    if v in ("chrome", "google-chrome", "googlechrome", "本机chrome"):
        return "chrome"
    if v in ("msedge", "edge", "microsoft-edge", "本机edge", "本机msedge"):
        return "msedge"
    return "chromium"


def is_real_browser_cfg(browser: dict | None) -> bool:
    """配置里是否开启真实浏览器（兼容旧键 proxy_only）。"""
    if not isinstance(browser, dict):
        return False
    return bool(browser.get("real_browser") or browser.get("proxy_only"))


def resolve_agent_base_url(cfg: dict) -> str:
    """Agent 用 Anthropic Messages；LLMClient 会再拼 /v1/messages.

    - deepseek → …/anthropic/v1/messages
    - newapi   → 同主机 …/v1/messages（去掉 OpenAI 的 /v1，避免 /v1/v1/messages）
    - custom   → 使用 agent_base_url
    """
    fmt = str(cfg.get("api_format") or "deepseek").strip().lower()
    if fmt not in API_FORMATS:
        fmt = "deepseek"

    explicit = str(cfg.get("agent_base_url") or "").strip().rstrip("/")
    if explicit:
        return explicit

    base = str(cfg.get("base_url") or "").strip().rstrip("/")
    if not base:
        return "https://api.deepseek.com/anthropic"
    low = base.lower()

    use_deepseek = fmt == "deepseek" or (
        fmt != "newapi" and "deepseek.com" in low
    )
    if use_deepseek:
        if low.endswith("/v1"):
            return base[: -len("/v1")] + "/anthropic"
        if low.endswith("/anthropic"):
            return base
        return base + "/anthropic"

    # newapi / custom 未填 agent_base_url：同主机 /v1/messages
    if low.endswith("/v1"):
        return base[: -len("/v1")]
    if low.endswith("/anthropic"):
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


def is_opencode_host(url_or_base: str | None) -> bool:
    low = (url_or_base or "").strip().lower()
    return "opencode.ai" in low


def get_opencode_session_id(cfg: dict | None = None) -> str:
    """稳定会话 ID：配置优先，否则进程内生成一次。"""
    global _OPENCODE_SESSION_ID
    cfg = cfg or {}
    fixed = str(cfg.get("opencode_session") or "").strip()
    if fixed:
        return fixed
    if not _OPENCODE_SESSION_ID:
        _OPENCODE_SESSION_ID = str(uuid.uuid4())
    return _OPENCODE_SESSION_ID


def enrich_ai_headers(
    headers: dict,
    *,
    url: str = "",
    cfg: dict | None = None,
    for_anthropic: bool = False,
) -> dict:
    """为 OpenCode Go/Zen 等网关补会话头与 UA；其它主机原样返回。"""
    out = dict(headers or {})
    cfg = cfg or {}
    target = url or str(cfg.get("base_url") or "")
    if not is_opencode_host(target):
        return out

    out.setdefault("User-Agent", "CipherBridge/1.0")
    out.setdefault("x-opencode-client", "cipherbridge")
    out["x-opencode-session"] = get_opencode_session_id(cfg)

    # Anthropic Messages 路径需要 x-api-key
    if for_anthropic:
        key = str(cfg.get("api_key") or "").strip()
        if not key:
            auth = str(out.get("Authorization") or "")
            if auth.lower().startswith("bearer "):
                key = auth[7:].strip()
        if key:
            out.setdefault("x-api-key", key)
    return out
