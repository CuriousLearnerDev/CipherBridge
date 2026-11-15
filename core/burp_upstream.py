"""通知已加载的 Burp 扩展「CipherBridge Upstream」设置/清除上游代理."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

DEFAULT_BRIDGE_PORT = 19527
DEFAULT_TIMEOUT = 2.5


def bridge_base_url(port: int = DEFAULT_BRIDGE_PORT) -> str:
    return f"http://127.0.0.1:{int(port)}"


def burp_bridge_health(bridge_port: int = DEFAULT_BRIDGE_PORT) -> dict[str, Any] | None:
    try:
        req = urllib.request.Request(
            bridge_base_url(bridge_port) + "/health",
            method="GET",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return None


def set_burp_upstream(
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8081,
    *,
    bridge_port: int = DEFAULT_BRIDGE_PORT,
) -> tuple[bool, str]:
    """让 Burp 上游代理指向加密端. 成功返回 (True, msg)."""
    payload = json.dumps(
        {"host": proxy_host, "port": int(proxy_port)},
        ensure_ascii=False,
    ).encode("utf-8")
    req = urllib.request.Request(
        bridge_base_url(bridge_port) + "/upstream",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            try:
                obj = json.loads(body)
            except Exception:
                obj = {}
            if obj.get("ok"):
                return True, f"Burp 上游已设为 {proxy_host}:{proxy_port}"
            return False, str(obj.get("error") or body or "未知错误")
    except urllib.error.URLError as e:
        return False, (
            "未连通 CipherBridge Upstream 扩展（"
            f"{bridge_base_url(bridge_port)}）。"
            "请在 Burp → Extender → Extensions 加载 tools/burp/CipherBridge-Upstream.jar"
            f"：{e.reason}"
        )
    except Exception as e:
        return False, str(e)


def clear_burp_upstream(*, bridge_port: int = DEFAULT_BRIDGE_PORT) -> tuple[bool, str]:
    """恢复/清空 Burp 上游代理."""
    req = urllib.request.Request(
        bridge_base_url(bridge_port) + "/upstream/clear",
        data=b"{}",
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            try:
                obj = json.loads(body)
            except Exception:
                obj = {}
            if obj.get("ok"):
                return True, "已恢复/清除 Burp 上游代理"
            return False, str(obj.get("error") or body or "未知错误")
    except urllib.error.URLError as e:
        return False, f"未连通 Burp 扩展，跳过清除上游: {e.reason}"
    except Exception as e:
        return False, str(e)
