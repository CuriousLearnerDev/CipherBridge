"""代理启停 — 默认关闭，需 CB_MCP_ALLOW_PROXY=1。"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from mcp_server.paths import ALLOW_PROXY_CTRL, PLUGINS_DIR, ROOT

_decrypt: subprocess.Popen | None = None
_encrypt: subprocess.Popen | None = None


def _mitmdump() -> str:
    for name in ("mitmdump.exe", "mitmdump"):
        cand = ROOT / name
        if cand.is_file():
            return str(cand)
    import shutil

    return shutil.which("mitmdump") or "mitmdump"


def proxy_status() -> dict[str, Any]:
    def alive(p: subprocess.Popen | None) -> bool:
        return bool(p and p.poll() is None)

    return {
        "allow_proxy_ctrl": ALLOW_PROXY_CTRL,
        "decrypt_running": alive(_decrypt),
        "encrypt_running": alive(_encrypt),
        "decrypt_pid": _decrypt.pid if alive(_decrypt) else None,
        "encrypt_pid": _encrypt.pid if alive(_encrypt) else None,
        "hint": None
        if ALLOW_PROXY_CTRL
        else "启停需设置环境变量 CB_MCP_ALLOW_PROXY=1",
    }


def _stop(proc: subprocess.Popen | None, label: str) -> str:
    if not proc or proc.poll() is not None:
        return f"{label}: 未运行"
    try:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        return f"{label}: 已停止"
    except Exception as e:
        return f"{label}: 停止失败 {e}"


def proxy_stop(role: str = "decrypt") -> dict[str, Any]:
    global _decrypt, _encrypt
    if not ALLOW_PROXY_CTRL:
        return {"ok": False, "error": "未授权：设置 CB_MCP_ALLOW_PROXY=1"}
    role = (role or "decrypt").lower()
    msgs = []
    if role in ("decrypt", "all"):
        msgs.append(_stop(_decrypt, "decrypt"))
        _decrypt = None
    if role in ("encrypt", "all"):
        msgs.append(_stop(_encrypt, "encrypt"))
        _encrypt = None
    return {"ok": True, "messages": msgs, **proxy_status()}


def proxy_start(
    project: str,
    *,
    role: str = "decrypt",
    port: int = 8083,
    burp_port: int = 8080,
) -> dict[str, Any]:
    global _decrypt, _encrypt
    if not ALLOW_PROXY_CTRL:
        return {"ok": False, "error": "未授权：设置 CB_MCP_ALLOW_PROXY=1"}
    project = (project or "").strip()
    if not project:
        return {"ok": False, "error": "project 不能为空"}
    plugin = PLUGINS_DIR / project / "plugin.py"
    if not plugin.is_file():
        return {"ok": False, "error": f"缺少插件: {plugin}"}

    role = (role or "decrypt").lower()
    if role not in ("decrypt", "encrypt"):
        return {"ok": False, "error": "role 必须是 decrypt 或 encrypt"}

    # 同角色先停
    if role == "decrypt" and _decrypt and _decrypt.poll() is None:
        proxy_stop("decrypt")
    if role == "encrypt" and _encrypt and _encrypt.poll() is None:
        proxy_stop("encrypt")

    env = os.environ.copy()
    env["BURP_PORT"] = str(burp_port)
    env["PROFILE"] = project
    cmd = [_mitmdump(), "-s", str(plugin), "-p", str(port), "--set", "block_global=false"]
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
        )
    except Exception as e:
        return {"ok": False, "error": str(e), "cmd": cmd}

    if role == "decrypt":
        _decrypt = proc
    else:
        _encrypt = proc
    return {
        "ok": True,
        "role": role,
        "project": project,
        "port": port,
        "burp_port": burp_port,
        "pid": proc.pid,
        "cmd": cmd,
        **proxy_status(),
    }
