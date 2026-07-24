"""系统 HTTP(S) 代理开关 — 便于微信小程序跟系统代理走抓包端口.

仅 Windows 写注册表；其它平台返回说明，由用户手动配置.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any


@dataclass
class ProxySnapshot:
    enabled: int = 0
    server: str = ""
    override: str = ""


def is_supported() -> bool:
    return sys.platform == "win32"


def get_proxy() -> ProxySnapshot:
    if not is_supported():
        return ProxySnapshot()
    import winreg

    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0,
        winreg.KEY_READ,
    )
    try:
        enabled = int(winreg.QueryValueEx(key, "ProxyEnable")[0])
    except OSError:
        enabled = 0
    try:
        server = str(winreg.QueryValueEx(key, "ProxyServer")[0])
    except OSError:
        server = ""
    try:
        override = str(winreg.QueryValueEx(key, "ProxyOverride")[0])
    except OSError:
        override = ""
    winreg.CloseKey(key)
    return ProxySnapshot(enabled=enabled, server=server, override=override)


def _notify_wininet() -> None:
    """通知 WinINet 代理设置已变更."""
    import ctypes

    internet_option_settings_changed = 39
    internet_option_refresh = 37
    internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
    internet_set_option(0, internet_option_settings_changed, 0, 0)
    internet_set_option(0, internet_option_refresh, 0, 0)


def set_proxy(host: str, port: int, *, keep_local_direct: bool = True) -> ProxySnapshot:
    """启用系统代理，返回变更前的快照以便恢复."""
    if not is_supported():
        raise RuntimeError("当前系统不支持一键系统代理，请手动将微信/系统代理设为 "
                           f"{host}:{port}")
    import winreg

    prev = get_proxy()
    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0,
        winreg.KEY_SET_VALUE,
    )
    server = f"{host}:{int(port)}"
    override = prev.override
    if keep_local_direct:
        extras = ["<local>", "localhost", "127.0.0.1"]
        parts = [p.strip() for p in (override or "").split(";") if p.strip()]
        for e in extras:
            if e not in parts:
                parts.append(e)
        override = ";".join(parts)
    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)
    winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, override)
    winreg.CloseKey(key)
    _notify_wininet()
    return prev


def restore_proxy(snapshot: ProxySnapshot | dict[str, Any] | None) -> None:
    if not is_supported() or snapshot is None:
        return
    if isinstance(snapshot, dict):
        snapshot = ProxySnapshot(
            enabled=int(snapshot.get("enabled", 0)),
            server=str(snapshot.get("server", "")),
            override=str(snapshot.get("override", "")),
        )
    import winreg

    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0,
        winreg.KEY_SET_VALUE,
    )
    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, int(snapshot.enabled))
    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, snapshot.server or "")
    winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, snapshot.override or "")
    winreg.CloseKey(key)
    _notify_wininet()
