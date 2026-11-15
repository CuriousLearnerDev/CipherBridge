"""mitmproxy HTTPS 证书 — 一键安装（Windows 自动，其他平台打开证书文件）."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import time


def mitmproxy_cert_dir() -> str:
    return os.path.join(os.path.expanduser("~"), ".mitmproxy")


def mitmproxy_cert_path() -> str:
    for name in ("mitmproxy-ca-cert.cer", "mitmproxy-ca-cert.pem"):
        path = os.path.join(mitmproxy_cert_dir(), name)
        if os.path.isfile(path):
            return path
    return os.path.join(mitmproxy_cert_dir(), "mitmproxy-ca-cert.cer")


def is_cert_trusted() -> bool:
    """是否已信任 mitmproxy 根证书."""
    system = platform.system()
    if system == "Windows":
        return _windows_cert_in_store("user") or _windows_cert_in_store("machine")
    # macOS/Linux: 仅检查证书文件是否存在（系统信任需用户手动确认）
    return os.path.isfile(mitmproxy_cert_path())


def cert_status_text() -> str:
    if is_cert_trusted():
        return "HTTPS 证书: 已安装"
    if os.path.isfile(mitmproxy_cert_path()):
        return "HTTPS 证书: 未安装（点按钮安装）"
    return "HTTPS 证书: 未生成（先启动解密端）"


def _windows_cert_in_store(scope: str = "user") -> bool:
    try:
        cmd = ["certutil", "-store", "-user", "Root"] if scope == "user" else ["certutil", "-store", "Root"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20, encoding="gbk", errors="replace")
        return "mitmproxy" in ((r.stdout or "") + (r.stderr or "")).lower()
    except Exception:
        return False


def _resolve_mitmdump() -> str:
    if platform.system() == "Windows":
        import sys
        cand = os.path.join(os.path.dirname(sys.executable), "Scripts", "mitmdump.exe")
        if os.path.isfile(cand):
            return cand
    return shutil.which("mitmdump") or "mitmdump"


def ensure_cert_file() -> tuple[bool, str]:
    """若证书文件不存在，短暂启动 mitmdump 自动生成."""
    os.makedirs(mitmproxy_cert_dir(), exist_ok=True)
    if os.path.isfile(mitmproxy_cert_path()):
        return True, ""
    mitmdump = _resolve_mitmdump()
    if not mitmdump or (mitmdump == "mitmdump" and not shutil.which("mitmdump")):
        return False, "未找到 mitmdump，请先 pip install mitmproxy"
    try:
        proc = subprocess.Popen(
            [mitmdump, "-p", "18100", "--set", "flow_detail=0"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(2)
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
    except Exception as e:
        return False, f"生成证书失败: {e}"
    if os.path.isfile(mitmproxy_cert_path()):
        return True, ""
    return False, "证书未生成，请先在 GUI 启动一次解密端"


def _install_windows() -> tuple[bool, str]:
    ok, err = ensure_cert_file()
    if not ok:
        return False, err
    cert_path = mitmproxy_cert_path()
    if _windows_cert_in_store("user") or _windows_cert_in_store("machine"):
        return True, "证书已安装。\n请完全退出浏览器后访问 https://mitm.it 验证（需走解密代理）。"
    try:
        r = subprocess.run(
            ["certutil", "-addstore", "-user", "Root", cert_path],
            capture_output=True,
            text=True,
            timeout=30,
            encoding="gbk",
            errors="replace",
        )
        out = (r.stdout or "") + (r.stderr or "")
        if r.returncode == 0 or "已经在存储中" in out or "already in store" in out.lower():
            return True, (
                "安装成功。\n\n"
                "请完全退出浏览器（任务管理器结束 msedge.exe / chrome.exe），再重新打开。\n"
                "验证: 代理指向解密端 → 打开 https://mitm.it"
            )
        return False, out.strip() or "安装失败"
    except Exception as e:
        return False, str(e)


def _install_macos() -> tuple[bool, str]:
    ok, err = ensure_cert_file()
    if not ok:
        return False, err
    cert_path = mitmproxy_cert_path()
    subprocess.Popen(["open", cert_path])
    return True, (
        "已打开证书文件。\n"
        "钥匙串 → 找到 mitmproxy → 信任 → 始终信任 → 重启浏览器。\n"
        "验证: https://mitm.it"
    )


def _install_linux() -> tuple[bool, str]:
    ok, err = ensure_cert_file()
    if not ok:
        return False, err
    subprocess.Popen(["xdg-open", mitmproxy_cert_dir()])
    return True, (
        "已打开证书目录。\n"
        "Ubuntu: sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem "
        "/usr/local/share/ca-certificates/mitmproxy.crt && sudo update-ca-certificates\n"
        "Firefox 需在设置里单独导入证书。"
    )


def install_https_cert(parent=None, *, silent: bool = False) -> tuple[bool, str]:
    """一键安装 HTTPS 证书 — 主入口."""
    system = platform.system()
    if system == "Windows":
        ok, msg = _install_windows()
    elif system == "Darwin":
        ok, msg = _install_macos()
    else:
        ok, msg = _install_linux()

    if parent is not None and not silent:
        from PyQt6.QtWidgets import QMessageBox
        (QMessageBox.information if ok else QMessageBox.warning)(parent, "HTTPS 证书", msg)
    return ok, msg


def auto_install_if_needed(parent=None) -> bool:
    """解密端启动时：Windows 未安装则自动静默安装."""
    if platform.system() != "Windows" or is_cert_trusted():
        return is_cert_trusted()
    ok, _ = install_https_cert(parent, silent=True)
    if ok and parent is not None:
        from PyQt6.QtWidgets import QMessageBox
        QMessageBox.information(
            parent,
            "HTTPS 证书",
            "已自动安装 mitmproxy 证书。\n请完全退出浏览器后再访问 HTTPS 站点。",
        )
    return ok
