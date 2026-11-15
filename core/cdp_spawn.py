"""系统 Edge/Chrome：--remote-debugging-port 启动后 Playwright connect_over_cdp.

Playwright launch / launch_persistent_context 在部分瑞数门禁上易被识别；
先起 OS 浏览器、挑战跑完再 attach，指纹更接近日常浏览器。
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass
class SpawnedCdpBrowser:
    """connect_over_cdp 结果；关闭时需 disconnect + 杀 OS 进程。"""

    browser: Any
    child: subprocess.Popen
    endpoint: str
    exe: str
    label: str
    port: int


def free_local_port() -> int:
    """占用一个本机空闲 TCP 端口后立即释放，返回端口号。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def find_system_chromium(prefer: str | None = None) -> dict[str, str] | None:
    """查找本机 Edge / Chrome 可执行文件。

    prefer: msedge | chrome | None（默认先 Edge 后 Chrome）
    """
    program_files = os.environ.get("ProgramFiles") or r"C:\Program Files"
    program_files_x86 = os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)"
    local_app = os.environ.get("LOCALAPPDATA") or ""

    edge = [
        os.path.join(program_files_x86, "Microsoft", "Edge", "Application", "msedge.exe"),
        os.path.join(program_files, "Microsoft", "Edge", "Application", "msedge.exe"),
        "/usr/bin/microsoft-edge",
        "/usr/bin/microsoft-edge-stable",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ]
    chrome = [
        os.path.join(program_files, "Google", "Chrome", "Application", "chrome.exe"),
        os.path.join(program_files_x86, "Google", "Chrome", "Application", "chrome.exe"),
        os.path.join(local_app, "Google", "Chrome", "Application", "chrome.exe"),
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ]

    pref = (prefer or "").strip().lower()
    if pref in ("chrome", "google-chrome"):
        ordered = [("chrome", chrome), ("msedge", edge)]
    else:
        ordered = [("msedge", edge), ("chrome", chrome)]

    for label, paths in ordered:
        for path in paths:
            if path and os.path.isfile(path):
                return {"exe": path, "label": label}
    return None


def _cdp_ready(port: int) -> bool:
    url = f"http://127.0.0.1:{port}/json/version"
    try:
        with urllib.request.urlopen(url, timeout=0.8) as resp:
            return int(getattr(resp, "status", 200) or 200) == 200
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def wait_cdp_ready(port: int, budget_ms: int = 25_000) -> None:
    deadline = time.monotonic() + budget_ms / 1000.0
    while time.monotonic() < deadline:
        if _cdp_ready(port):
            return
        time.sleep(0.25)
    raise RuntimeError(
        f"CDP 端点 http://127.0.0.1:{port} 在 {budget_ms}ms 内未就绪"
    )


def spawn_and_connect_cdp(
    playwright,
    user_data_dir: str,
    *,
    warmup_url: str | None = None,
    warmup_ms: int = 12_000,
    prefer: str | None = None,
    extra_args: list[str] | None = None,
    log=None,
) -> SpawnedCdpBrowser:
    """启动系统浏览器并 sync connect_over_cdp.

    warmup_url 非空时：OS 进程先打开该 URL，等 warmup_ms 再 attach，
    让 JS 挑战在调试器接入前尽量跑完。
    """
    found = find_system_chromium(prefer)
    if not found:
        raise RuntimeError(
            "未找到本机 Edge/Chrome，无法 CDP 附加（请安装 Microsoft Edge 或 Google Chrome）"
        )

    os.makedirs(user_data_dir, exist_ok=True)
    port = free_local_port()
    endpoint = f"http://127.0.0.1:{port}"
    start_url = (warmup_url or "").strip() or "about:blank"
    args = [
        f"--remote-debugging-port={port}",
        f"--user-data-dir={user_data_dir}",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    if extra_args:
        args.extend(extra_args)
    args.append(start_url)

    if log:
        log(f"系统浏览器 CDP 启动: {found['label']} → {found['exe']}")
        log(f"调试口 {endpoint} · profile={user_data_dir}")
        if start_url != "about:blank":
            log(
                f"warmup 打开 {start_url}，约 {warmup_ms // 1000}s 后再 attach"
                "（挑战页可先跑完）"
            )

    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

    child = subprocess.Popen(
        [found["exe"], *args],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        creationflags=creationflags,
    )
    try:
        wait_cdp_ready(port, 25_000)
        if start_url != "about:blank" and warmup_ms > 0:
            time.sleep(warmup_ms / 1000.0)
            wait_cdp_ready(port, 15_000)
        browser = playwright.chromium.connect_over_cdp(endpoint)
        if log:
            log(f"CDP attach {endpoint} 成功（{found['label']}）")
        return SpawnedCdpBrowser(
            browser=browser,
            child=child,
            endpoint=endpoint,
            exe=found["exe"],
            label=found["label"],
            port=port,
        )
    except Exception:
        try:
            child.kill()
        except Exception:
            pass
        raise


def _kill_cdp_child(spawned: SpawnedCdpBrowser, *, log=None) -> None:
    child = spawned.child
    try:
        if child.poll() is None:
            child.kill()
            try:
                child.wait(timeout=5)
            except Exception:
                pass
            if log:
                log("已结束系统浏览器 CDP 进程")
    except Exception as e:
        if log:
            log(f"结束 CDP 浏览器进程失败: {e}")


def stop_spawned_cdp(spawned: SpawnedCdpBrowser | None, *, log=None) -> None:
    """断开 CDP 并结束 OS 浏览器进程（同步 Playwright）。"""
    if spawned is None:
        return
    try:
        spawned.browser.close()
    except Exception:
        pass
    _kill_cdp_child(spawned, log=log)


async def spawn_and_connect_cdp_async(
    playwright,
    user_data_dir: str,
    *,
    warmup_url: str | None = None,
    warmup_ms: int = 12_000,
    prefer: str | None = None,
    extra_args: list[str] | None = None,
    log=None,
) -> SpawnedCdpBrowser:
    """启动系统浏览器并 async connect_over_cdp（供 BrowserAgent 使用）。"""
    found = find_system_chromium(prefer)
    if not found:
        raise RuntimeError(
            "未找到本机 Edge/Chrome，无法 CDP 附加（请安装 Microsoft Edge 或 Google Chrome）"
        )

    os.makedirs(user_data_dir, exist_ok=True)
    port = free_local_port()
    endpoint = f"http://127.0.0.1:{port}"
    start_url = (warmup_url or "").strip() or "about:blank"
    args = [
        f"--remote-debugging-port={port}",
        f"--user-data-dir={user_data_dir}",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    if extra_args:
        args.extend(extra_args)
    args.append(start_url)

    if log:
        log(f"系统浏览器 CDP 启动: {found['label']} → {found['exe']}")
        log(f"调试口 {endpoint} · profile={user_data_dir}")
        if start_url != "about:blank":
            log(
                f"warmup 打开 {start_url}，约 {warmup_ms // 1000}s 后再 attach"
                "（挑战页可先跑完）"
            )

    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

    child = subprocess.Popen(
        [found["exe"], *args],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        creationflags=creationflags,
    )
    try:
        wait_cdp_ready(port, 25_000)
        if start_url != "about:blank" and warmup_ms > 0:
            time.sleep(warmup_ms / 1000.0)
            wait_cdp_ready(port, 15_000)
        browser = await playwright.chromium.connect_over_cdp(endpoint)
        if log:
            log(f"CDP attach {endpoint} 成功（{found['label']}）")
        return SpawnedCdpBrowser(
            browser=browser,
            child=child,
            endpoint=endpoint,
            exe=found["exe"],
            label=found["label"],
            port=port,
        )
    except Exception:
        try:
            child.kill()
        except Exception:
            pass
        raise


async def stop_spawned_cdp_async(
    spawned: SpawnedCdpBrowser | None, *, log=None
) -> None:
    """断开 CDP 并结束 OS 浏览器进程（异步 Playwright）。"""
    if spawned is None:
        return
    try:
        close = getattr(spawned.browser, "close", None)
        if close is not None:
            result = close()
            if hasattr(result, "__await__"):
                await result
    except Exception:
        pass
    _kill_cdp_child(spawned, log=log)
