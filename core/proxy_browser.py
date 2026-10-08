"""快速启动浏览器 — 经解密端代理访问（类似 Burp 内置浏览器）."""

from __future__ import annotations

import asyncio
import base64
import os
import shutil
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlparse
from urllib.request import url2pathname

from PyQt6.QtCore import QThread, pyqtSignal


class ProxyBrowserWorker(QThread):
    """Playwright 浏览器，流量走指定 HTTP 代理，忽略证书错误.

    注意：必须在子线程用 asyncio 新事件循环 + async_api。
    sync_api 会触发 set_wakeup_fd only works in main thread。

    record_mode=True：复用 data/browser_profile[_chrome]。
    browser_channel: chromium | chrome。
    """

    log = pyqtSignal(str)
    failed = pyqtSignal(str)
    started_ok = pyqtSignal()
    stopped = pyqtSignal()

    def __init__(
        self,
        proxy_port: int,
        url: str = "",
        *,
        record_mode: bool = True,
        browser_channel: str = "chromium",
        fallback_chromium: bool = True,
        parent=None,
    ):
        super().__init__(parent)
        self.proxy_port = int(proxy_port)
        self.url = (url or "").strip()
        self.record_mode = bool(record_mode)
        self.browser_channel = browser_channel or "chromium"
        self.fallback_chromium = bool(fallback_chromium)
        self._stop_flag = False
        self._ephemeral_profile: str | None = None

    def stop(self) -> None:
        self._stop_flag = True

    @staticmethod
    def _file_uri_to_path(target: str) -> Path | None:
        if not target.startswith("file:"):
            return None
        parsed = urlparse(target)
        path = Path(url2pathname(unquote(parsed.path)))
        return path if path.is_file() else None

    @staticmethod
    def _home_html_with_embedded_png(html_path: Path) -> str:
        html = html_path.read_text(encoding="utf-8")
        png = html_path.parent / "e2f83ef5-edda-4dbf-a8f0-cf24bbc920aa.png"
        if not png.is_file():
            return html
        b64 = base64.b64encode(png.read_bytes()).decode("ascii")
        data_uri = f"data:image/png;base64,{b64}"
        for old in (
            'src="e2f83ef5-edda-4dbf-a8f0-cf24bbc920aa.png"',
            "src='e2f83ef5-edda-4dbf-a8f0-cf24bbc920aa.png'",
            'src="./e2f83ef5-edda-4dbf-a8f0-cf24bbc920aa.png"',
        ):
            html = html.replace(old, f'src="{data_uri}"')
        return html

    async def _maximize_page(self, page) -> None:
        try:
            session = await page.context.new_cdp_session(page)
            win = await session.send("Browser.getWindowForTarget")
            window_id = win.get("windowId")
            if window_id is not None:
                await session.send(
                    "Browser.setWindowBounds",
                    {"windowId": window_id, "bounds": {"windowState": "maximized"}},
                )
                return
        except Exception:
            pass
        try:
            await page.evaluate(
                "() => { try { window.moveTo(0,0); "
                "window.resizeTo(screen.availWidth, screen.availHeight); } catch (e) {} }"
            )
        except Exception:
            pass

    async def _open_start_page(self, page, target: str) -> None:
        path = self._file_uri_to_path(target)
        if path is not None:
            html = self._home_html_with_embedded_png(path)
            await page.set_content(html, wait_until="domcontentloaded")
            return
        await page.goto(target, wait_until="domcontentloaded", timeout=45000)

    async def _run_async(self) -> None:
        import sys

        from core.playwright_env import (
            apply_launch_channel,
            channel_label,
            has_bundled_chromium,
            profile_dir_for_channel,
            setup_playwright_browsers_path,
        )

        setup_playwright_browsers_path()
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            py = sys.executable
            self.failed.emit(
                "未安装 Playwright。\n\n"
                f'请执行:\n  "{py}" -m pip install playwright\n'
                f'  "{py}" -m playwright install chromium'
            )
            return

        from core.ai_config import normalize_browser_channel

        ch = normalize_browser_channel(self.browser_channel)
        if getattr(sys, "frozen", False) and ch == "chromium" and not has_bundled_chromium():
            self.failed.emit("未找到内置 Chromium（ms-playwright）。请使用完整绿色版包，或改选「本机 Chrome」。")
            return

        proxy = f"http://127.0.0.1:{self.proxy_port}"
        self.log.emit(f"启动浏览器，代理 → {proxy}（解密端）· {channel_label(ch)}")
        launch_error: str | None = None

        if self.record_mode:
            user_data_dir = profile_dir_for_channel(ch)
            os.makedirs(user_data_dir, exist_ok=True)
            self.log.emit(f"记录模式：复用持久 Profile → {user_data_dir}")
        else:
            user_data_dir = tempfile.mkdtemp(prefix="cb_proxy_browser_")
            self._ephemeral_profile = user_data_dir
            self.log.emit(f"非记录模式：临时 Profile → {user_data_dir}")

        try:
            async with async_playwright() as p:
                args = [
                    "--start-maximized",
                    "--ignore-certificate-errors",
                    "--allow-file-access-from-files",
                    f"--proxy-server={proxy}",
                    "--proxy-bypass-list=<-loopback>",
                ]
                from core.browser_stealth import (
                    apply_stealth_to_context_async,
                    apply_playwright_marker_cleanup_async,
                    merge_launch_options,
                    stealth_summary,
                    wait_out_js_challenge_async,
                )

                launch_opts = merge_launch_options(
                    apply_launch_channel(
                        {
                            "headless": False,
                            "proxy": {"server": proxy},
                            "ignore_https_errors": True,
                            "viewport": None,
                            "args": args,
                        },
                        ch,
                    ),
                    for_lab=False,
                )
                self.log.emit(f"拟真环境：{stealth_summary()}")
                try:
                    context = await p.chromium.launch_persistent_context(
                        user_data_dir, **launch_opts
                    )
                except Exception as e:
                    if ch == "chrome" and self.fallback_chromium:
                        self.log.emit(
                            f"本机 Chrome 启动失败，回退内置 Chromium：{e}"
                        )
                        ch = "chromium"
                        if self.record_mode:
                            user_data_dir = profile_dir_for_channel(ch)
                            os.makedirs(user_data_dir, exist_ok=True)
                            self.log.emit(f"记录模式：改用 Profile → {user_data_dir}")
                        launch_opts = merge_launch_options(
                            apply_launch_channel(
                                {
                                    "headless": False,
                                    "proxy": {"server": proxy},
                                    "ignore_https_errors": True,
                                    "viewport": None,
                                    "args": args,
                                },
                                ch,
                            ),
                            for_lab=False,
                        )
                        context = await p.chromium.launch_persistent_context(
                            user_data_dir, **launch_opts
                        )
                    elif ch == "chrome":
                        raise RuntimeError(
                            f"本机 Chrome 启动失败: {e}\n"
                            "请确认已安装 Google Chrome，或改回「Chromium（内置）」。"
                        ) from e
                    else:
                        raise
                try:
                    await apply_stealth_to_context_async(context)
                    await apply_playwright_marker_cleanup_async(context)
                except Exception as e:
                    self.log.emit(f"拟真脚本注入提示: {e}")
                page = context.pages[0] if context.pages else await context.new_page()
                await self._maximize_page(page)

                target = self.url or "about:blank"
                if target and not target.startswith(
                    ("http://", "https://", "about:", "file:", "data:")
                ):
                    target = "https://" + target

                try:
                    await self._open_start_page(page, target)
                    await self._maximize_page(page)
                    if target.startswith(("http://", "https://")):
                        await wait_out_js_challenge_async(
                            page,
                            log=lambda m: self.log.emit(m),
                        )
                except Exception as e:
                    msg = str(e)
                    if "has been closed" in msg or "Target closed" in msg:
                        self.log.emit("浏览器已关闭")
                    else:
                        self.log.emit(f"打开起始页提示: {e}")
                else:
                    self.started_ok.emit()
                    mode = "记录模式" if self.record_mode else "临时会话"
                    self.log.emit(
                        f"浏览器已打开（最大化 · {channel_label(ch)} · {mode} · 代理 {proxy}），关窗即结束"
                    )

                while not self._stop_flag:
                    try:
                        if page.is_closed():
                            break
                        if not context.pages:
                            break
                    except Exception:
                        break
                    await asyncio.sleep(0.2)

                try:
                    await context.close()
                except Exception:
                    pass
        except Exception as e:
            msg = str(e)
            if "has been closed" not in msg and "Target closed" not in msg:
                launch_error = msg
        finally:
            ephem = self._ephemeral_profile
            self._ephemeral_profile = None
            if ephem:
                try:
                    shutil.rmtree(ephem, ignore_errors=True)
                    self.log.emit("已清理临时 Profile")
                except Exception:
                    pass
            if launch_error:
                self.failed.emit(launch_error)

    def run(self) -> None:
        # 子线程必须自建事件循环，不能用 sync_playwright
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._run_async())
        except Exception as e:
            msg = str(e)
            if "has been closed" not in msg and "Target closed" not in msg:
                self.failed.emit(msg)
        finally:
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:
                pass
            loop.close()
            self.log.emit("代理浏览器已关闭")
            self.stopped.emit()
