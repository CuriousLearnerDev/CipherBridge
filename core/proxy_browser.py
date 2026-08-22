"""快速启动浏览器 — 经解密端代理访问（类似 Burp 内置浏览器）."""

from __future__ import annotations

import asyncio
import base64
import time
from pathlib import Path
from urllib.parse import unquote, urlparse
from urllib.request import url2pathname

from PyQt6.QtCore import QThread, pyqtSignal


class ProxyBrowserWorker(QThread):
    """Playwright Chromium，流量走指定 HTTP 代理，忽略证书错误.

    注意：必须在子线程用 asyncio 新事件循环 + async_api。
    sync_api 会触发 set_wakeup_fd only works in main thread。
    """

    log = pyqtSignal(str)
    failed = pyqtSignal(str)
    started_ok = pyqtSignal()
    stopped = pyqtSignal()

    def __init__(self, proxy_port: int, url: str = "", parent=None):
        super().__init__(parent)
        self.proxy_port = int(proxy_port)
        self.url = (url or "").strip()
        self._stop_flag = False

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

        from core.playwright_env import has_bundled_chromium, setup_playwright_browsers_path

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

        if getattr(sys, "frozen", False) and not has_bundled_chromium():
            self.failed.emit("未找到内置 Chromium（ms-playwright）。请使用完整绿色版包。")
            return

        proxy = f"http://127.0.0.1:{self.proxy_port}"
        self.log.emit(f"启动浏览器，代理 → {proxy}（解密端）")
        launch_error: str | None = None

        try:
            async with async_playwright() as p:
                # launch + context + Chromium 参数三处都指定代理，避免只配 context 时未生效
                browser = await p.chromium.launch(
                    headless=False,
                    proxy={"server": proxy},
                    args=[
                        "--start-maximized",
                        "--ignore-certificate-errors",
                        "--disable-features=HttpsFirstBalancedModeAutoEnable",
                        "--allow-file-access-from-files",
                        f"--proxy-server={proxy}",
                        "--proxy-bypass-list=<-loopback>",
                    ],
                )
                # 起始拓扑页可为本地 HTML；之后 http(s) 一律经解密端
                context = await browser.new_context(
                    ignore_https_errors=True,
                    proxy={"server": proxy},
                    no_viewport=True,
                )
                page = await context.new_page()
                await self._maximize_page(page)

                target = self.url or "about:blank"
                if target and not target.startswith(
                    ("http://", "https://", "about:", "file:", "data:")
                ):
                    target = "https://" + target

                try:
                    await self._open_start_page(page, target)
                    await self._maximize_page(page)
                except Exception as e:
                    msg = str(e)
                    if "has been closed" in msg or "Target closed" in msg:
                        self.log.emit("浏览器已关闭")
                    else:
                        self.log.emit(f"打开起始页提示: {e}")
                else:
                    self.started_ok.emit()
                    self.log.emit(f"浏览器已打开（最大化 · 代理 {proxy}），关窗即结束")

                while not self._stop_flag:
                    try:
                        if not browser.is_connected():
                            break
                        if page.is_closed():
                            break
                        if not browser.contexts or not context.pages:
                            break
                    except Exception:
                        break
                    await asyncio.sleep(0.2)

                try:
                    if not page.is_closed():
                        await context.close()
                except Exception:
                    pass
                try:
                    if browser.is_connected():
                        await browser.close()
                except Exception:
                    pass
        except Exception as e:
            msg = str(e)
            if "has been closed" not in msg and "Target closed" not in msg:
                launch_error = msg
        finally:
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
