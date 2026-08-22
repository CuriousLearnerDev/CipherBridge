"""密桥前端壳 — PyQt QWebEngine 加载 Vue 界面 + 本地 API.

用法:
  python gui.py              # 默认前端壳（config gui.ui=web）
  python gui.py --qt         # 经典 PyQt 界面
  python -m core.web_shell   # 直接启动前端壳
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from PyQt6.QtCore import QTimer, Qt, QUrl
from PyQt6.QtWidgets import (
    QApplication,
    QLabel,
    QMainWindow,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

from core.brand import APP_TITLE
from core.paths import get_app_root

API_PORT = 18765
VITE_PORT = 5174


def _vue_root() -> Path:
    return Path(get_app_root()) / "vue版"


def _dist_index() -> Path:
    return _vue_root() / "dist" / "index.html"


def _port_open(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.4):
            return True
    except OSError:
        return False


def _http_ok(url: str, timeout: float = 0.8) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return 200 <= getattr(resp, "status", 200) < 300
    except Exception:
        return False


def _wait_until(pred, timeout: float = 45.0, interval: float = 0.35) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(interval)
    return False


def _find_npm() -> str | None:
    return shutil.which("npm.cmd") or shutil.which("npm")


class WebShellWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_TITLE} · 前端")
        self.setMinimumSize(1100, 700)
        self.resize(1280, 820)
        self._api_proc: subprocess.Popen | None = None
        self._vite_proc: subprocess.Popen | None = None
        self._frontend_url = ""

        splash = QWidget()
        lay = QVBoxLayout(splash)
        self._status = QLabel("正在启动前端界面…")
        self._status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status.setStyleSheet("font-size:14px; color:#5f6d7d; padding:40px;")
        lay.addWidget(self._status)
        self.setCentralWidget(splash)

        QTimer.singleShot(80, self._boot)

    def _set_status(self, text: str) -> None:
        self._status.setText(text)
        QApplication.processEvents()

    def _boot(self) -> None:
        try:
            self._ensure_api()
            url = self._ensure_frontend()
            self._frontend_url = url
            self._mount_webview(url)
        except Exception as e:
            self._status.setText(f"启动失败：{e}")
            QMessageBox.critical(
                self,
                "前端界面启动失败",
                f"{e}\n\n可改用经典界面：\n  python gui.py --qt\n\n"
                "或先准备前端：\n  cd vue版\n  npm.cmd install\n  npm.cmd run build",
            )

    def _ensure_api(self) -> None:
        status_url = f"http://127.0.0.1:{API_PORT}/status"
        if _http_ok(status_url):
            self._set_status("Python API 已就绪")
            return

        self._set_status("正在启动 Python API…")
        root = Path(get_app_root())
        api_script = root / "vue版" / "server" / "api_server.py"
        if not api_script.is_file():
            raise FileNotFoundError(f"找不到 API：{api_script}")

        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        self._api_proc = subprocess.Popen(
            [sys.executable, str(api_script), "--port", str(API_PORT), "--root", str(root)],
            cwd=str(root),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        if not _wait_until(lambda: _http_ok(status_url), timeout=20):
            raise RuntimeError(
                f"API 未能在 :{API_PORT} 就绪。请确认已安装 fastapi / uvicorn：\n"
                f"  pip install -r vue版/server/requirements.txt"
            )

    def _ensure_frontend(self) -> str:
        """优先用构建产物（经 API 静态托管或本地 http），否则拉起 Vite 开发服。"""
        dist = _dist_index()
        vue = _vue_root()

        # 已有 dist：让 API 托管静态（需 api_server 支持）；或直接起一个简易 file server
        if dist.is_file():
            # API 已带 StaticFiles 时走同源；否则 Vite preview / 直连 file 不如 http
            # 约定：API 根路径挂 dist 后访问 http://127.0.0.1:18765/
            if _http_ok(f"http://127.0.0.1:{API_PORT}/"):
                self._set_status("加载前端构建产物…")
                return f"http://127.0.0.1:{API_PORT}/"
            # 回退：用 python -m http.server 不行因为要 SPA；直接用 vite preview
            npm = _find_npm()
            if npm:
                self._set_status("正在预览前端构建…")
                self._vite_proc = subprocess.Popen(
                    [npm, "run", "preview", "--", "--host", "127.0.0.1", "--port", str(VITE_PORT)],
                    cwd=str(vue),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    shell=False,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
                )
                url = f"http://127.0.0.1:{VITE_PORT}/"
                if _wait_until(lambda: _http_ok(url), timeout=25):
                    return url

        # 开发：vite
        if _http_ok(f"http://127.0.0.1:{VITE_PORT}/"):
            self._set_status("连接 Vite 开发服…")
            return f"http://127.0.0.1:{VITE_PORT}/"

        npm = _find_npm()
        if not npm:
            raise RuntimeError(
                "未找到 npm，且没有 vue版/dist。\n"
                "请安装 Node.js，或在 vue版 执行 npm run build。"
            )
        if not (vue / "node_modules").is_dir():
            self._set_status("首次运行：npm install（可能较久）…")
            env = os.environ.copy()
            env.setdefault("ELECTRON_MIRROR", "https://npmmirror.com/mirrors/electron/")
            r = subprocess.run(
                [npm, "install"],
                cwd=str(vue),
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if r.returncode != 0:
                raise RuntimeError(f"npm install 失败：\n{(r.stderr or r.stdout)[-800:]}")

        self._set_status("正在启动 Vite 前端…")
        self._vite_proc = subprocess.Popen(
            [npm, "run", "dev", "--", "--host", "127.0.0.1", "--port", str(VITE_PORT)],
            cwd=str(vue),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        url = f"http://127.0.0.1:{VITE_PORT}/"
        if not _wait_until(lambda: _http_ok(url), timeout=60):
            raise RuntimeError(f"Vite 未能在 :{VITE_PORT} 就绪")
        return url

    def _mount_webview(self, url: str) -> None:
        self._set_status(f"打开 {url}")
        try:
            from PyQt6.QtWebEngineWidgets import QWebEngineView
            from PyQt6.QtWebEngineCore import QWebEngineSettings
        except ImportError as e:
            raise RuntimeError(
                "缺少 PyQt6-WebEngine。请安装：\n  pip install PyQt6-WebEngine"
            ) from e

        view = QWebEngineView(self)
        settings = view.settings()
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        view.load(QUrl(url))
        self.setCentralWidget(view)

    def closeEvent(self, event) -> None:
        for proc in (self._vite_proc, self._api_proc):
            if proc is None or proc.poll() is not None:
                continue
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        event.accept()


def run_web_shell() -> int:
    # QtWebEngine 要求在 QApplication 前导入/共享 GL
    try:
        from PyQt6.QtCore import Qt as _Qt
        QApplication.setAttribute(_Qt.ApplicationAttribute.AA_ShareOpenGLContexts)
    except Exception:
        pass
    try:
        import PyQt6.QtWebEngineWidgets  # noqa: F401
    except ImportError:
        print("请安装: pip install PyQt6-WebEngine", file=sys.stderr)
        return 1

    app = QApplication(sys.argv)
    try:
        from core.icon_loader import apply_app_icon, app_icon

        ic = app_icon()
        if not ic.isNull():
            app.setWindowIcon(ic)
    except Exception:
        apply_app_icon = None  # type: ignore[assignment]

    win = WebShellWindow()
    if apply_app_icon is not None:
        try:
            apply_app_icon(win)
        except Exception:
            pass
    win.show()
    return app.exec()


def main() -> None:
    sys.exit(run_web_shell())


if __name__ == "__main__":
    main()
