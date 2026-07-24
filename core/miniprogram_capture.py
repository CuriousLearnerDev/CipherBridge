"""小程序流量采集 — 启动独立 mitmdump(capture_addon)，解析 CB_FLOW 行."""

from __future__ import annotations

import json
import os
import shutil
import sys

from PyQt6.QtCore import QObject, QProcess, QProcessEnvironment, pyqtSignal

from core.capture_addon import PREFIX
from core.capture_filter import parse_filter_patterns, should_capture_url
from core.paths import get_app_root, get_bundle_root
from core.system_proxy import ProxySnapshot, is_supported, restore_proxy, set_proxy

DEFAULT_PORT = 8090


def resolve_mitmdump() -> str:
    root = get_app_root()
    for name in ("mitmdump.exe", "mitmdump"):
        cand = os.path.join(root, name)
        if os.path.isfile(cand):
            return cand
    if sys.platform == "win32":
        cand = os.path.join(os.path.dirname(sys.executable), "Scripts", "mitmdump.exe")
        if os.path.isfile(cand):
            return cand
    return shutil.which("mitmdump") or "mitmdump"


def capture_addon_path() -> str:
    for root in (get_app_root(), get_bundle_root()):
        path = os.path.join(root, "core", "capture_addon.py")
        if os.path.isfile(path):
            return path
    return os.path.join(get_app_root(), "core", "capture_addon.py")


class MiniprogramCaptureWorker(QObject):
    """QProcess 驱动的抓包代理；发出与 BrowserLab 同形的 flow 信号."""

    flow_captured = pyqtSignal(dict)
    flow_updated = pyqtSignal(dict)
    log = pyqtSignal(str)
    started = pyqtSignal(int)  # port
    stopped = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._proc: QProcess | None = None
        self._port = DEFAULT_PORT
        self._use_system_proxy = True
        self._proxy_snapshot: ProxySnapshot | None = None
        self._key_to_index: dict[str, int] = {}
        self._flow_count = 0
        self._buf = ""
        self._host_filter = ""
        self._block_noise = True

    @property
    def running(self) -> bool:
        return bool(
            self._proc
            and self._proc.state() != QProcess.ProcessState.NotRunning
        )

    @property
    def port(self) -> int:
        return self._port

    def set_capture_filter(self, host_filter: str = "", *, block_noise: bool | None = None) -> None:
        """运行中也可改过滤（进程内二次过滤；重启后 addon 侧一并生效）."""
        self._host_filter = (host_filter or "").strip()
        if block_noise is not None:
            self._block_noise = bool(block_noise)

    def start(
        self,
        port: int = DEFAULT_PORT,
        *,
        use_system_proxy: bool = True,
        host_filter: str = "",
        block_noise: bool = True,
    ) -> None:
        if self.running:
            self.failed.emit("抓包代理已在运行")
            return
        self._port = int(port)
        self._use_system_proxy = bool(use_system_proxy)
        self._host_filter = (host_filter or "").strip()
        self._block_noise = bool(block_noise)
        self._key_to_index.clear()
        self._flow_count = 0
        self._buf = ""

        addon = capture_addon_path()
        if not os.path.isfile(addon):
            self.failed.emit(f"找不到抓包插件: {addon}")
            return

        mitmdump = resolve_mitmdump()
        args = [
            "-s", addon,
            "-p", str(self._port),
            "--set", "flow_detail=0",
            "--ssl-insecure",
        ]
        self._proc = QProcess(self)
        env = QProcessEnvironment.systemEnvironment()
        env.insert("PYTHONPATH", get_app_root())
        env.insert("CB_CAPTURE_HOST_FILTER", self._host_filter)
        env.insert("CB_CAPTURE_BLOCK_NOISE", "1" if self._block_noise else "0")
        self._proc.setProcessEnvironment(env)
        self._proc.setProgram(mitmdump)
        self._proc.setArguments(args)
        self._proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self._proc.readyReadStandardOutput.connect(self._on_stdout)
        self._proc.finished.connect(self._on_finished)
        self._proc.errorOccurred.connect(self._on_error)

        self.log.emit(f"启动抓包: {mitmdump} {' '.join(args)}")
        if self._host_filter:
            self.log.emit(f"域名过滤: {self._host_filter}")
        else:
            self.log.emit("域名过滤: （未设置，记录全部匹配流量）")
        if self._block_noise:
            self.log.emit("已开启：屏蔽常见系统噪音（更新/微软/谷歌等）")
        self._proc.start()
        if not self._proc.waitForStarted(8000):
            err = self._proc.errorString() if self._proc else "启动超时"
            self._proc = None
            self.failed.emit(f"mitmdump 启动失败: {err}")
            return

        if self._use_system_proxy and is_supported():
            try:
                self._proxy_snapshot = set_proxy("127.0.0.1", self._port)
                self.log.emit(
                    f"已设置系统代理 127.0.0.1:{self._port} "
                    f"(原设置: enable={self._proxy_snapshot.enabled} "
                    f"server={self._proxy_snapshot.server or '无'})"
                )
            except Exception as e:
                self.log.emit(f"系统代理设置失败（请手动配置）: {e}")
                self._proxy_snapshot = None
        elif self._use_system_proxy:
            self.log.emit(
                f"请手动将系统/微信代理设为 127.0.0.1:{self._port}"
            )

        self.started.emit(self._port)

    def stop(self) -> None:
        self._restore_system_proxy()
        if self._proc and self.running:
            self._proc.kill()
            self._proc.waitForFinished(3000)
        self._proc = None
        self.stopped.emit()

    def _restore_system_proxy(self) -> None:
        if self._proxy_snapshot is None:
            return
        try:
            restore_proxy(self._proxy_snapshot)
            self.log.emit("已恢复系统代理设置")
        except Exception as e:
            self.log.emit(f"恢复系统代理失败: {e}")
        self._proxy_snapshot = None

    def _on_stdout(self) -> None:
        if not self._proc:
            return
        raw = bytes(self._proc.readAllStandardOutput()).decode("utf-8", errors="replace")
        self._buf += raw
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            line = line.strip()
            if not line:
                continue
            if line.startswith(PREFIX):
                self._handle_flow_line(line[len(PREFIX):])
            elif "error" in line.lower() or "traceback" in line.lower():
                self.log.emit(line[:500])

    def _passes_filter(self, data: dict) -> bool:
        return should_capture_url(
            str(data.get("url") or ""),
            allow_patterns=parse_filter_patterns(self._host_filter),
            block_noise=self._block_noise,
        )

    def _handle_flow_line(self, payload: str) -> None:
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return
        key = str(data.get("key", ""))
        phase = data.get("phase")
        if not self._passes_filter(data):
            return
        if phase == "request" or key not in self._key_to_index:
            idx = self._flow_count
            self._flow_count += 1
            if key:
                self._key_to_index[key] = idx
            data["_index"] = idx
            data["_key"] = key
            self.flow_captured.emit(data)
            return
        idx = self._key_to_index[key]
        data["_index"] = idx
        data["_key"] = key
        self.flow_updated.emit(data)

    def _on_finished(self, code: int, _status) -> None:
        self._restore_system_proxy()
        self.log.emit(f"抓包进程结束 (code={code})")
        self._proc = None
        self.stopped.emit()

    def _on_error(self, _err) -> None:
        if self._proc:
            self.log.emit(f"抓包进程错误: {self._proc.errorString()}")
