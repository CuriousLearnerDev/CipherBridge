"""加解密代理框架 — PyQt6 图形界面 (新架构).

Tab互通:
  请求解析器 ←→ 可视化构建器 (共享数据模型)
  在解析器标记字段 → 构建器自动生成步骤
  在构建器编辑步骤 → 解析器树刷新标记

端口职责:
  8083 解密端: 只处理 request(ctx) — 解密请求体
  8081 加密端: 只处理 request(ctx) — 加密+签名
  Burp 默认 8080
"""

import os, sys, json, yaml, logging, secrets, urllib.parse, html
import base64, hashlib, re
from datetime import datetime
from sm_crypto import sm3_hash
from encoding_utils import ENCODING_FUNCTIONS, HASH_FUNCTIONS

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QPushButton, QLabel, QLineEdit, QPlainTextEdit,
    QComboBox, QGroupBox, QSpinBox, QSplitter, QFrame,
    QMessageBox, QGridLayout, QCheckBox, QScrollArea, QTreeWidget,
    QTreeWidgetItem, QMenu, QInputDialog, QDialog, QListWidget,
    QDialogButtonBox, QFormLayout, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QFileDialog, QToolButton, QSizePolicy,
)
from PyQt6.QtCore import Qt, QProcess, QProcessEnvironment, pyqtSignal, QObject, QTimer, QSize
from PyQt6.QtGui import QFont, QTextCursor, QColor, QPalette

from core.paths import get_app_root

_APP_ROOT = os.path.dirname(__file__) if not getattr(sys, "frozen", False) else get_app_root()
sys.path.insert(0, _APP_ROOT)
_VENDOR = os.path.join(_APP_ROOT, "vendor")
if os.path.isdir(_VENDOR) and _VENDOR not in sys.path:
    sys.path.insert(0, _VENDOR)
from algorithms import create_algorithm
from codegen import (
    generate_code_from_steps,
    parse_code_to_steps,
    codegen_for_pipeline,
    get_codegen_role,
    blank_plugin_template,
    default_profile_match_yaml,
)
from core.http_message import HTTP_LOG_BEGIN, HTTP_LOG_END, HTTP_LOG_BLANK
from core.extension_registry import (
    EXTENSIONS_DIR, reload_extensions, list_extension_files,
    get_extension_choices, get_extension_op_types, get_meta,
    run_extension_test, new_extension_template, get_file_registered_names,
)
from core.ai_lab_tab import AILabTab
from core.brand import APP_TITLE
from core.home_tab import HomeTab
from core.cert_helper import install_https_cert, is_cert_trusted, cert_status_text, auto_install_if_needed
from core.match_dialog import MatchRulesDialog
from core.launch_checks import (
    is_port_in_use, port_in_use_message, check_roles, check_cert_before_decrypt,
    match_startup_tips, diagnose_proxy_line, exit_code_hint, load_profile,
    stop_qprocess, free_listen_port,
)
from core.settings_dialog import SettingsDialog
from core.settings_tab import SettingsHubTab
from core.project_name import normalize_project_name
from core.project_io import (
    ProjectPackageError,
    default_export_filename,
    export_project,
    import_project,
    inspect_package,
    package_extension,
    project_exists,
)
from core.icon_loader import set_btn_icon, apply_app_icon, app_icon, icon
from core.theme import (
    apply_theme, style_button, style_muted_label, style_status_label,
    setup_code_editor, setup_mono_field, build_logo_header, style_feedback, style_feedback_box,
    style_step_title, style_compact_button, style_sidebar_aux_button, setup_log_view, setup_main_tabs,
    setup_sub_tabs, repolish_widget,
    configure_combo_popup, pick_from_list,
    LOG_COLORS, HTTP_LOG_COLORS, C,
)

from core.paths import get_app_root

PROJECT_ROOT = get_app_root()
PROFILES_DIR = os.path.join(PROJECT_ROOT, "profiles")
PLUGINS_DIR = os.path.join(PROJECT_ROOT, "plugins")
MAIN_SCRIPT = os.path.join(PROJECT_ROOT, "main.py")


def _resolve_mitmdump() -> str:
    """优先使用绿色版同目录 mitmdump.exe."""
    import shutil
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


def _mitmdump_available() -> bool:
    path = _resolve_mitmdump()
    if path and path != "mitmdump" and os.path.isfile(path):
        return True
    import shutil
    return bool(shutil.which("mitmdump"))


def _profile_from_window(window=None) -> str:
    if window is not None and hasattr(window, "control"):
        return window.control.profile_combo.currentText()
    return ""


def get_plugin_script_path(profile_name: str) -> str:
    """当前项目 plugin.py 绝对路径 — mitmdump -s 直接加载."""
    if not profile_name:
        return ""
    plugin_name = get_plugin_name(profile_name) or profile_name
    return os.path.join(PLUGINS_DIR, plugin_name, "plugin.py")


def build_proxy_launch(
    profile: str,
    role: str,
    port: int,
    *,
    use_main: bool,
    burp_port: int = 8080,
) -> tuple[str, list[str], dict[str, str]]:
    """组装 mitmdump 入口脚本、参数与环境变量.

    解密端使用 --mode upstream 把流量交给 Burp，避免插件里再用 requests
    二次转发（易超时、Intercept 卡住、连接复用异常）。
    """
    env: dict[str, str] = {"PYTHONPATH": PROJECT_ROOT}
    args = ["-p", str(port), "--set", "flow_detail=0", "--ssl-insecure"]
    if role == "decrypt":
        env["BURP_PORT"] = str(burp_port)
        # 浏览器 → :decrypt_port → (upstream) Burp → 服务器
        args += ["--mode", f"upstream:http://127.0.0.1:{burp_port}"]
    if use_main:
        env["PROFILE"] = profile
        env["PROXY_ROLE"] = role
        script = MAIN_SCRIPT
        args = ["-s", script] + args
    else:
        script = get_plugin_script_path(profile)
        args = ["-s", script] + args
    return script, args, env


def get_plugin_name(profile_name: str) -> str:
    """profile 名 → plugins 子目录名."""
    if not profile_name:
        return ""
    path = os.path.join(PROFILES_DIR, f"{profile_name}.yaml")
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
            return cfg.get("plugin", profile_name)
        except yaml.YAMLError as e:
            logging.warning("profile YAML 解析失败 %s: %s", path, e)
            return profile_name
    return profile_name


def save_project_state(profile_name: str, raw_input: str = "") -> None:
    """持久化步骤/解析数据到 plugins/{plugin}/state.json."""
    if not profile_name:
        return
    plugin_name = get_plugin_name(profile_name) or profile_name
    plugin_dir = os.path.join(PLUGINS_DIR, plugin_name)
    os.makedirs(plugin_dir, exist_ok=True)
    state_path = os.path.join(plugin_dir, "state.json")
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump({
            "steps": shared_pipeline.steps,
            "parsed_fields": shared_pipeline.parsed_fields,
            "parsed_query": getattr(shared_pipeline, "parsed_query", {}),
            "body_format": getattr(shared_pipeline, "body_format", "json"),
            "raw_input": raw_input,
        }, f, ensure_ascii=False)

# ---- 共享数据模型 (请求解析器 ↔ 可视化构建器) ----
class SharedPipeline:
    """两个Tab共享的操作步骤列表 + 变更通知."""
    def __init__(self):
        self.steps = []         # [{type:, params:{}}]
        self.parsed_fields = {} # 解析器解析出的字段 {path: value}
        self.parsed_query = {}  # URL 查询参数 {key: value}
        self.body_format = "json"  # json | form | none
        self.listeners = []     # 变更回调
        self._plugin_code = ""  # 当前项目的插件代码

    def update_from_parser(self, steps: list, fields: dict):
        """解析器标记字段后，更新构建器步骤."""
        self.steps = steps
        self.parsed_fields = fields
        self._notify()

    def update_from_builder(self, steps: list):
        """构建器修改后，通知解析器刷新标记."""
        self.steps = steps
        self._notify()

    def _notify(self):
        for cb in self.listeners:
            try: cb()
            except: pass

    def listen(self, callback):
        self.listeners.append(callback)

shared_pipeline = SharedPipeline()

# 加解密测试 — 内置函数树（供 CryptoTab 使用）
CRYPTO_FUNC_TREE = {
    "时间相关": {
        "时间戳-毫秒": lambda: str(int(__import__("time").time() * 1000)),
        "时间戳-秒": lambda: str(int(__import__("time").time())),
        "年-月-日 时:分:秒": lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "编码": {
        "Base64编码": lambda t: base64.b64encode(t.encode()).decode(),
        "Base64解码": lambda t: base64.b64decode(t).decode(),
        "URL编码": lambda t: urllib.parse.quote(t),
        "URL解码": lambda t: urllib.parse.unquote(t),
        "Hex编码": lambda t: t.encode().hex(),
        "Hex解码": lambda t: bytes.fromhex(t).decode(),
    },
    "哈希": {
        "MD5": lambda t: hashlib.md5(t.encode()).hexdigest(),
        "MD5(16位)": lambda t: hashlib.md5(t.encode()).hexdigest()[8:24],
        "SHA1": lambda t: hashlib.sha1(t.encode()).hexdigest(),
        "SHA256": lambda t: hashlib.sha256(t.encode()).hexdigest(),
        "SM3": lambda t: sm3_hash(t.encode()),
    },
    "随机": {
        "字母+数字(16)": lambda: secrets.token_hex(8),
        "16字节hex": lambda: secrets.token_bytes(16).hex(),
    },
    "字符串": {
        "大写": lambda t: t.upper(),
        "小写": lambda t: t.lower(),
        "反转": lambda t: t[::-1],
    },
    "正则清洗": {
        "清除\\r\\n": lambda t: t.replace("\r", "").replace("\n", ""),
        "清除空白": lambda t: re.sub(r"\s+", "", t),
        "清除引号": lambda t: t.replace('"', "").replace("'", ""),
        "仅保留字母数字": lambda t: re.sub(r"[^a-zA-Z0-9]", "", t),
    },
}

# ---- 日志信号 ----
class LogSignal(QObject):
    append_log = pyqtSignal(str, str)
log_signal = LogSignal()


class ExtensionSignal(QObject):
    changed = pyqtSignal()
extension_signal = ExtensionSignal()


# ============================================================
# 左侧控制面板 (新架构 — 自动Profile匹配)
# ============================================================
class ControlPanel(QFrame):
    start_decrypt = pyqtSignal(int, str)
    stop_decrypt = pyqtSignal()
    start_encrypt = pyqtSignal(int, str)
    stop_encrypt = pyqtSignal()
    view_decrypt_log = pyqtSignal()
    view_encrypt_log = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sidebar")
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setMinimumWidth(256)
        self.setMaximumWidth(320)
        self._last_profile = ""
        self._build_ui()
        # 仅填充下拉列表, 不触发加载 (MainWindow 初始化完成后再加载)

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 12)
        layout.setSpacing(10)

        build_logo_header(layout)

        # ---- 项目 ----
        layout.addWidget(self._section_caption("项目"))
        project_box = QFrame()
        project_box.setObjectName("proxyRail")
        pj = QVBoxLayout(project_box)
        pj.setContentsMargins(10, 10, 10, 10)
        pj.setSpacing(8)

        row = QHBoxLayout()
        row.setSpacing(6)
        self.profile_combo = QComboBox()
        self.profile_combo.currentTextChanged.connect(self._on_profile_changed)
        row.addWidget(self.profile_combo, 1)

        new_btn = self._make_icon_toolbtn("add", "新建项目", self._new_project)
        row.addWidget(new_btn)

        more_btn = self._make_icon_toolbtn("more", "编辑 / 删除 / 导入导出")
        more_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        more_menu = QMenu(self)
        more_menu.addAction("编辑插件", self._edit_plugin)
        more_menu.addAction("删除项目", self._delete_project)
        more_menu.addSeparator()
        more_menu.addAction("导出项目…", self._export_project)
        more_menu.addAction("导入项目…", self._import_project)
        more_btn.setMenu(more_menu)
        row.addWidget(more_btn)
        pj.addLayout(row)

        self.project_empty_hint = QLabel("暂无项目，点「+」新建")
        self.project_empty_hint.setObjectName("projectEmptyHint")
        self.project_empty_hint.setWordWrap(True)
        self.project_empty_hint.hide()
        pj.addWidget(self.project_empty_hint)

        self.profile_role_label = QLabel("")
        style_muted_label(self.profile_role_label)
        self.profile_role_label.setWordWrap(True)
        pj.addWidget(self.profile_role_label)
        self.load_mode_combo = QComboBox(self)
        self.load_mode_combo.addItem("plugin.py 直接", "plugin")
        self.load_mode_combo.addItem("main.py 框架", "main")
        self.load_mode_combo.hide()
        layout.addWidget(project_box)

        # ---- 解密端 ----
        self.decrypt_section = self._section_caption("解密端")
        layout.addWidget(self.decrypt_section)
        self.decrypt_grp = QFrame()
        self.decrypt_grp.setObjectName("proxyRail")
        d = QVBoxLayout(self.decrypt_grp)
        d.setContentsMargins(10, 10, 10, 10)
        d.setSpacing(10)

        d_head = QHBoxLayout()
        d_head.setSpacing(8)
        self.decrypt_dot = QFrame()
        self.decrypt_dot.setObjectName("statusDot")
        self.decrypt_dot.setProperty("running", "false")
        d_head.addWidget(self.decrypt_dot, 0, Qt.AlignmentFlag.AlignVCenter)
        self.decrypt_status = QLabel("已停止")
        self.decrypt_status.setObjectName("proxyStatusText")
        style_status_label(self.decrypt_status, running=False)
        d_head.addWidget(self.decrypt_status, 1)
        d.addLayout(d_head)

        self.decrypt_start_btn = QPushButton("启动解密")
        self.decrypt_start_btn.setToolTip("启动解密端；运行中再点即停止")
        self.decrypt_start_btn.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        d.addWidget(self.decrypt_start_btn)

        d_ports = QHBoxLayout()
        d_ports.setSpacing(8)
        self.decrypt_port = QSpinBox()
        self.decrypt_port.setRange(1024, 65535)
        self.decrypt_port.setValue(8083)
        self.decrypt_port.setToolTip("浏览器/客户端代理指向此端口（解密端）")
        d_ports.addLayout(self._port_field("监听", self.decrypt_port), 1)
        self.burp_port = QSpinBox()
        self.burp_port.setRange(1024, 65535)
        self.burp_port.setValue(8080)
        self.burp_port.setToolTip("解密后的明文转发到此 Burp 端口")
        d_ports.addLayout(self._port_field("Burp", self.burp_port), 1)
        d.addLayout(d_ports)

        d_aux = QHBoxLayout()
        d_aux.setSpacing(2)
        self.decrypt_log_btn = self._make_icon_toolbtn(
            "log", "解密端日志", lambda: self.view_decrypt_log.emit()
        )
        d_aux.addWidget(self.decrypt_log_btn)
        self.browser_open_btn = self._make_icon_toolbtn(
            "browser", "打开代理浏览器（经解密端）", self._launch_proxy_browser
        )
        d_aux.addWidget(self.browser_open_btn)
        d_more = self._make_icon_toolbtn("more", "匹配规则 / HTTPS 证书")
        d_more.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        d_menu = QMenu(self)
        d_menu.addAction("匹配规则…", self._edit_match_rules)
        d_menu.addAction("安装 HTTPS 证书…", self._install_https_cert)
        d_more.setMenu(d_menu)
        d_aux.addWidget(d_more)
        d_aux.addStretch()
        self.cert_status = QLabel(cert_status_text())
        self.cert_status.setObjectName("proxyCertHint")
        style_muted_label(self.cert_status)
        self.cert_status.setWordWrap(False)
        d_aux.addWidget(self.cert_status)
        d.addLayout(d_aux)

        self._proxy_browser = None
        layout.addWidget(self.decrypt_grp)
        self.decrypt_start_btn.clicked.connect(self._toggle_decrypt)

        # ---- 加密端 ----
        self.encrypt_section = self._section_caption("加密端")
        layout.addWidget(self.encrypt_section)
        self.encrypt_grp = QFrame()
        self.encrypt_grp.setObjectName("proxyRail")
        e = QVBoxLayout(self.encrypt_grp)
        e.setContentsMargins(10, 10, 10, 10)
        e.setSpacing(10)

        e_head = QHBoxLayout()
        e_head.setSpacing(8)
        self.encrypt_dot = QFrame()
        self.encrypt_dot.setObjectName("statusDot")
        self.encrypt_dot.setProperty("running", "false")
        e_head.addWidget(self.encrypt_dot, 0, Qt.AlignmentFlag.AlignVCenter)
        self.encrypt_status = QLabel("已停止")
        self.encrypt_status.setObjectName("proxyStatusText")
        style_status_label(self.encrypt_status, running=False)
        e_head.addWidget(self.encrypt_status, 1)
        e.addLayout(e_head)

        self.encrypt_start_btn = QPushButton("启动加密")
        self.encrypt_start_btn.setToolTip("启动加密端；运行中再点即停止")
        self.encrypt_start_btn.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        e.addWidget(self.encrypt_start_btn)

        self.encrypt_port = QSpinBox()
        self.encrypt_port.setRange(1024, 65535)
        self.encrypt_port.setValue(8081)
        e.addLayout(self._port_field("端口", self.encrypt_port))

        e_aux = QHBoxLayout()
        e_aux.setSpacing(2)
        self.encrypt_log_btn = self._make_icon_toolbtn(
            "log", "加密端日志", lambda: self.view_encrypt_log.emit()
        )
        e_aux.addWidget(self.encrypt_log_btn)
        e_aux.addStretch()
        e.addLayout(e_aux)

        layout.addWidget(self.encrypt_grp)
        self.encrypt_start_btn.clicked.connect(self._toggle_encrypt)

        style_button(self.decrypt_start_btn, "primary")
        style_button(self.encrypt_start_btn, "default")
        set_btn_icon(self.decrypt_start_btn, "play")
        set_btn_icon(self.encrypt_start_btn, "play")

        # ---- Burp 连接检测（风格与加解密端一致：日志用图标打开）----
        self.burp_link_section = self._section_caption("Burp 连接")
        layout.addWidget(self.burp_link_section)
        self.burp_link_grp = QFrame()
        self.burp_link_grp.setObjectName("proxyRail")
        bl = QVBoxLayout(self.burp_link_grp)
        bl.setContentsMargins(10, 10, 10, 10)
        bl.setSpacing(10)

        bl_head = QHBoxLayout()
        bl_head.setSpacing(8)
        self.burp_link_dot = QFrame()
        self.burp_link_dot.setObjectName("statusDot")
        self.burp_link_dot.setProperty("running", "false")
        bl_head.addWidget(self.burp_link_dot, 0, Qt.AlignmentFlag.AlignVCenter)
        self.burp_link_status = QLabel("未检测")
        self.burp_link_status.setObjectName("proxyStatusText")
        style_status_label(self.burp_link_status, running=False)
        bl_head.addWidget(self.burp_link_status, 1)
        bl.addLayout(bl_head)

        self.burp_test_btn = QPushButton("测试连接")
        self.burp_test_btn.setToolTip(
            "检测：Burp 监听端口、CipherBridge 扩展 API、加密端端口"
        )
        self.burp_test_btn.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        self.burp_test_btn.clicked.connect(self._test_burp_connection)
        style_button(self.burp_test_btn, "default")
        set_btn_icon(self.burp_test_btn, "test")
        bl.addWidget(self.burp_test_btn)

        bl_aux = QHBoxLayout()
        bl_aux.setSpacing(2)
        self.burp_link_log_btn = self._make_icon_toolbtn(
            "log", "Burp 连接日志", self._open_burp_link_log
        )
        bl_aux.addWidget(self.burp_link_log_btn)
        bl_aux.addStretch()
        bl.addLayout(bl_aux)

        # 隐藏缓冲，供独立日志窗共享文档（与加解密端日志同交互）
        self.burp_link_log = QPlainTextEdit()
        self.burp_link_log.setReadOnly(True)
        self.burp_link_log.setMaximumBlockCount(200)
        self.burp_link_log.hide()
        self._burp_link_log_win = None

        layout.addWidget(self.burp_link_grp)

        self._update_project_ui_state()
        layout.addStretch(1)

    @staticmethod
    def _section_caption(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName("sidebarSection")
        return lbl

    @staticmethod
    def _port_field(label: str, spin: QSpinBox) -> QVBoxLayout:
        col = QVBoxLayout()
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(4)
        lbl = QLabel(label)
        lbl.setObjectName("proxyFieldLabel")
        col.addWidget(lbl)
        col.addWidget(spin)
        return col

    def _make_icon_toolbtn(self, icon_name: str, tip: str, slot=None) -> QToolButton:
        """侧栏小图标按钮（无文字）."""
        btn = QToolButton()
        btn.setToolTip(tip)
        btn.setAutoRaise(True)
        btn.setFixedSize(22, 22)
        btn.setIconSize(QSize(14, 14))
        btn.setIcon(icon(icon_name, size=16))
        btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonIconOnly)
        style_sidebar_aux_button(btn, icon_only=True)
        if slot is not None:
            btn.clicked.connect(slot)
        return btn

    def _set_status_dot(self, dot: QFrame | None, running: bool) -> None:
        if dot is None:
            return
        dot.setProperty("running", "true" if running else "false")
        from core.theme import repolish_widget
        repolish_widget(dot)

    def _toggle_decrypt(self) -> None:
        if self._decrypt_is_running():
            self.stop_decrypt.emit()
        else:
            self._choose_and_start("decrypt")

    def _toggle_encrypt(self) -> None:
        if self._encrypt_is_running():
            self.stop_encrypt.emit()
        else:
            self._choose_and_start("encrypt")

    def _burp_link_append(self, line: str) -> None:
        from datetime import datetime

        ts = datetime.now().strftime("%H:%M:%S")
        view = getattr(self, "burp_link_log", None)
        if view is None:
            return
        view.appendPlainText(f"[{ts}] {line}")

    def _open_burp_link_log(self) -> None:
        """弹出 Burp 连接日志窗（与加解密端日志按钮同交互）。"""
        win = getattr(self, "_burp_link_log_win", None)
        if win is not None and win.isVisible():
            win.raise_()
            win.activateWindow()
            return
        win = ProxyLogWindow("Burp 连接日志", self.burp_link_log, self.window())
        self._burp_link_log_win = win
        win.show()
        win.raise_()
        win.activateWindow()

    def _test_burp_connection(self) -> None:
        """检测 Burp 端口、扩展 API、加密端是否可达。"""
        from core.burp_upstream import burp_bridge_health, DEFAULT_BRIDGE_PORT
        from core.launch_checks import is_port_in_use

        burp_port = int(self.burp_port.value())
        enc_port = int(self.encrypt_port.value())
        self._burp_link_append("—— 开始检测 ——")

        ok_all = True

        # 1) Burp 代理端口
        if is_port_in_use(burp_port):
            self._burp_link_append(f"✓ Burp 监听 :{burp_port} 可达")
        else:
            ok_all = False
            self._burp_link_append(
                f"✗ Burp 端口 :{burp_port} 无进程（请先启动 Burp Proxy）"
            )

        # 2) CipherBridge Burp 扩展
        health = burp_bridge_health(DEFAULT_BRIDGE_PORT)
        if health and health.get("ok"):
            self._burp_link_append(
                f"✓ 扩展 API :{DEFAULT_BRIDGE_PORT} 正常"
                f"（{health.get('extension') or 'CipherBridge'}）"
            )
            st = health.get("status")
            if st:
                self._burp_link_append(f"  · 扩展状态: {st}")
        else:
            ok_all = False
            self._burp_link_append(
                f"✗ 扩展 API :{DEFAULT_BRIDGE_PORT} 不通"
                "（请在 Burp 加载 tools/burp/CipherBridge-Upstream.jar）"
            )

        # 3) 加密端（可选提示）
        if is_port_in_use(enc_port):
            self._burp_link_append(f"✓ 加密端 :{enc_port} 在听")
        else:
            self._burp_link_append(
                f"· 加密端 :{enc_port} 未启动（启动加密后可再测上游）"
            )

        # 汇总状态灯
        if ok_all:
            self.burp_link_status.setText("连接正常")
            style_status_label(self.burp_link_status, running=True)
            self._set_status_dot(self.burp_link_dot, True)
            self._burp_link_append("结果：Burp + 扩展 可用")
        else:
            self.burp_link_status.setText("异常 / 未就绪")
            style_status_label(self.burp_link_status, running=False)
            self._set_status_dot(self.burp_link_dot, False)
            self._burp_link_append("结果：尚有项未就绪，见日志")

        self._open_burp_link_log()

    def _encrypt_is_running(self) -> bool:
        return "运行中" in (self.encrypt_status.text() or "")

    def _sync_toggle_btn(self, btn: QPushButton, *, running: bool, role: str) -> None:
        """启停合一：切换文案 / 样式 / 图标."""
        if running:
            btn.setText("停止")
            style_button(btn, "danger")
            set_btn_icon(btn, "stop")
            btn.setToolTip(f"停止{role}")
        else:
            btn.setText(f"启动{role.replace('端', '')}" if role.endswith("端") else f"启动{role}")
            # 解密端主操作；加密端次要，避免双主色抢戏
            style_button(btn, "primary" if "解密" in role else "default")
            set_btn_icon(btn, "play")
            btn.setToolTip(f"启动{role}；运行中再点即停止")

    def _update_project_ui_state(self) -> None:
        """无项目时禁用启动按钮并显示引导；按角色显隐解密/加密区."""
        count = self.profile_combo.count()
        name = self.profile_combo.currentText()
        has_project = count > 0 and bool(name)
        roles = self._profile_roles(name) if has_project else []
        dec_running = self._decrypt_is_running()
        enc_running = self._encrypt_is_running()
        has_decrypt = "decrypt" in roles
        has_encrypt = "encrypt" in roles

        self.project_empty_hint.setVisible(count == 0)
        if count == 0:
            self.profile_role_label.setText("")

        # 无对应角色则折叠；若仍在运行则保留，便于停止
        show_decrypt = has_decrypt or dec_running or not has_project
        show_encrypt = has_encrypt or enc_running
        self.decrypt_grp.setVisible(show_decrypt)
        self.encrypt_grp.setVisible(show_encrypt)
        if hasattr(self, "decrypt_section"):
            self.decrypt_section.setVisible(show_decrypt)
        if hasattr(self, "encrypt_section"):
            self.encrypt_section.setVisible(show_encrypt)

        # 运行中始终可点停止；未运行需有项目且具备角色
        self.decrypt_start_btn.setEnabled((has_project and has_decrypt) or dec_running)
        self.encrypt_start_btn.setEnabled((has_project and has_encrypt) or enc_running)
        self._sync_toggle_btn(self.decrypt_start_btn, running=dec_running, role="解密端")
        self._sync_toggle_btn(self.encrypt_start_btn, running=enc_running, role="加密端")
        self._set_status_dot(getattr(self, "decrypt_dot", None), dec_running)
        self._set_status_dot(getattr(self, "encrypt_dot", None), enc_running)
        self._refresh_browser_hint()

        win = self.window()
        if hasattr(win, "home_tab"):
            win.home_tab.refresh_status(self)

    def _refresh_profiles(self):
        """刷新项目下拉列表."""
        current = self.profile_combo.currentText()
        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()
        if os.path.isdir(PROFILES_DIR):
            for f in sorted(os.listdir(PROFILES_DIR)):
                if f.endswith('.yaml') and not f.startswith('_'):
                    self.profile_combo.addItem(f.replace('.yaml', ''))
        self.profile_combo.blockSignals(False)
        if current and self.profile_combo.findText(current) >= 0:
            self.profile_combo.setCurrentText(current)
        self._on_profile_changed(self.profile_combo.currentText())
        self._update_project_ui_state()

    def _on_profile_changed(self, name: str):
        """选中项目时显示角色信息, 并保存/加载步骤状态和解析数据."""
        if not name:
            self._update_project_ui_state()
            return

        # 保存当前项目的状态到本地（已删除的项目不再写回）
        if self._last_profile:
            last_profile_path = os.path.join(PROFILES_DIR, f"{self._last_profile}.yaml")
            if os.path.exists(last_profile_path):
                try:
                    save_project_state(self._last_profile, getattr(self, "_last_raw", ""))
                except Exception as e:
                    logging.warning("保存项目状态失败: %s", e)

        self._last_profile = name

        try:
            path = os.path.join(PROFILES_DIR, f"{name}.yaml")
            if not os.path.exists(path):
                return
            with open(path, encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
            roles = cfg.get("roles", ["decrypt", "encrypt"])
            plugin = cfg.get("plugin", name)
            alg = cfg.get("request", {}).get("encryption", {}).get("algorithm", "?")
            role_txt = (
                "解密+加密" if ("decrypt" in roles and "encrypt" in roles)
                else ("解密" if "decrypt" in roles else "加密")
            )
            match = cfg.get("match", {})
            hosts = match.get("host") or []
            paths = match.get("path") or []
            match_bits = []
            if hosts:
                match_bits.append(",".join(str(h) for h in hosts[:2]))
            if paths:
                match_bits.append(str(paths[0]))
            match_txt = " ".join(match_bits) if match_bits else ""

            short = f"{role_txt}"
            if alg and alg != "?":
                short += f" · {alg}"
            if match_txt:
                short += f" · {match_txt}"
            full = f"插件: {plugin} | 算法: {alg} | {role_txt}"
            if match_txt:
                full += f" | 匹配: {match_txt}"
            self.profile_role_label.setText(short)
            self.profile_role_label.setToolTip(full)

            # 加载插件代码
            plugin_path = os.path.join(PLUGINS_DIR, plugin, "plugin.py")
            if os.path.exists(plugin_path):
                with open(plugin_path, encoding="utf-8") as f:
                    shared_pipeline._plugin_code = f.read()

            # 加载该项目保存的步骤和解析数据
            state_path = os.path.join(PLUGINS_DIR, plugin, "state.json")
            state_steps = None
            if os.path.exists(state_path):
                with open(state_path, encoding="utf-8") as f:
                    state = json.load(f)
                state_steps = state.get("steps", [])
                shared_pipeline.parsed_fields = state.get("parsed_fields", {})
                shared_pipeline.parsed_query = state.get("parsed_query", {})
                shared_pipeline.body_format = state.get("body_format", "json")
                self._last_raw = state.get("raw_input", "")
            else:
                # 新项目/无状态项目: 不残留旧项目的解析报文
                self._last_raw = ""

            # 优先用state中的步骤, 如果为空则从代码逆向生成
            if state_steps and len(state_steps) > 0:
                shared_pipeline.steps = state_steps
            elif os.path.exists(plugin_path):
                with open(plugin_path, encoding="utf-8") as f:
                    shared_pipeline.steps = parse_code_to_steps(f.read())
                # 保存逆向生成的步骤到state
                try:
                    with open(state_path, "w", encoding="utf-8") as f:
                        json.dump({"steps": shared_pipeline.steps, "parsed_fields": shared_pipeline.parsed_fields}, f)
                except Exception as e:
                    logging.warning("保存逆向步骤失败: %s", e)
            else:
                shared_pipeline.steps = []
                self._last_raw = self._last_raw or ""

            # 恢复或清空解析器
            main_win = self.window()
            if hasattr(main_win, 'parser_tab'):
                if self._last_raw:
                    main_win.parser_tab.raw_input.setPlainText(self._last_raw)
                    main_win.parser_tab._parse(keep_steps=True)
                else:
                    main_win.parser_tab.tree.clear()
                    main_win.parser_tab.raw_input.clear()
                    main_win.parser_tab._marked_encrypt.clear()
                main_win.parser_tab.mark_summary_label.setText("左键点击字段值添加加解密")
                if shared_pipeline._plugin_code:
                    main_win.parser_tab.code_preview.setPlainText(shared_pipeline._plugin_code)

            # 加载步骤到可视化构建器
            if hasattr(main_win, 'visual_builder_tab'):
                if shared_pipeline.steps:
                    main_win.visual_builder_tab._load_steps(shared_pipeline.steps)
                else:
                    main_win.visual_builder_tab._clear_all()
                    main_win.visual_builder_tab.code_preview.setPlainText(shared_pipeline._plugin_code)

            shared_pipeline._notify()
        except yaml.YAMLError as e:
            logging.warning("profile YAML 解析失败 %s: %s", path, e)
            self.profile_role_label.setText(f"配置错误: {name}.yaml 格式无效")
        except Exception:
            self.profile_role_label.setText("")
        self._update_project_ui_state()

    def set_decrypt_running(self, r: bool):
        if r:
            self.decrypt_status.setText("运行中")
            style_status_label(self.decrypt_status, running=True)
            self.decrypt_port.setEnabled(False)
            self.burp_port.setEnabled(False)
        else:
            self.decrypt_status.setText("已停止")
            style_status_label(self.decrypt_status, running=False)
            self.decrypt_port.setEnabled(True)
            self.burp_port.setEnabled(True)
        self._set_status_dot(getattr(self, "decrypt_dot", None), r)
        self._update_project_ui_state()
        self._refresh_browser_hint()

    def set_encrypt_running(self, r: bool):
        if r:
            self.encrypt_status.setText("运行中")
            style_status_label(self.encrypt_status, running=True)
            self.encrypt_port.setEnabled(False)
        else:
            self.encrypt_status.setText("已停止")
            style_status_label(self.encrypt_status, running=False)
            self.encrypt_port.setEnabled(True)
        self._set_status_dot(getattr(self, "encrypt_dot", None), r)
        self._update_project_ui_state()

    def _decrypt_is_running(self) -> bool:
        return "运行中" in (self.decrypt_status.text() or "")

    def _proxy_browser_home_url(self) -> str:
        """默认起始页：拓扑图 HTML（类似 Burp 打开内置浏览器）。"""
        from pathlib import Path
        from core.paths import get_app_root

        html = Path(get_app_root()) / "img" / "proxy_browser_home.html"
        if html.is_file():
            return html.resolve().as_uri()
        return "about:blank"

    def _refresh_browser_hint(self) -> None:
        btn = getattr(self, "browser_open_btn", None)
        if btn is None:
            return
        port = self.decrypt_port.value()
        running = bool(self._proxy_browser and self._proxy_browser.isRunning())
        if running:
            btn.setToolTip(f"代理浏览器运行中 → :{port}（关窗退出）")
            btn.setEnabled(False)
        elif self._decrypt_is_running():
            btn.setToolTip(f"打开代理浏览器（经解密端 :{port}）")
            btn.setEnabled(True)
        else:
            btn.setToolTip(f"打开代理浏览器（将代理到 :{port}，建议先启动解密端）")
            btn.setEnabled(True)

    def _launch_proxy_browser(self) -> None:
        if self._proxy_browser and self._proxy_browser.isRunning():
            QMessageBox.information(self, "提示", "代理浏览器已在运行")
            return
        if not self._decrypt_is_running():
            reply = QMessageBox.question(
                self,
                "解密端未启动",
                "建议先启动解密端，浏览器才会走加解密代理。\n\n仍要打开吗？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        port = int(self.decrypt_port.value())
        url = self._proxy_browser_home_url()
        from core.proxy_browser import ProxyBrowserWorker

        self._proxy_browser = ProxyBrowserWorker(port, url, parent=self)
        self._proxy_browser.log.connect(
            lambda m: log_signal.append_log.emit("INFO", f"[浏览器] {m}")
        )
        self._proxy_browser.failed.connect(self._on_proxy_browser_failed)
        self._proxy_browser.stopped.connect(self._on_proxy_browser_stopped)
        self._proxy_browser.start()
        self._refresh_browser_hint()
        log_signal.append_log.emit(
            "INFO",
            f"代理浏览器已指定代理 127.0.0.1:{port}（解密端监听端口，非 Burp :8080）",
        )

    def _stop_proxy_browser(self) -> None:
        if self._proxy_browser and self._proxy_browser.isRunning():
            self._proxy_browser.stop()
            btn = getattr(self, "browser_open_btn", None)
            if btn is not None:
                btn.setToolTip("正在关闭代理浏览器…")
                btn.setEnabled(False)

    def _on_proxy_browser_failed(self, err: str) -> None:
        log_signal.append_log.emit("ERROR", f"[浏览器] {err}")
        QMessageBox.warning(self, "启动浏览器失败", err)

    def _on_proxy_browser_stopped(self) -> None:
        self._proxy_browser = None
        self._refresh_browser_hint()

    def _profile_roles(self, name: str) -> list:
        """读取项目角色；缺省或空时按历史默认视为解密+加密."""
        if not name:
            return []
        path = os.path.join(PROFILES_DIR, f"{name}.yaml")
        if not os.path.exists(path):
            return []
        try:
            with open(path, encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
            roles = cfg.get("roles")
            if not roles:
                return ["decrypt", "encrypt"]
            return list(roles)
        except Exception:
            return ["decrypt", "encrypt"]

    def _open_settings(self):
        win = self.window()
        if win is not None and hasattr(win, "open_settings_hub"):
            win.open_settings_hub()
            return
        dlg = SettingsDialog(self, parent=self)
        dlg.exec()

    def _install_https_cert(self):
        install_https_cert(self.window())
        self.refresh_cert_status()

    def refresh_cert_status(self):
        self.cert_status.setText(cert_status_text())
        self._update_project_ui_state()

    def _choose_and_start(self, role: str):
        """弹出项目选择对话框, 用控制面板已设置的端口."""
        dlg = QDialog(self)
        dlg.setWindowTitle(f"选择项目 — {'解密端' if role == 'decrypt' else '加密端'}")
        dlg.setMinimumWidth(350)
        layout = QVBoxLayout(dlg)

        port = self.decrypt_port.value() if role == "decrypt" else self.encrypt_port.value()
        layout.addWidget(QLabel(f"选择项目 (端口 {port}, 在控制面板可修改):"))

        combo = QComboBox()
        combo.addItems([self.profile_combo.itemText(i) for i in range(self.profile_combo.count())])
        if self.profile_combo.currentText():
            combo.setCurrentText(self.profile_combo.currentText())
        layout.addWidget(combo)

        btn = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btn.accepted.connect(dlg.accept); btn.rejected.connect(dlg.reject)
        layout.addWidget(btn)

        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        profile = combo.currentText()
        ok, msg = check_roles(profile, role)
        if not ok:
            QMessageBox.warning(self, "角色不可用", msg)
            log_signal.append_log.emit("WARNING", msg.replace("\n", " | "))
            return
        if role == "decrypt":
            self.start_decrypt.emit(port, profile)
        else:
            self.start_encrypt.emit(port, profile)

    def _new_plugin(self):
        """旧方法兼容."""
        self._new_project()

    def _new_project(self):
        """新建项目 — 选择角色(解密/加密)."""
        dlg = QDialog(self); dlg.setWindowTitle("新建项目"); dlg.setMinimumWidth(350)
        fl = QFormLayout(dlg)
        name_edit = QLineEdit()
        name_edit.setPlaceholderText("如 my_app（自动转小写，中文/数字会规范化）")
        fl.addRow("项目名称:", name_edit)
        cb_decrypt = QCheckBox("🔓 解密 (监听解密端, 解密请求体)"); cb_decrypt.setChecked(True); fl.addRow(cb_decrypt)
        cb_encrypt = QCheckBox("🔒 加密 (8081加密端, 加密+签名)"); cb_encrypt.setChecked(False); fl.addRow(cb_encrypt)
        btn = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btn.accepted.connect(dlg.accept); btn.rejected.connect(dlg.reject); fl.addRow(btn)
        if dlg.exec() != QDialog.DialogCode.Accepted: return

        name = normalize_project_name(name_edit.text().strip())
        if not name:
            return
        roles = []
        if cb_decrypt.isChecked(): roles.append("decrypt")
        if cb_encrypt.isChecked(): roles.append("encrypt")

        # 创建插件目录和空白 mitmdump 模板（合法 HTTPFlow，可直接启动）
        plugin_dir = os.path.join(PLUGINS_DIR, name)
        os.makedirs(plugin_dir, exist_ok=True)
        plugin_path = os.path.join(plugin_dir, "plugin.py")
        content = blank_plugin_template(name)
        with open(plugin_path, "w", encoding="utf-8") as f: f.write(content)

        # 创建profile（默认匹配放宽，避免「启动了但完全没流量」）
        profile_path = os.path.join(PROFILES_DIR, f"{name}.yaml")
        with open(profile_path, "w", encoding="utf-8") as f:
            f.write(
                f"name: {name}\ndescription: ''\nplugin: {name}\nroles: {roles}\n"
                f"{default_profile_match_yaml()}"
            )

        # 清除所有旧数据 BEFORE refresh (否则refresh会加载旧项目的state)
        shared_pipeline.steps = []
        shared_pipeline.parsed_fields = {}
        shared_pipeline._plugin_code = content
        self._last_raw = ""  # 防止 _on_profile_changed 用旧项目报文恢复解析器
        shared_pipeline._notify()
        main_win = self.window()
        if hasattr(main_win, 'parser_tab'):
            main_win.parser_tab.raw_input.clear()
            main_win.parser_tab.tree.clear()
            main_win.parser_tab._marked_encrypt.clear()
            main_win.parser_tab.code_preview.setPlainText(content)
        if hasattr(main_win, 'visual_builder_tab'):
            main_win.visual_builder_tab._clear_all()
            main_win.visual_builder_tab.code_preview.setPlainText(content)

        # 刷新列表(跳过_on_profile_changed)
        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()
        if os.path.isdir(PROFILES_DIR):
            for f in sorted(os.listdir(PROFILES_DIR)):
                if f.endswith('.yaml') and not f.startswith('_'):
                    self.profile_combo.addItem(f.replace('.yaml', ''))
        self.profile_combo.blockSignals(False)
        self.profile_combo.setCurrentText(name)
        self._on_profile_changed(name)
        log_signal.append_log.emit("INFO", f"已创建项目: {name} (角色: {roles})")

    def _export_project(self) -> None:
        """导出当前项目为 .cbproj.zip."""
        name = self.profile_combo.currentText()
        if not name:
            QMessageBox.warning(self, "提示", "请先选择要导出的项目")
            return

        if self._last_profile:
            try:
                save_project_state(self._last_profile, getattr(self, "_last_raw", ""))
            except Exception as e:
                logging.warning("导出前保存状态失败: %s", e)

        dest, _ = QFileDialog.getSaveFileName(
            self,
            "导出项目",
            default_export_filename(name),
            f"密桥项目 (*{package_extension()});;ZIP 压缩包 (*.zip)",
        )
        if not dest:
            return

        try:
            files = export_project(
                name, dest, profiles_dir=PROFILES_DIR, plugins_dir=PLUGINS_DIR,
            )
        except ProjectPackageError as e:
            QMessageBox.warning(self, "导出失败", str(e))
            return

        QMessageBox.information(
            self, "导出成功",
            f"项目「{name}」已导出\n\n包含: {', '.join(files)}",
        )
        log_signal.append_log.emit("INFO", f"已导出项目: {name} → {dest}")

    def _import_project(self) -> None:
        """从 .cbproj.zip 导入项目."""
        src, _ = QFileDialog.getOpenFileName(
            self,
            "导入项目",
            "",
            f"密桥项目 (*{package_extension()});;ZIP 压缩包 (*.zip);;所有文件 (*.*)",
        )
        if not src:
            return

        try:
            info = inspect_package(src)
        except ProjectPackageError as e:
            QMessageBox.warning(self, "导入失败", str(e))
            return

        name = info["profile_name"]
        if not name:
            QMessageBox.warning(self, "导入失败", "项目包中未包含有效的项目名称")
            return

        roles = info.get("roles") or []
        role_text = ", ".join(roles) if roles else "未指定"
        state_hint = "含可视化步骤 (state.json)" if info["has_state"] else "无 state.json（可从 plugin.py 逆向）"
        desc = info.get("description") or ""
        summary = f"名称: {name}\n角色: {role_text}\n{state_hint}"
        if desc:
            summary += f"\n说明: {desc}"

        overwrite = False
        if project_exists(name, profiles_dir=PROFILES_DIR, plugins_dir=PLUGINS_DIR):
            reply = QMessageBox.question(
                self,
                "项目已存在",
                f"项目「{name}」已存在。\n\n{summary}\n\n是否覆盖？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Cancel:
                return
            if reply == QMessageBox.StandardButton.Yes:
                overwrite = True
            else:
                new_name, ok = QInputDialog.getText(
                    self, "重命名导入", "新项目名称:", text=f"{name}_import",
                )
                if not ok or not new_name.strip():
                    return
                name = normalize_project_name(new_name.strip())
                if not name:
                    QMessageBox.warning(self, "导入失败", "项目名称无效")
                    return
                if project_exists(name, profiles_dir=PROFILES_DIR, plugins_dir=PLUGINS_DIR):
                    QMessageBox.warning(self, "导入失败", f"项目「{name}」已存在，请换一个名称")
                    return

        try:
            imported = import_project(
                src,
                profiles_dir=PROFILES_DIR,
                plugins_dir=PLUGINS_DIR,
                profile_name=name,
                overwrite=overwrite,
            )
        except FileExistsError:
            QMessageBox.warning(self, "导入失败", f"项目「{name}」已存在")
            return
        except ProjectPackageError as e:
            QMessageBox.warning(self, "导入失败", str(e))
            return

        self._refresh_profiles()
        self.profile_combo.setCurrentText(imported)
        QMessageBox.information(self, "导入成功", f"项目「{imported}」已导入，可在请求解析器/可视化构建器中继续编辑。")
        log_signal.append_log.emit("INFO", f"已导入项目: {imported} ← {src}")

    def _delete_project(self):
        """删除当前选中的项目."""
        import shutil

        name = self.profile_combo.currentText()
        if not name:
            return
        plugin_name = get_plugin_name(name) or name
        reply = QMessageBox.question(
            self, "确认删除",
            f"确定要删除项目 '{name}' 吗?\n\n这将删除:\n"
            f"- plugins/{plugin_name}/\n"
            f"- profiles/{name}.yaml",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        errors: list[str] = []
        profile_path = os.path.join(PROFILES_DIR, f"{name}.yaml")
        if os.path.exists(profile_path):
            try:
                os.remove(profile_path)
            except OSError as e:
                errors.append(f"无法删除配置: {profile_path}\n{e}")

        for folder in dict.fromkeys((plugin_name, name)):
            plugin_dir = os.path.join(PLUGINS_DIR, folder)
            if not os.path.isdir(plugin_dir):
                continue
            try:
                shutil.rmtree(plugin_dir)
            except OSError as e:
                errors.append(f"无法删除插件目录: {plugin_dir}\n{e}")

        if getattr(self, "_last_profile", "") == name:
            self._last_profile = ""

        self._refresh_profiles()

        if errors:
            QMessageBox.warning(self, "删除不完整", "\n\n".join(errors))
            log_signal.append_log.emit("WARNING", f"项目 {name} 删除不完整")
        else:
            log_signal.append_log.emit("INFO", f"已删除项目: {name}")

    def _edit_match_rules(self):
        """打开匹配规则对话框 — 指定哪些流量走代理."""
        name = self.profile_combo.currentText()
        if not name:
            QMessageBox.warning(self, "提示", "请先选择项目")
            return
        dlg = MatchRulesDialog(name, proxy_port=self.decrypt_port.value(), parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._on_profile_changed(name)
            main_win = self.window()
            if hasattr(main_win, "visual_builder_tab") and shared_pipeline.steps:
                main_win.visual_builder_tab.code_preview.setPlainText(
                    codegen_for_pipeline(
                        shared_pipeline.steps,
                        shared_pipeline.body_format,
                        name,
                    )
                )
            log_signal.append_log.emit("INFO", f"已更新匹配规则: {name}")

    def _edit_plugin(self):
        name = self.profile_combo.currentText()
        if not name: return
        path = os.path.join(PROFILES_DIR, f"{name}.yaml")
        if not os.path.exists(path):
            QMessageBox.warning(self, "错误", f"配置文件不存在: {path}")
            return
        import subprocess, platform
        if platform.system() == "Windows":
            os.startfile(path)
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])


# ============================================================
# 请求解析器 Tab (保留, 增强 — 生成新架构插件代码)
# ============================================================
class RequestParserTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._parsed_fields = {}; self._parsed_query = {}; self._parsed_headers = {}; self._parsed_body = None
        self._parsed_response_fields = {}
        self._body_format = "json"
        self._marked_encrypt = {}; self._marked_sign_source = None; self._marked_sign_config = None
        self._build_ui()
        shared_pipeline.listen(self._pull_from_builder)  # 监听构建器变更

    def _on_tree_item_clicked(self, item, col):
        """左键点击字段值 → 弹出加解密配置对话框."""
        if item.childCount() > 0:  # 只响应叶子节点
            return
        name, val = item.text(0), item.text(1)
        if not val: return
        field_path = item.data(0, Qt.ItemDataRole.UserRole) or name
        self._selected_field = (field_path, val)
        scope = self._detect_field_scope(item)
        self._show_add_crypto_dialog(field_path, val, scope=scope)

    def _detect_field_scope(self, item) -> str:
        """根据树节点位置判断字段来源: body | form | query | response."""
        node = item
        while node:
            label = node.text(0)
            if label in ("Response Body", "Response"):
                return "response"
            if label == "Query":
                return "query"
            if label == "Body":
                return "form" if self._body_format == "form" else "body"
            node = node.parent()
        return "body"

    def load_captured_flow(self, flow: dict, *, keep_steps: bool = True) -> bool:
        """从 AI 实验室等来源加载单条流量并解析为可点击字段树."""
        from core.flow_format import flow_to_parser_raw, format_request_burp
        req = (flow.get("request_body") or "").strip()
        if not req and not (flow.get("url") or "").strip():
            return False
        raw = flow_to_parser_raw(flow)
        if not self.parse_response_chk.isChecked():
            # 未勾选「解析响应」: 只把请求放进解析器, 响应不写入输入框也不解析
            raw = format_request_burp(flow)
        self.raw_input.setPlainText(raw)
        self._parse(keep_steps=keep_steps)
        resp_n = len(self._parsed_response_fields)
        req_n = len(self._parsed_fields)
        self.mark_summary_label.setText(
            f"已加载流量 — 请求字段 {req_n} 个"
            + (f"，响应字段 {resp_n} 个" if resp_n else "")
            + " | 左键点击字段添加加解密"
        )
        style_feedback(self.mark_summary_label, "success")
        return True

    def _detect_body_format(self, headers: dict, body: str) -> str:
        ct = headers.get("Content-Type", headers.get("content-type", "")).lower()
        if "json" in ct:
            return "json"
        if "urlencoded" in ct or "form-urlencoded" in ct:
            return "form"
        if body:
            try:
                json.loads(body)
                return "json"
            except json.JSONDecodeError:
                if "=" in body and "&" in body or "=" in body:
                    return "form"
        return "none"

    def _show_add_crypto_dialog(self, field_name: str, field_value: str, scope: str = "body"):
        """弹出对话框: 从17种操作中选择, 填入参数, 加入共享管道."""
        from gui import VisualBuilderTab
        op_types = VisualBuilderTab.get_op_types()
        op_names = list(op_types.keys())

        dlg = QDialog(self); dlg.setWindowTitle(f"添加加解密 — {field_name}")
        dlg.setMinimumWidth(500)
        layout = QVBoxLayout(dlg)

        # 操作类型选择 — 用滚动列表对话框，避免下拉过长
        type_row = QHBoxLayout()
        type_row.addWidget(QLabel("操作类型:"))
        common_ops = ["🔓 解密字段","🔒 加密字段","🔓 解密响应字段","🔒 加密响应字段",
                      "📝 签名(Hash)","📝 签名(HMAC带密钥)",
                      "🔤 编码转换","🔗 拼接字符串","🔐 AuthToken生成","✂️ 正则清洗",
                      "🏷 设置Header","📦 设置Body字段","⏰ 生成时间戳","🎲 生成随机数",
                      "🔑 定义密钥(固定值)","🔑 提取密钥(从响应)","🔑 派生密钥(计算)",
                      "📝 签名(排序拼接)","✂️ 字符串切片","🔀 字符串反转"]
        other_ops = [n for n in op_names if n not in common_ops]
        ext_choices = get_extension_choices()
        op_sections = [("常用操作", common_ops)]
        if other_ops:
            op_sections.append(("其他操作", other_ops))
        if ext_choices:
            op_sections.append(("自定义扩展", ext_choices))
        looks_encrypted = len(field_value) > 20 and all(
            c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in field_value
        )
        if scope == "response":
            current_op = {"type": "🔓 解密响应字段" if looks_encrypted else "🔒 加密响应字段"}
        else:
            current_op = {"type": "🔓 解密字段" if looks_encrypted else "🔒 加密字段"}

        type_display = QLineEdit()
        type_display.setReadOnly(True)
        type_display.setText(current_op["type"])

        def pick_op_type():
            selected = pick_from_list(dlg, "选择操作类型", sections=op_sections)
            if selected:
                current_op["type"] = selected
                type_display.setText(selected)
                rebuild_params(selected)
                do_test()

        pick_btn = QPushButton("选择…")
        pick_btn.clicked.connect(pick_op_type)
        type_row.addWidget(type_display, 1)
        type_row.addWidget(pick_btn)
        layout.addLayout(type_row)

        # 参数区域 (动态)
        param_container = QWidget()
        param_layout_inner = QVBoxLayout(param_container); param_layout_inner.setContentsMargins(0,0,0,0)
        layout.addWidget(param_container)
        current_form = QFormLayout()

        def rebuild_params(op_type):
            nonlocal current_form
            # 删除旧表单
            while current_form.count():
                current_form.removeRow(0)
            # 重建
            for pname, pkey, ptype in op_types.get(op_type, []):
                if isinstance(ptype, list):
                    w = QComboBox(); w.addItems(ptype)
                    if len(ptype) > 12:
                        configure_combo_popup(w)
                    current_form.addRow(pname, w)
                else:
                    w = QLineEdit()
                    if "字段" in pname or "源" in pname or "路径" in pname:
                        w.setText(field_name)
                    elif "密钥" in pname.lower() or "key" in pkey.lower():
                        w.setPlaceholderText("输入密钥 或 $变量名")
                    elif "Header" in pname and "名" in pname:
                        w.setText("X-Sign")
                    elif "base_key" in pkey or "基础" in pname:
                        w.setPlaceholderText("输入密钥 或 $变量名")
                    current_form.addRow(pname, w)
            if param_layout_inner.count() == 0:
                param_layout_inner.addLayout(current_form)

        rebuild_params(current_op["type"])

        # 测试解密/加密预览区
        test_result = QLabel("")
        test_result.setWordWrap(True)
        style_feedback_box(test_result, "neutral")
        layout.addWidget(test_result)

        def _show_test(text: str, kind: str = "neutral"):
            test_result.setText(text)
            style_feedback_box(test_result, kind)

        def do_test():
            """用当前参数尝试加密/解密/编码真实字段值."""
            op = current_op["type"]
            # 收集参数
            t_params = {}
            for i in range(current_form.count()):
                item = current_form.itemAt(i, QFormLayout.ItemRole.FieldRole)
                label_item = current_form.itemAt(i, QFormLayout.ItemRole.LabelRole)
                if item and label_item:
                    pname = label_item.widget().text().rstrip(":")
                    for pn, pk, pt in op_types.get(op, []):
                        if pn == pname:
                            w = item.widget()
                            t_params[pk] = w.currentText() if isinstance(w, QComboBox) else w.text()
            # 处理编码操作
            if "编码" in op:
                enc = t_params.get("encode_type", "")
                try:
                    emap = {"Base64编码": lambda t: base64.b64encode(t.encode()).decode(),
                            "Base64解码": lambda t: base64.b64decode(t).decode(),
                            "Hex编码": lambda t: t.encode().hex(),
                            "Hex解码": lambda t: bytes.fromhex(t).decode(),
                            "URL编码": lambda t: urllib.parse.quote(t),
                            "URL解码": lambda t: urllib.parse.unquote(t)}
                    if enc in emap:
                        r = emap[enc](field_value)
                        _show_test(f"结果: {r[:200]}", "success")
                except Exception as e:
                    _show_test(f"❌ {e}", "error")
                return
            if op.startswith("🔌 "):
                meta = get_meta(op, t_params)
                if meta:
                    try:
                        t_params["extension_id"] = meta["id"]
                        result = run_extension_test(meta["id"], field_value, t_params)
                        _show_test(f"🔌 结果: {result[:200]}", "info")
                    except Exception as e:
                        _show_test(f"❌ {e}", "error")
                return
            if "加密" not in op and "解密" not in op:
                return
            key = t_params.get("key", "")
            if not key or key.startswith("$"):
                return
            algo_name = t_params.get("algo", "AES")
            mode = t_params.get("mode", "ECB")
            padding = t_params.get("padding", "PKCS7")
            try:
                algo = create_algorithm({
                    "algorithm": algo_name, "mode": mode, "key": key, "padding": padding,
                    "iv": t_params.get("iv", ""),
                    "input_fmt": t_params.get("input_fmt", "base64"),
                })
                if "解密" in op:
                    result = algo.decrypt(field_value)
                    _show_test(f"🔓 解密结果: {result}", "success")
                else:
                    result = algo.encrypt(field_value)
                    _show_test(f"🔒 加密结果: {result[:80]}...", "warn")
            except Exception as e:
                _show_test(f"❌ {e}", "error")

        # 按钮行: 测试 + OK/Cancel
        btn_row_dlg = QHBoxLayout()
        test_btn = QPushButton("测试")
        style_button(test_btn, "default")
        set_btn_icon(test_btn, "test")
        test_btn.setToolTip("用真实数据测试当前操作的加密/解密/编码结果")
        test_btn.clicked.connect(do_test)
        btn_row_dlg.addWidget(test_btn)
        btn_row_dlg.addStretch()
        btn = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btn.accepted.connect(dlg.accept); btn.rejected.connect(dlg.reject)
        btn_row_dlg.addWidget(btn)
        layout.addLayout(btn_row_dlg)

        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        # 验证AES密钥长度
        for pn, pk, pt in op_types[current_op["type"]]:
            if pk in ("key", "hmac_key", "base_key"):
                key_val = ""
                for i in range(current_form.count()):
                    item = current_form.itemAt(i, QFormLayout.ItemRole.FieldRole)
                    label_item = current_form.itemAt(i, QFormLayout.ItemRole.LabelRole)
                    if item and label_item and label_item.widget().text().rstrip(":") == pn:
                        if isinstance(item.widget(), QLineEdit):
                            key_val = item.widget().text()
                if key_val and not key_val.startswith("$"):
                    algo = ""
                    for i in range(current_form.count()):
                        item = current_form.itemAt(i, QFormLayout.ItemRole.FieldRole)
                        label_item = current_form.itemAt(i, QFormLayout.ItemRole.LabelRole)
                        if item and label_item and label_item.widget().text().rstrip(":") in ("算法",):
                            if isinstance(item.widget(), QComboBox):
                                algo = item.widget().currentText()
                    if algo == "AES" and len(key_val) not in (16, 24, 32):
                        QMessageBox.warning(self, "密钥长度警告",
                            f"AES 密钥必须为 16/24/32 字节\n当前密钥 '{key_val}' 长度为 {len(key_val)} 字节")
                        return
                    elif algo in ("DES","3DES") and len(key_val) not in (8, 16, 24):
                        QMessageBox.warning(self, "密钥长度警告",
                            f"{algo} 密钥长度不正确, 当前 {len(key_val)} 字节")
                        return

        # 收集参数
        op_type = current_op["type"]
        params = {}
        for i in range(current_form.count()):
            item = current_form.itemAt(i, QFormLayout.ItemRole.FieldRole)
            label_item = current_form.itemAt(i, QFormLayout.ItemRole.LabelRole)
            if item and label_item:
                pname = label_item.widget().text().rstrip(":")
                for pn, pk, pt in op_types[op_type]:
                    if pn == pname:
                        w = item.widget()
                        if isinstance(w, QComboBox):
                            params[pk] = w.currentText()
                        else:
                            params[pk] = w.text()

        # 加入共享管道
        scope_label = {"body": "📋 Body (JSON)", "form": "📋 Body (Form)", "query": "🔗 URL Query"}.get(scope, "📋 Body (JSON)")
        if "scope" in [k for _, k, _ in op_types.get(op_type, [])]:
            params["scope"] = scope_label
        if op_type.startswith("🔌 "):
            meta = get_meta(op_type, params)
            if meta:
                params["extension_id"] = meta["id"]
        new_step = {"type": op_type, "params": params}
        shared_pipeline.steps.append(new_step)
        shared_pipeline.update_from_builder(list(shared_pipeline.steps))

        # 更新本地标记 + 刷新树 + 刷新代码预览
        if "加密" in op_type:
            self._marked_encrypt[field_name] = (params.get("algo","AES"), params.get("mode","ECB"), params.get("key",""), params.get("padding","PKCS7"))
        elif "签名" in op_type:
            self._marked_sign_source = params.get("source", field_name)
            self._marked_sign_config = (params.get("algo","sha256"), params.get("target","signature"), params.get("key",""))

        self._refresh_marks()
        self.code_preview.setPlainText(codegen_for_pipeline(shared_pipeline.steps, shared_pipeline.body_format, _profile_from_window(self.window())))
        count = len(shared_pipeline.steps)
        self.mark_summary_label.setText(f"已添加 {count} 个步骤 | 继续点击其他字段添加更多 | 完成后点 [保存项目]")
        ctrl = self.window().control if hasattr(self.window(), "control") else None
        if ctrl and ctrl.profile_combo.currentText():
            try:
                save_project_state(ctrl.profile_combo.currentText(), getattr(ctrl, "_last_raw", ""))
            except Exception:
                pass

        # 智能提示: 如果添加了加密/解密字段, 检查是否有签名header需要处理
        if ("加密" in op_type or "解密" in op_type) and count == 1:
            sig_headers = [k for k, v in self._parsed_headers.items() if self._looks_like_hash(v)]
            if sig_headers:
                reply = QMessageBox.question(self, "智能建议",
                    f"检测到请求中包含签名Header:\n{', '.join(sig_headers[:3])}\n\n"
                    f"是否需要继续添加签名步骤？\n(点击「否」稍后手动添加, 或切到可视化构建器编辑)",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if reply == QMessageBox.StandardButton.Yes:
                    # 简化: 提示用户手动点击header添加签名
                    self.mark_summary_label.setText(f"请点击Headers下的签名字段添加签名步骤 | 当前 {count} 个步骤")

    def _build_ui(self):
        layout = QVBoxLayout(self); layout.setContentsMargins(8,8,8,8); layout.setSpacing(4)

        # 状态行
        bar = QHBoxLayout()
        self.mark_summary_label = QLabel("左键点击字段值添加加解密")
        style_muted_label(self.mark_summary_label)
        bar.addWidget(self.mark_summary_label)
        bar.addStretch()
        self.undo_btn = QPushButton("撤销"); self.undo_btn.setToolTip("撤销最后一步操作")
        self.undo_btn.clicked.connect(self._undo_last_step); bar.addWidget(self.undo_btn)
        self.save_btn = QPushButton("保存代码")
        self.save_btn.clicked.connect(self._generate_plugin_code); bar.addWidget(self.save_btn)
        self.test_btn = QPushButton("测试代码")
        self.test_btn.setToolTip("用当前报文执行生成的代码，弹出处理前后对比")
        self.test_btn.clicked.connect(self._test_plugin_code); bar.addWidget(self.test_btn)
        self.parse_response_chk = QCheckBox("解析响应")
        self.parse_response_chk.setToolTip("勾选后解析报文中的响应部分（HTTP/1.1 200 开头），显示在树中；默认只解析请求")
        self.parse_response_chk.setChecked(False)
        bar.addWidget(self.parse_response_chk)
        self.parse_btn = QPushButton("解析"); self.parse_btn.clicked.connect(self._parse)
        bar.addWidget(self.parse_btn)
        # 层级：解析=主操作；保存/测试=次要；撤销=弱
        style_button(self.undo_btn, "ghost")
        style_button(self.save_btn, "default")
        style_button(self.test_btn, "default")
        style_button(self.parse_btn, "primary")
        set_btn_icon(self.undo_btn, "undo")
        set_btn_icon(self.save_btn, "save")
        set_btn_icon(self.test_btn, "analyze")
        set_btn_icon(self.parse_btn, "search")
        layout.addLayout(bar)

        # === 主布局: 左(报文+树) | 右(代码预览) ===
        h_splitter = QSplitter(Qt.Orientation.Horizontal)

        # 左侧: 报文(上) + 解析树(下)
        left_panel = QWidget(); ll = QVBoxLayout(left_panel); ll.setContentsMargins(0,0,4,0); ll.setSpacing(4)
        self.raw_input = QPlainTextEdit()
        self.raw_input.setFont(QFont("Courier New", 10))
        self.raw_input.setPlaceholderText("粘贴 HTTP 请求报文（可带响应，需勾选「解析响应」才显示），点击 [解析]")
        self.raw_input.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.raw_input.customContextMenuRequested.connect(self._on_raw_context_menu)
        ll.addWidget(self.raw_input, 1)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["字段", "值"])
        self.tree.setColumnWidth(0, 160)
        self.tree.header().setStretchLastSection(True)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.tree.itemClicked.connect(self._on_tree_item_clicked)          # 左键点击 → 弹出加解密对话框
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._on_context_menu)
        ll.addWidget(self.tree, 2)

        h_splitter.addWidget(left_panel)

        # 右侧: 代码预览 (与可视化构建器完全一致)
        right_panel = QWidget(); rl = QVBoxLayout(right_panel); rl.setContentsMargins(4,0,0,0); rl.setSpacing(4)
        rl.addWidget(QLabel("生成的插件代码 (与可视化构建器同步)"))
        self.code_preview = QPlainTextEdit()
        self.code_preview.setFont(QFont("Cascadia Code", 11))
        setup_code_editor(self.code_preview)
        self.code_preview.setReadOnly(True)
        self.code_preview.setPlaceholderText("左键点击字段值 → 选择加解密方式 → 自动生成代码")
        self.code_preview.setMaximumBlockCount(3000)
        rl.addWidget(self.code_preview)
        self.copy_btn = QPushButton("复制代码"); self.copy_btn.clicked.connect(self._copy_parser_code); rl.addWidget(self.copy_btn)
        style_button(self.copy_btn, "ghost")
        set_btn_icon(self.copy_btn, "copy")
        h_splitter.addWidget(right_panel)
        h_splitter.setSizes([550, 650])

        layout.addWidget(h_splitter, 1)

    def _copy_parser_code(self):
        QApplication.clipboard().setText(self.code_preview.toPlainText())
        log_signal.append_log.emit("INFO","代码已复制到剪贴板")

    # ---- 测试生成的代码 ----
    def _test_plugin_code(self):
        """点击「测试代码」：用当前报文执行生成的代码，弹出处理前后对比."""
        code = self.code_preview.toPlainText().strip()
        raw = self.raw_input.toPlainText().strip()
        if not code or "def request(" not in code:
            QMessageBox.information(self, "测试", "请先左键点击字段添加加解密步骤，生成代码后再测试")
            return
        if not raw:
            QMessageBox.information(self, "测试", "请先粘贴 HTTP 请求报文")
            return
        try:
            before, after, resp_before, resp_after, notice = self._run_test_plugin(code, raw)
        except Exception as e:
            import traceback
            QMessageBox.critical(self, "测试执行失败", f"{e}\n\n{traceback.format_exc()}")
            return
        self._show_test_result(before, after, resp_before, resp_after, notice)

    def _run_test_plugin(self, code: str, raw: str) -> tuple[str, str, str, str, str]:
        """执行生成的插件代码，返回 (请求处理前, 请求处理后, 响应处理前, 响应处理后, 提示).

        纯逻辑无 UI，供按钮与离屏测试调用。请求报文里带响应块时会构造响应一并测试
        （含生成代码中的 response() 钩子）。
        """
        from mitmproxy import http
        from mitmproxy.test.tflow import tflow
        from core.flow_format import split_request_response_body
        from core.http_message import format_request, format_response

        raw = raw.replace("\r\n", "\n").replace("\r", "\n")
        lines = raw.split("\n")
        first_line = lines[0].strip()
        parts = first_line.split(" ", 2)
        method = parts[0] if parts else "POST"
        path = parts[1] if len(parts) > 1 else "/"
        header_section, _, body_section = raw.partition("\n\n")
        req_body, resp_block = split_request_response_body(body_section.strip())

        headers: dict[str, str] = {}
        for line in header_section.split("\n")[1:]:
            line = line.strip()
            if line and ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        # HTTP header 名大小写不敏感：优先取报文的 Host（小写 host 常见）
        host = ""
        for k, v in headers.items():
            if k.lower() == "host":
                host = v.strip()
                break
        url = f"http://{host or 'localhost'}{path}"
        req = http.Request.make(method, url, req_body.encode("utf-8"), headers)
        flow = tflow(req=req)
        if resp_block:
            flow.response = _build_mock_response(resp_block)

        before = format_request(flow)
        resp_before = format_response(flow) if flow.response else ""

        # 生成代码依赖 sdk 与 core.match_rules，需项目根在 sys.path
        root = _APP_ROOT
        if root not in sys.path:
            sys.path.insert(0, root)
        ns = {
            "__name__": "_cipherbridge_test_plugin",
            "__file__": os.path.join(PLUGINS_DIR, "_cipherbridge_test_tmp.py"),
        }
        exec(compile(code, "<cipherbridge-test>", "exec"), ns)
        fn = ns.get("request")
        if not callable(fn):
            raise RuntimeError("生成代码中没有可调用的 request(flow) 函数")

        fn(flow)

        # 报文带响应且生成代码含 response() 钩子时一并执行
        if resp_block and callable(ns.get("response")):
            ns["response"](flow)

        after = format_request(flow)
        resp_after = format_response(flow) if flow.response else ""
        notice = ""
        if after == before and (resp_after == resp_before):
            notice = "请求未被修改 —— 可能未匹配 MATCH_RULES 规则，或当前步骤对请求无实际效果"
        return before, after, resp_before, resp_after, notice

    def _show_test_result(self, before: str, after: str, resp_before: str = "", resp_after: str = "", notice: str = ""):
        """展示处理前后报文对比对话框."""
        dlg = QDialog(self)
        dlg.setWindowTitle("测试生成代码")
        dlg.setMinimumSize(780, 540)
        v = QVBoxLayout(dlg)
        if notice:
            v.addWidget(QLabel(notice))
        tabs = QTabWidget()
        for title, text in (("处理前", before), ("处理后", after)):
            e = QPlainTextEdit()
            e.setReadOnly(True)
            e.setFont(QFont("Courier New", 10))
            e.setPlainText(text)
            tabs.addTab(e, title)
        tabs.setCurrentIndex(1)
        v.addWidget(tabs, 1)
        if resp_before or resp_after:
            resp_tabs = QTabWidget()
            for title, text in (("响应处理前", resp_before), ("响应处理后", resp_after)):
                e = QPlainTextEdit()
                e.setReadOnly(True)
                e.setFont(QFont("Courier New", 10))
                e.setPlainText(text)
                resp_tabs.addTab(e, title)
            resp_tabs.setCurrentIndex(1)
            v.addWidget(resp_tabs, 1)
        btns = QDialogButtonBox()
        copy_btn = QPushButton("复制处理后请求")
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(after))
        btns.addButton(copy_btn, QDialogButtonBox.ButtonRole.ActionRole)
        btns.addButton(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(dlg.accept)
        v.addWidget(btns)
        dlg.exec()

    def _mark_feedback(self, text: str, kind: str = "success") -> None:
        self.mark_summary_label.setText(text)
        style_feedback(self.mark_summary_label, kind)

    # ---- 解析 ----
    def _parse(self, keep_steps=False, include_response: bool | None = None):
        """解析粘贴的 HTTP 报文.

        include_response=None 时按「解析响应」复选框决定是否解析响应块；
        True/False 强制开关（AI 流量加载等调用方显式控制）。
        """
        raw = self.raw_input.toPlainText().strip()
        if not raw: return
        self.tree.clear(); self._parsed_fields = {}; self._parsed_query = {}; self._parsed_headers = {}; self._parsed_body = None
        self._parsed_response_fields = {}
        self._marked_encrypt.clear(); self._marked_sign_source = None; self._marked_sign_config = None
        if not keep_steps:
            shared_pipeline.steps = []
            shared_pipeline.parsed_fields = {}
            shared_pipeline.parsed_query = {}
            shared_pipeline._notify()
        self.mark_summary_label.setText("")
        try:
            # 统一换行符
            raw = raw.replace("\r\n", "\n").replace("\r", "\n")
            lines = raw.split("\n"); first_line = lines[0].strip()
            body_start = raw.find("\n\n")
            sep_len = 2
            header_section = raw[:body_start] if body_start != -1 else ""
            body_section = raw[body_start + sep_len:].strip() if body_start != -1 else ""

            from core.flow_format import split_request_response_body
            req_body_section, resp_block = split_request_response_body(body_section)

            root = QTreeWidgetItem(self.tree, ["请求/响应信息", ""])
            req_url = ""
            if " " in first_line:
                parts = first_line.split(" ", 2)
                self._parsed_method = parts[0] if len(parts) > 0 else ""
                req_url = parts[1] if len(parts) > 1 else ""
                QTreeWidgetItem(root, ["方法", self._parsed_method])
                QTreeWidgetItem(root, ["URL", req_url])

            header_item = QTreeWidgetItem(root, ["Headers", ""])
            for line in header_section.split("\n")[1:]:
                line = line.strip()
                if line and ":" in line:
                    k, v = line.split(":", 1); k, v = k.strip(), v.strip()
                    self._parsed_headers[k] = v
                    hi = QTreeWidgetItem(header_item, [k, v])
                    if self._looks_like_hash(v):
                        hi.setToolTip(1, self._hash_hint(v)); hi.setForeground(1, QColor("#FF9800"))

            # 解析 URL Query 参数
            if req_url and "?" in req_url:
                query_item = QTreeWidgetItem(root, ["Query", ""])
                parsed = urllib.parse.urlparse(req_url)
                for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
                    QTreeWidgetItem(query_item, [k, v])
                    self._parsed_query[k] = v

            self._body_format = self._detect_body_format(self._parsed_headers, req_body_section)
            fmt_label = {"json": "JSON", "form": "Form", "none": "无"}.get(self._body_format, "JSON")
            QTreeWidgetItem(root, ["Body格式", fmt_label])

            if req_body_section:
                body_item = QTreeWidgetItem(root, ["Body", f"({fmt_label})"]); self._parsed_body = req_body_section
                if self._body_format == "json":
                    try:
                        body_obj = json.loads(req_body_section)
                        self._add_json_to_tree(body_obj, body_item)
                    except json.JSONDecodeError:
                        QTreeWidgetItem(body_item, ["原始", req_body_section[:200]])
                elif self._body_format == "form":
                    for k, v in urllib.parse.parse_qsl(req_body_section, keep_blank_values=True):
                        QTreeWidgetItem(body_item, [k, v]); self._parsed_fields[k] = v
                else:
                    QTreeWidgetItem(body_item, ["原始", req_body_section[:200]])

            if include_response is None:
                include_response = self.parse_response_chk.isChecked()

            if resp_block and include_response:
                self._parse_response_block(resp_block, root)

            # 保存当前原始报文到控制面板 + 共享管道, 以便切换项目时恢复
            self.window().control._last_raw = raw
            shared_pipeline.parsed_fields = dict(self._parsed_fields)
            shared_pipeline.parsed_query = dict(self._parsed_query)
            shared_pipeline.body_format = self._body_format

            self.tree.expandAll()
            fmt_info = f" | Body:{fmt_label}" + (f" | Query:{len(self._parsed_query)}项" if self._parsed_query else "")
            if self._parsed_response_fields:
                fmt_info += f" | 响应字段:{len(self._parsed_response_fields)}"
            log_signal.append_log.emit("INFO", f"解析完成{fmt_info}")
        except Exception as e:
            QMessageBox.critical(self, "解析错误", str(e))

    def _parse_response_block(self, resp_block: str, root: QTreeWidgetItem) -> None:
        lines = resp_block.replace("\r\n", "\n").split("\n")
        status = "200"
        if lines and lines[0].strip().upper().startswith("HTTP/"):
            m = re.match(r"HTTP/\d\.\d\s+(\d+)", lines[0].strip(), re.I)
            if m:
                status = m.group(1)
        resp_headers: dict[str, str] = {}
        i = 1
        while i < len(lines) and lines[i].strip():
            line = lines[i].strip()
            if ":" in line:
                k, v = line.split(":", 1)
                resp_headers[k.strip()] = v.strip()
            i += 1
        resp_body = "\n".join(lines[i + 1:]).strip() if i < len(lines) else ""

        resp_root = QTreeWidgetItem(root, ["Response", ""])
        QTreeWidgetItem(resp_root, ["状态码", status])
        if resp_headers:
            rh_item = QTreeWidgetItem(resp_root, ["Response Headers", ""])
            for k, v in resp_headers.items():
                QTreeWidgetItem(rh_item, [k, v])
        resp_fmt = self._detect_body_format(resp_headers, resp_body)
        resp_label = {"json": "JSON", "form": "Form", "none": "无"}.get(resp_fmt, "JSON")
        if resp_body:
            rb_item = QTreeWidgetItem(resp_root, ["Response Body", f"({resp_label})"])
            if resp_fmt == "json":
                try:
                    self._add_json_to_tree(
                        json.loads(resp_body), rb_item, fields=self._parsed_response_fields,
                    )
                except json.JSONDecodeError:
                    QTreeWidgetItem(rb_item, ["原始", resp_body[:200]])
            elif resp_fmt == "form":
                for k, v in urllib.parse.parse_qsl(resp_body, keep_blank_values=True):
                    leaf = QTreeWidgetItem(rb_item, [k, v])
                    leaf.setData(0, Qt.ItemDataRole.UserRole, k)
                    self._parsed_response_fields[k] = v
            else:
                QTreeWidgetItem(rb_item, ["原始", resp_body[:200]])

    def _add_json_to_tree(self, obj, parent, prefix="", fields=None):
        if fields is None:
            fields = self._parsed_fields
        if isinstance(obj, dict):
            for k, v in obj.items():
                path = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    self._add_json_to_tree(v, QTreeWidgetItem(parent, [k, ""]), path, fields=fields)
                else:
                    leaf = QTreeWidgetItem(parent, [k, str(v)])
                    leaf.setData(0, Qt.ItemDataRole.UserRole, path)
                    fields[path] = str(v)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                path = f"{prefix}[{i}]"
                if isinstance(v, (dict, list)):
                    self._add_json_to_tree(v, QTreeWidgetItem(parent, [f"[{i}]", ""]), path, fields=fields)
                else:
                    leaf = QTreeWidgetItem(parent, [f"[{i}]", str(v)])
                    leaf.setData(0, Qt.ItemDataRole.UserRole, path)
                    fields[path] = str(v)

    # ---- 上下文菜单 ----
    def _on_raw_context_menu(self, pos):
        cursor = self.raw_input.textCursor(); selected = cursor.selectedText().strip()
        menu = QMenu(self)
        if selected:
            menu.addAction(f"选中: {selected[:40]}...").setEnabled(False); menu.addSeparator()
            enc_menu = menu.addMenu("🔒 标记为加密")
            for a in ["AES/ECB","AES/CBC","DES/ECB","3DES/ECB","SM4/ECB","RSA/OAEP"]:
                parts = a.split("/")
                enc_menu.addAction(a).triggered.connect(lambda checked, al=parts[0], mo=parts[1]: self._annotate_selected(al, mo))
            enc_menu.addAction("自定义...").triggered.connect(self._annotate_custom)
            code_menu = menu.addMenu("编码转换")
            for act in ["Base64编码","Base64解码","URL编码","URL解码","Hex编码","Hex解码"]:
                code_menu.addAction(act).triggered.connect(lambda checked, a=act: self._apply_to_selected(a))
            hash_menu = menu.addMenu("哈希计算")
            for act in ["MD5","SHA1","SHA256","SHA512","SM3"]:
                hash_menu.addAction(act).triggered.connect(lambda checked, a=act: self._apply_to_selected(a))
            menu.addSeparator(); menu.addAction("解密选中文本").triggered.connect(self._decrypt_selected)
        else:
            menu.addAction("请先选中文本").setEnabled(False); menu.addSeparator()
            menu.addAction("解密选中文本").triggered.connect(self._decrypt_selected)
        menu.exec(self.raw_input.viewport().mapToGlobal(pos))

    def _on_context_menu(self, pos):
        item = self.tree.itemAt(pos)
        if not item or item.childCount()>0: return
        name, val = item.text(0), item.text(1)
        if not val: return
        self._selected_field = (name, val)
        menu = QMenu(self)
        parent = item.parent()
        is_header = parent and parent.text(0) == "Headers"

        # 签名验证 (仅Header的哈希值)
        if is_header and self._looks_like_hash(val):
            vmenu = menu.addMenu("验证签名")
            for a in ["md5","sha1","sha256","sha512","sm3"]:
                vmenu.addAction(a.upper()).triggered.connect(lambda checked, al=a: self._verify_signature(al))
            vmenu.addAction("全部自动匹配").triggered.connect(self._auto_match_signature); menu.addSeparator()

        # 左键已处理加解密标记, 右键菜单保留快速测试和工具
        menu.addAction("🔓 解密测试(输密钥)").triggered.connect(self._quick_decrypt)
        menu.addAction("🔒 加密测试(输密钥)").triggered.connect(self._quick_encrypt)
        if name in self._marked_encrypt:
            menu.addAction("✗ 移除此字段标记").triggered.connect(lambda: self._unmark_encrypt(name))
        menu.addSeparator()
        em = menu.addMenu("编码转换")
        for act in ["Base64编码","Base64解码","URL编码","URL解码","Hex编码","Hex解码"]:
            em.addAction(act).triggered.connect(lambda checked, a=act: self._quick_encode(a))
        hm = menu.addMenu("哈希计算")
        for act in ["MD5","SHA1","SHA256","SHA512","SM3"]:
            hm.addAction(act).triggered.connect(lambda checked, a=act: self._quick_hash(a))
        rm = menu.addMenu("正则清洗")
        for act in ["清除\\r\\n","清除空白字符","清除引号","仅保留字母数字"]:
            rm.addAction(act).triggered.connect(lambda checked, a=act: self._quick_regex(a))
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    # ---- 标注方法 ----
    def _annotate_selected(self, algo, mode):
        cursor = self.raw_input.textCursor(); original = cursor.selectedText()
        if not original: return
        stripped = original.strip().strip('"').strip("'")
        dlg = QDialog(self); dlg.setWindowTitle(f"标记加密 — {algo}/{mode}"); fl = QFormLayout(dlg)
        key_edit = QLineEdit(); fl.addRow("密钥:", key_edit)
        pad_cb = QComboBox(); pad_cb.addItems(["PKCS7","ZeroPadding","NoPadding"]); fl.addRow("填充:", pad_cb)
        btn = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btn.accepted.connect(dlg.accept); btn.rejected.connect(dlg.reject); fl.addRow(btn)
        if dlg.exec() != QDialog.DialogCode.Accepted: return
        key = key_edit.text().strip(); pad = pad_cb.currentText()
        cursor.insertText(f"{{{{{stripped}}}}}X({algo}({mode},{pad})={key})")

    def _annotate_custom(self):
        cursor = self.raw_input.textCursor(); original = cursor.selectedText()
        if not original: return
        dlg = QDialog(self); dlg.setWindowTitle("自定义加密标注"); fl = QFormLayout(dlg)
        algo_cb = QComboBox(); algo_cb.addItems(["AES","DES","3DES","SM4","RSA","SM2","XOR"])
        mode_cb = QComboBox(); mode_cb.addItems(["ECB","CBC","CFB","OFB","CTR","GCM","OAEP","PKCS1v15"])
        key_edit = QLineEdit()
        pad_cb = QComboBox(); pad_cb.addItems(["PKCS7","ZeroPadding","NoPadding","ISO10126"])
        fl.addRow("算法:", algo_cb); fl.addRow("模式:", mode_cb); fl.addRow("密钥:", key_edit); fl.addRow("填充:", pad_cb)
        btn = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btn.accepted.connect(dlg.accept); btn.rejected.connect(dlg.reject); fl.addRow(btn)
        if dlg.exec() != QDialog.DialogCode.Accepted: return
        clean = original.strip().strip('"').strip("'")
        cursor.insertText(f"{{{{{clean}}}}}X({algo_cb.currentText()}({mode_cb.currentText()},{pad_cb.currentText()})={key_edit.text().strip()})")

    def _apply_to_selected(self, action):
        cursor = self.raw_input.textCursor(); text = cursor.selectedText().strip()
        if not text: return
        try:
            result = {
                "Base64编码":lambda t:base64.b64encode(t.encode()).decode(),
                "Base64解码":lambda t:base64.b64decode(t).decode(),
                "URL编码":lambda t:urllib.parse.quote(t),
                "URL解码":lambda t:urllib.parse.unquote(t),
                "Hex编码":lambda t:t.encode().hex(),
                "Hex解码":lambda t:bytes.fromhex(t).decode(),
                "MD5":lambda t:hashlib.md5(t.encode()).hexdigest(),
                "SHA1":lambda t:hashlib.sha1(t.encode()).hexdigest(),
                "SHA256":lambda t:hashlib.sha256(t.encode()).hexdigest(),
                "SHA512":lambda t:hashlib.sha512(t.encode()).hexdigest(),
                "SM3":lambda t:sm3_hash(t.encode()),
            }[action](text)
            cursor.insertText(result)
        except Exception as e: QMessageBox.critical(self, "失败", str(e))

    def _decrypt_selected(self):
        cursor = self.raw_input.textCursor(); text = cursor.selectedText().strip().strip('"').strip("'")
        if not text: return
        try:
            algo = self._get_decrypt_algo()
            if not algo: return
            result = algo.decrypt(text); cursor.insertText(result)
            self._mark_feedback(f"[解密]\n{result}", "success")
        except Exception as e:
            self._mark_feedback(f"[失败] {e}", "error")

    # ---- 标记方法 (简化) ----
    def _get_selected_value(self): return self._selected_field[1] if hasattr(self,'_selected_field') else ""
    def _get_selected_name(self): return self._selected_field[0] if hasattr(self,'_selected_field') else ""
    def _get_decrypt_algo(self):
        """弹出密钥输入框, 返回算法对象."""
        dlg = QDialog(self); dlg.setWindowTitle("输入解密密钥"); fl = QFormLayout(dlg)
        algo_cb = QComboBox(); algo_cb.addItems(["AES","DES","3DES","SM4","RSA","SM2","XOR"]); fl.addRow("算法:", algo_cb)
        mode_cb = QComboBox(); mode_cb.addItems(["ECB","CBC","CFB","OFB","CTR","GCM"]); fl.addRow("模式:", mode_cb)
        key_edit = QLineEdit(); key_edit.setPlaceholderText("输入密钥"); fl.addRow("密钥:", key_edit)
        btn = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btn.accepted.connect(dlg.accept); btn.rejected.connect(dlg.reject); fl.addRow(btn)
        if dlg.exec() != QDialog.DialogCode.Accepted: return None
        return create_algorithm({"algorithm":algo_cb.currentText(),"mode":mode_cb.currentText(),"key":key_edit.text().strip() or "test","padding":"PKCS7"})

    def _quick_decrypt(self):
        algo = self._get_decrypt_algo()
        if not algo: return
        try: r=algo.decrypt(self._get_selected_value()); self._mark_feedback(f"解密: {r[:60]}", "success")
        except Exception as e: self._mark_feedback(f"解密失败: {e}", "error")

    def _quick_encrypt(self):
        algo = self._get_decrypt_algo()
        if not algo: return
        try: r=algo.encrypt(self._get_selected_value()); self._mark_feedback(f"加密: {r[:60]}", "warn")
        except Exception as e: self._mark_feedback(f"加密失败: {e}", "error")

    def _quick_encode(self, action):
        v=self._get_selected_value()
        if not v: return
        try:
            r={"Base64编码":lambda t:base64.b64encode(t.encode()).decode(),"Base64解码":lambda t:base64.b64decode(t).decode(),"URL编码":lambda t:urllib.parse.quote(t),"URL解码":lambda t:urllib.parse.unquote(t),"Hex编码":lambda t:t.encode().hex(),"Hex解码":lambda t:bytes.fromhex(t).decode()}[action](v)
            self._mark_feedback(f"[{action}]\n{r}", "success")
        except Exception as e: self._mark_feedback(f"[错误] {e}", "error")

    def _quick_hash(self, action):
        v=self._get_selected_value()
        if not v: return
        try:
            r={"MD5":lambda t:hashlib.md5(t.encode()).hexdigest(),"SHA1":lambda t:hashlib.sha1(t.encode()).hexdigest(),"SHA256":lambda t:hashlib.sha256(t.encode()).hexdigest(),"SHA512":lambda t:hashlib.sha512(t.encode()).hexdigest(),"SM3":lambda t:sm3_hash(t.encode())}[action](v)
            self._mark_feedback(f"[{action}]\n{r}", "success")
        except Exception as e: self._mark_feedback(f"[错误] {e}", "error")

    def _quick_regex(self, action):
        v=self._get_selected_value()
        if not v: return
        r={"清除\\r\\n":lambda t:t.replace('\r','').replace('\n',''),"清除空白字符":lambda t:re.sub(r'\s+','',t),"清除引号":lambda t:t.replace('"','').replace("'",''),"仅保留字母数字":lambda t:re.sub(r'[^a-zA-Z0-9]','',t)}[action](v)
        self._mark_feedback(f"[{action}]\n{r}", "success")

    def _mark_encrypt(self, algo, mode):
        n=self._get_selected_name()
        if not n: return
        key="YOUR-KEY"
        self._marked_encrypt[n]=(algo,mode,key,"PKCS7"); self._refresh_marks()
        self._push_to_builder()

    def _mark_encrypt_custom(self):
        n=self._get_selected_name()
        if not n: return
        dlg=QDialog(self); dlg.setWindowTitle("自定义加密参数"); fl=QFormLayout(dlg)
        ac=QComboBox(); ac.addItems(["AES","DES","3DES","SM4","RSA","SM2","XOR"])
        mc=QComboBox(); mc.addItems(["ECB","CBC","CFB","OFB","CTR","GCM","OAEP","PKCS1v15"])
        ke=QLineEdit()
        pc=QComboBox(); pc.addItems(["PKCS7","ZeroPadding","NoPadding","ISO10126"])
        fl.addRow("字段:",QLabel(n)); fl.addRow("算法:",ac); fl.addRow("模式:",mc); fl.addRow("密钥:",ke); fl.addRow("填充:",pc)
        btn=QDialogButtonBox(QDialogButtonBox.StandardButton.Ok|QDialogButtonBox.StandardButton.Cancel)
        btn.accepted.connect(dlg.accept); btn.rejected.connect(dlg.reject); fl.addRow(btn)
        if dlg.exec()==QDialog.DialogCode.Accepted:
            self._marked_encrypt[n]=(ac.currentText(),mc.currentText(),ke.text().strip(),pc.currentText()); self._refresh_marks()

    def _unmark_encrypt(self, name): self._marked_encrypt.pop(name,None); self._refresh_marks()
    def _mark_sign_source(self, name): self._marked_sign_source=name
    def _unmark_sign(self): self._marked_sign_source=None; self._marked_sign_config=None; self._refresh_marks()
    def _clear_marks(self): self._marked_encrypt.clear(); self._marked_sign_source=None; self._marked_sign_config=None; self._refresh_marks(); self._push_to_builder()

    def _undo_last_step(self):
        """撤销最后一步."""
        if not shared_pipeline.steps:
            self.mark_summary_label.setText("没有可撤销的步骤"); return
        removed = shared_pipeline.steps.pop()
        # 同步清理标记
        field = removed.get("params", {}).get("field", "")
        if field in self._marked_encrypt:
            del self._marked_encrypt[field]
        if self._marked_sign_source == field:
            self._marked_sign_source = None; self._marked_sign_config = None
        shared_pipeline.update_from_builder(list(shared_pipeline.steps))
        self._refresh_marks()
        self.code_preview.setPlainText(codegen_for_pipeline(shared_pipeline.steps, shared_pipeline.body_format, _profile_from_window(self.window())) if shared_pipeline.steps else shared_pipeline._plugin_code)
        self.mark_summary_label.setText(f"已撤销: {removed['type']} → {field}")
        ctrl = self.window().control if hasattr(self.window(), "control") else None
        if ctrl and ctrl.profile_combo.currentText():
            try:
                save_project_state(ctrl.profile_combo.currentText(), getattr(ctrl, "_last_raw", ""))
            except Exception:
                pass

    def _push_to_builder(self):
        """将解析器标记同步到可视化构建器."""
        steps = []
        for field, (algo, mode, key, pad) in self._marked_encrypt.items():
            steps.append({"type":"🔒 加密字段","params":{"field":field,"algo":algo,"mode":mode,"key":key,"padding":pad}})
        if self._marked_sign_source and self._marked_sign_config:
            sa, st, sk = self._marked_sign_config
            steps.append({"type":"📝 签名(Hash)","params":{"algo":sa,"source":self._marked_sign_source,"output":"hex","target_type":"Header","target":st}})
        shared_pipeline.update_from_parser(steps, dict(self._parsed_fields))

    def _pull_from_builder(self):
        """从可视化构建器同步标记到解析器."""
        self._marked_encrypt.clear()
        for s in shared_pipeline.steps:
            if "加密" in s["type"] or "解密" in s["type"]:
                p = s["params"]
                self._marked_encrypt[p.get("field","data")] = (p.get("algo","AES"), p.get("mode","ECB"), p.get("key",""), p.get("padding","PKCS7"))
            elif "签名" in s["type"]:
                p = s["params"]
                self._marked_sign_source = p.get("source","")
                self._marked_sign_config = (p.get("algo","sha256"), p.get("target","signature"), p.get("key",""))
        self._refresh_marks()

    def _refresh_marks(self):
        def color_node(item):
            for i in range(item.childCount()):
                c=item.child(i); n=c.text(0)
                if n in self._marked_encrypt:
                    c.setForeground(0, QColor(C["accent"])); c.setForeground(1, QColor(C["accent"]))
                elif n==self._marked_sign_source:
                    c.setForeground(0, QColor(C["warn"])); c.setForeground(1, QColor(C["warn"]))
                else:
                    c.setForeground(0, QColor(C["text"])); c.setForeground(1, QColor(C["text_dim"]))
                color_node(c)
        if self.tree.topLevelItemCount()>0: color_node(self.tree.topLevelItem(0))
        lines=[]
        if self._marked_encrypt:
            lines.append("🔒 " + ", ".join(f"{n}({a}/{m})" for n,(a,m,k,p) in self._marked_encrypt.items()))
        if self._marked_sign_source:
            lines.append(f"📝 签名源: {self._marked_sign_source}")
        self.mark_summary_label.setText(" | ".join(lines) if lines else "左键点击字段值添加加解密")
        if lines:
            style_feedback(self.mark_summary_label, "success")
        else:
            style_muted_label(self.mark_summary_label)
        # 刷新共享代码预览: 优先显示生成的代码, 否则显示项目已有代码
        if shared_pipeline.steps:
            self.code_preview.setPlainText(codegen_for_pipeline(shared_pipeline.steps, shared_pipeline.body_format, _profile_from_window(self.window())))
        elif hasattr(shared_pipeline, '_plugin_code') and shared_pipeline._plugin_code:
            self.code_preview.setPlainText(shared_pipeline._plugin_code)

    @staticmethod
    def _looks_like_hash(v): return len(v.strip())>=32 and all(c in '0123456789abcdefABCDEF' for c in v.strip())
    @staticmethod
    def _hash_hint(v):
        l=len(v.strip())
        if l==32: return "疑似: MD5"
        if l==40: return "疑似: SHA1"
        if l==64: return "疑似: SHA256/SM3"
        if l==128: return "疑似: SHA512"
        return "疑似: 哈希值"

    def _verify_signature(self, algo):
        sig=self._get_selected_value().strip()
        r=[]
        for fp,fv in self._parsed_fields.items():
            if self._compute_hash(fv,algo)==sig: r.append(f"✓ {algo.upper()}(字段: {fp})")
        self._mark_feedback(
            f"[签名 {algo}]\n" + "\n".join(r) if r else f"✗ 未匹配",
            "success" if r else "warn",
        )

    def _auto_match_signature(self):
        sig=self._get_selected_value().strip(); r=[]
        for algo in ["md5","sha1","sha256","sha512","sm3"]:
            for fp,fv in self._parsed_fields.items():
                if self._compute_hash(fv,algo)==sig: r.append(f"✓ {algo.upper()}(字段: {fp})")
        self._mark_feedback(
            "[自动匹配]\n" + "\n".join(r) if r else "未找到匹配",
            "success" if r else "warn",
        )

    def _compute_hash(self, data, algo):
        db=data.encode("utf-8")
        if algo=="sm3": return sm3_hash(db)
        return hashlib.new(algo,db).hexdigest()

    # ---- 生成插件代码 (新架构) ----
    def _generate_plugin_code(self):
        """保存到控制面板当前选中的项目."""
        steps = shared_pipeline.steps
        if not steps:
            QMessageBox.information(self, "提示", "请先左键点击字段值添加加解密步骤")
            return

        # 从主窗口获取当前选中的项目名
        main_win = self.window()
        name = ""
        if hasattr(main_win, 'control'):
            name = main_win.control.profile_combo.currentText()

        if not name:
            name, ok = QInputDialog.getText(self, "保存项目", "项目名称:")
            if not ok or not name.strip(): return
            name = name.strip().lower().replace(" ", "_")

        # 生成代码并保存
        code = codegen_for_pipeline(steps, shared_pipeline.body_format, _profile_from_window(main_win))
        plugin_name = get_plugin_name(name) or name
        plugin_dir = os.path.join(PLUGINS_DIR, plugin_name)
        os.makedirs(plugin_dir, exist_ok=True)
        with open(os.path.join(plugin_dir, "plugin.py"), "w", encoding="utf-8") as f:
            f.write(code)

        # 更新profile
        host = self._parsed_headers.get("Host", "*")
        profile_path = os.path.join(PROFILES_DIR, f"{name}.yaml")
        if not os.path.exists(profile_path):
            with open(profile_path, "w", encoding="utf-8") as f:
                f.write(
                    f"name: {name}\ndescription: ''\nplugin: {plugin_name}\n"
                    f"roles: [decrypt, encrypt]\n"
                    f"match:\n  host:\n    - {host}\n"
                    f"  path:\n    - '*'\n"
                    f"  methods:\n    - POST\n    - PUT\n    - PATCH\n    - GET\n"
                )

        log_signal.append_log.emit("INFO", f"已保存项目: {name}")
        self.mark_summary_label.setText(f"已保存到项目: {name} | 共 {len(steps)} 个步骤")

        # 保存后同步预览与状态
        shared_pipeline._plugin_code = code
        raw = getattr(self.window().control, "_last_raw", "") if hasattr(self.window(), "control") else ""
        state_path = os.path.join(plugin_dir, "state.json")
        with open(state_path, "w", encoding="utf-8") as f:
            json.dump({
                "steps": shared_pipeline.steps,
                "parsed_fields": shared_pipeline.parsed_fields,
                "raw_input": raw,
            }, f, ensure_ascii=False)
        self.code_preview.setPlainText(code)
        shared_pipeline._notify()

        QMessageBox.information(self, "保存成功",
            f"代码已写入 plugins/{plugin_name}/plugin.py\n\n在控制面板选择项目后启动代理即可。")

    def _generate_profile(self):
        """已合并到 _generate_plugin_code — 保留以兼容."""
        self._generate_plugin_code()


def _build_mock_response(resp_block: str):
    """把 Burp 风格响应报文（HTTP/1.1 200 ...）转成 mitmproxy Response，用于离线测试."""
    from mitmproxy import http
    lines = resp_block.replace("\r\n", "\n").split("\n")
    m = re.match(r"HTTP/\d\.\d\s+(\d+)", lines[0].strip())
    status = int(m.group(1)) if m else 200
    headers: dict[str, str] = {}
    body_start = len(lines)
    for i, line in enumerate(lines[1:], start=1):
        line = line.strip()
        if not line:
            body_start = i + 1
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    body = "\n".join(lines[body_start:]).strip().encode("utf-8")
    return http.Response.make(status, body, headers)


# ============================================================
# 插件编辑器 Tab — 编写自定义扩展函数/类
# ============================================================
class ExtensionEditorTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_file = ""
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        hint = QLabel(
            "在此编写自定义 Python 扩展（函数或类），用 @register 注册。\n"
            "保存后可在「请求解析器」「可视化构建器」的操作类型中选择 🔌 开头的自定义步骤。"
        )
        hint.setWordWrap(True)
        style_muted_label(hint)
        layout.addWidget(hint)

        top_row = QHBoxLayout()
        top_row.addWidget(QLabel("扩展文件:"))
        self.file_combo = QComboBox()
        self.file_combo.setMinimumWidth(180)
        self.file_combo.currentTextChanged.connect(self._load_file)
        top_row.addWidget(self.file_combo)
        new_btn = QPushButton("新建")
        new_btn.clicked.connect(self._new_file)
        top_row.addWidget(new_btn)
        save_btn = QPushButton("保存")
        save_btn.clicked.connect(self._save_file)
        top_row.addWidget(save_btn)
        del_btn = QPushButton("删除")
        del_btn.clicked.connect(self._delete_file)
        top_row.addWidget(del_btn)
        refresh_btn = QPushButton("刷新")
        refresh_btn.clicked.connect(self._refresh_all)
        top_row.addWidget(refresh_btn)
        top_row.addStretch()
        layout.addLayout(top_row)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.editor = QPlainTextEdit()
        self.editor.setFont(QFont("Cascadia Code", 11))
        setup_code_editor(self.editor)
        self.editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        splitter.addWidget(self.editor)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(4, 0, 0, 0)
        rl.addWidget(QLabel("已注册的扩展:"))
        self.fn_list = QListWidget()
        rl.addWidget(self.fn_list, 1)
        rl.addWidget(QLabel("测试输入:"))
        self.test_input = QLineEdit()
        self.test_input.setPlaceholderText("输入要测试的字段值")
        rl.addWidget(self.test_input)
        test_btn = QPushButton("测试选中扩展")
        test_btn.clicked.connect(self._test_selected)
        rl.addWidget(test_btn)
        self.test_output = QPlainTextEdit()
        self.test_output.setReadOnly(True)
        self.test_output.setMaximumHeight(120)
        self.test_output.setFont(QFont("Courier New", 10))
        rl.addWidget(self.test_output)
        splitter.addWidget(right)
        splitter.setSizes([720, 280])
        layout.addWidget(splitter, 1)

        self.status_label = QLabel("")
        layout.addWidget(self.status_label)

        style_button(new_btn, "default")
        style_button(save_btn, "primary")
        style_button(del_btn, "danger")
        style_button(refresh_btn, "ghost")
        style_button(test_btn, "default")
        set_btn_icon(new_btn, "add")
        set_btn_icon(save_btn, "save")
        set_btn_icon(del_btn, "delete")
        set_btn_icon(refresh_btn, "refresh")
        set_btn_icon(test_btn, "test")
        self._refresh_file_list()

    def _refresh_file_list(self):
        current = self.file_combo.currentText()
        self.file_combo.blockSignals(True)
        self.file_combo.clear()
        for f in list_extension_files():
            self.file_combo.addItem(f)
        self.file_combo.blockSignals(False)
        if current and self.file_combo.findText(current) >= 0:
            self.file_combo.setCurrentText(current)
        elif self.file_combo.count() > 0:
            self.file_combo.setCurrentIndex(0)
        else:
            self.editor.clear()
            self._current_file = ""
            self._refresh_fn_list()

    def _refresh_fn_list(self):
        self.fn_list.clear()
        reload_extensions(force=True)
        fname = self.file_combo.currentText()
        if not fname:
            for meta in sorted(get_extension_op_types().keys()):
                self.fn_list.addItem(meta)
            return
        names = get_file_registered_names(fname)
        if names:
            for n in names:
                self.fn_list.addItem(f"🔌 {n}")
        else:
            self.fn_list.addItem("(当前文件未注册任何 @register 函数)")

    def _refresh_all(self):
        self._refresh_file_list()
        self._load_file(self.file_combo.currentText())
        extension_signal.changed.emit()
        log_signal.append_log.emit("INFO", "扩展插件已刷新")

    def _load_file(self, filename: str):
        if not filename:
            return
        path = os.path.join(EXTENSIONS_DIR, filename)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self.editor.setPlainText(f.read())
            self._current_file = filename
            self.status_label.setText(f"已加载: {path}")
            self._refresh_fn_list()

    def _new_file(self):
        name, ok = QInputDialog.getText(self, "新建扩展", "文件名 (不含 .py):")
        if not ok or not name.strip():
            return
        name = name.strip().lower().replace(" ", "_")
        if not name.endswith(".py"):
            name += ".py"
        path = os.path.join(EXTENSIONS_DIR, name)
        if os.path.exists(path):
            QMessageBox.warning(self, "提示", "文件已存在")
            return
        os.makedirs(EXTENSIONS_DIR, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(new_extension_template(name.replace(".py", "")))
        self._refresh_file_list()
        self.file_combo.setCurrentText(name)
        self._load_file(name)

    def _save_file(self):
        filename = self.file_combo.currentText()
        if not filename:
            QMessageBox.information(self, "提示", "请先新建或选择扩展文件")
            return
        os.makedirs(EXTENSIONS_DIR, exist_ok=True)
        path = os.path.join(EXTENSIONS_DIR, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.editor.toPlainText())
        count, errors = reload_extensions(force=True)
        self._refresh_fn_list()
        self.status_label.setText(f"已保存: {path} | 共 {count} 个扩展已注册")
        log_signal.append_log.emit("INFO", f"扩展已保存: {filename} ({count} 个函数)")
        extension_signal.changed.emit()
        if errors:
            QMessageBox.warning(self, "加载警告", "\n\n".join(errors[:3]))

    def _delete_file(self):
        filename = self.file_combo.currentText()
        if not filename:
            return
        if QMessageBox.question(self, "确认", f"删除扩展文件 {filename}?") != QMessageBox.StandardButton.Yes:
            return
        path = os.path.join(EXTENSIONS_DIR, filename)
        if os.path.exists(path):
            os.remove(path)
        self._refresh_all()

    def _test_selected(self):
        item = self.fn_list.currentItem()
        if not item:
            return
        display = item.text()
        meta = get_meta(display)
        if not meta:
            self.test_output.setPlainText("未找到扩展元数据，请先保存文件")
            return
        value = self.test_input.text() or "test"
        try:
            result = run_extension_test(meta["id"], value, {})
            self.test_output.setPlainText(result)
        except Exception as e:
            self.test_output.setPlainText(f"错误: {e}")


# 兼容旧名称
PluginEditorTab = ExtensionEditorTab


# ============================================================
# 可视化构建器 Tab — 零代码组装加解密管道
# ============================================================
class VisualBuilderTab(QWidget):
    _SCOPE_OPTS = ["📋 Body (JSON)", "📋 Body (Form)", "🔗 URL Query"]
    _DATA_SCOPE_OPTS = ["📋 Body", "🔗 URL Query"]
    # 操作类型定义: (类型名, 参数字段列表)
    _OP_TYPES = {
        "🔒 加密字段": [
            ("字段名", "field", str),
            ("数据来源", "scope", _SCOPE_OPTS),
            ("算法", "algo", ["AES","DES","3DES","SM4","RSA","SM2","XOR"]),
            ("模式(对称) / 填充或格式(非对称)", "mode",
             ["ECB","CBC","CFB","OFB","CTR","GCM","OAEP","PKCS1v15","C1C3C2","C1C2C3"]),
            ("密钥(对称密钥 / RSA PEM / SM2 hex，或 $变量)", "key", str),
            ("填充", "padding", ["PKCS7","ZeroPadding","NoPadding","OAEP","PKCS1v15"]),
            ("IV(留空/@字段/$变量)", "iv", str),
        ],
        "🔓 解密字段": [
            ("字段名", "field", str),
            ("数据来源", "scope", _SCOPE_OPTS),
            ("算法", "algo", ["AES","DES","3DES","SM4","RSA","SM2","XOR"]),
            ("模式(对称) / 填充或格式(非对称)", "mode",
             ["ECB","CBC","CFB","OFB","CTR","GCM","OAEP","PKCS1v15","C1C3C2","C1C2C3"]),
            ("密钥(对称密钥 / RSA PEM / SM2 hex，或 $变量)", "key", str),
            ("填充", "padding", ["PKCS7","ZeroPadding","NoPadding","OAEP","PKCS1v15"]),
            ("IV(留空/@字段/$变量)", "iv", str),
            ("密文格式(默认base64)", "input_fmt", ["base64", "hex"]),
        ],
        "🔓 解密响应字段": [
            ("字段路径(如 data 或 result.data)", "field", str),
            ("算法", "algo", ["AES","DES","3DES","SM4","RSA","SM2","XOR"]),
            ("模式(对称) / 填充或格式(非对称)", "mode",
             ["ECB","CBC","CFB","OFB","CTR","GCM","OAEP","PKCS1v15","C1C3C2","C1C2C3"]),
            ("密钥(对称密钥 / RSA PEM / SM2 hex，或 $变量)", "key", str),
            ("填充", "padding", ["PKCS7","ZeroPadding","NoPadding","OAEP","PKCS1v15"]),
            ("IV(留空/@响应字段/#prefix)", "iv", str),
            ("密文格式(默认base64)", "input_fmt", ["base64", "hex"]),
        ],
        "🔒 加密响应字段": [
            ("字段路径(如 data 或 result.data)", "field", str),
            ("算法", "algo", ["AES","DES","3DES","SM4","RSA","SM2","XOR"]),
            ("模式(对称) / 填充或格式(非对称)", "mode",
             ["ECB","CBC","CFB","OFB","CTR","GCM","OAEP","PKCS1v15","C1C3C2","C1C2C3"]),
            ("密钥(对称密钥 / RSA PEM / SM2 hex，或 $变量)", "key", str),
            ("填充", "padding", ["PKCS7","ZeroPadding","NoPadding","OAEP","PKCS1v15"]),
            ("IV(留空/@响应字段/$变量)", "iv", str),
        ],
        "📝 签名(Hash)": [
            ("签名算法", "algo", ["SHA256","MD5","SHA1","SHA512","SM3"]),
            ("源字段(签哪个)", "source", str),
            ("输出格式", "output", ["hex","base64"]),
            ("写入方式", "target_type", ["Header","Body字段"]),
            ("目标名", "target", str),
        ],
        "📝 签名(HMAC带密钥)": [
            ("HMAC算法", "algo", ["HMAC-SHA256","HMAC-SHA1","HMAC-MD5","HMAC-SHA512","HMAC-SM3"]),
            ("HMAC密钥(固定值 或 $变量名)", "hmac_key", str),
            ("源字段(签哪个)", "source", str),
            ("输出格式", "output", ["hex","base64"]),
            ("写入方式", "target_type", ["Header","Body字段"]),
            ("目标名", "target", str),
        ],
        "📝 签名(排序拼接)": [
            ("签名算法", "algo", ["MD5","SHA256","SHA1","SM3"]),
            ("签名数据范围", "data_scope", _DATA_SCOPE_OPTS),
            ("拼接分隔符", "separator", ["|","&",""]),
            ("密钥后缀(secret)", "secret_suffix", str),
            ("是否包含字段名", "include_key", ["是(key=value|)","否(仅value|)"]),
            ("写入方式", "target_type", ["Header","Body字段","URL参数字段"]),
            ("目标名", "target", str),
        ],
        "🔗 拼接字符串": [
            ("拼接方式", "join_type", ["直接拼接","用&拼接","用|拼接","用@@拼接","用逗号拼接","用空格拼接"]),
            ("左边来源", "src1", ["📋 body字段(如data)","📝 固定文本"]),
            ("左边值(字段名或文本)", "val1", str),
            ("右边来源", "src2", ["📋 body字段(如data)","📝 固定文本"]),
            ("右边值(字段名或文本)", "val2", str),
            ("结果写入字段", "target_field", str),
        ],
        "🔤 编码转换": [
            ("要转换的字段名", "field", str),
            ("数据来源", "scope", _SCOPE_OPTS),
            ("编码方式", "encode_type", ["Base64编码","Base64解码","Hex编码","Hex解码","URL编码","URL解码"]),
        ],
        "✂️ 正则清洗": [
            ("要处理的字段名", "field", str),
            ("数据来源", "scope", _SCOPE_OPTS),
            ("清洗方式", "clean_type", ["清除\\r\\n","清除空白字符","清除引号","仅保留字母数字","大写","小写","反转"]),
        ],
        "🏷 设置Header": [
            ("Header名", "header_name", str),
            ("值的来源", "value_type", ["📋 body字段(如data)","🔗 URL Query字段","📝 固定文本","⏰ 时间戳(毫秒)","🎲 随机hex(16)"]),
            ("字段名或文本值", "value", str),
        ],
        "📦 设置Body字段": [
            ("目标字段路径", "field_path", str),
            ("数据来源", "scope", _SCOPE_OPTS),
            ("值的来源", "value_type", ["📋 body字段(如data)","🔗 URL Query字段","📝 固定文本","⏰ 时间戳(毫秒)","🎲 随机hex(16)","🔗 拼接结果"]),
            ("字段名或文本值", "value", str),
        ],
        "⏰ 生成时间戳": [
            ("时间格式", "ts_type", ["毫秒时间戳","秒时间戳","年-月-日 时:分:秒"]),
            ("写入目标字段", "target_field", str),
            ("数据来源", "scope", _SCOPE_OPTS),
        ],
        "🎲 生成随机数": [
            ("随机类型", "rand_type", ["32位hex","16位hex","8位hex","UUID","6位数字"]),
            ("写入目标字段", "target_field", str),
            ("数据来源", "scope", _SCOPE_OPTS),
        ],
        "🔐 AuthToken生成": [
            ("基础密钥(固定值 或 $变量名)", "base_key", str),
            ("JWT来源", "jwt_src", ["Header字段","固定值"]),
            ("JWT Header名/固定值", "jwt_value", str),
            ("签名来自哪个字段", "sign_source", str),
            ("Origin URL", "origin", str),
            ("URL前缀剥离", "strip_prefix", str),
            ("加密算法", "algo", ["AES","SM4"]),
        ],
        "✂️ 字符串切片": [
            ("字段名", "field", str),
            ("切片方式", "slice_type", ["取后20位 [-20:]","取后10位 [-10:]","取前10位 [:10]","取8位之后 [8:]","取后5位 [-5:]","自定义"]),
            ("自定义切片", "custom_slice", str),
        ],
        "🔀 字符串反转": [
            ("字段名", "field", str),
            ("写入目标字段", "target_field", str),
        ],
        "🔑 定义密钥(固定值)": [
            ("密钥变量名", "key_name", str),
            ("密钥值", "key_value", str),
            ("说明", "_note", str),
        ],
        "🔑 提取密钥(从响应)": [
            ("密钥变量名", "key_name", str),
            ("提取来源", "source_type", ["响应body字段","响应Header","请求Cookie"]),
            ("字段路径/Header名/Cookie名", "source_path", str),
        ],
        "🔑 派生密钥(计算)": [
            ("密钥变量名", "key_name", str),
            ("派生方式", "derive_type", ["MD5(body字段)","SHA256(body字段)","SHA256(时间戳+字段)","字段值反转","拼接: 字段+时间戳"]),
            ("公式参数(body字段名)", "derive_param", str),
        ],
    }

    @classmethod
    def get_op_types(cls) -> dict:
        ops = dict(cls._OP_TYPES)
        ops.update(get_extension_op_types())
        return ops

    def __init__(self, parent=None):
        super().__init__(parent)
        self._built_steps = []  # 跟踪当前UI中的步骤
        self._build_ui()
        shared_pipeline.listen(self._on_pipeline_changed)
        if shared_pipeline.steps:
            self._load_steps(shared_pipeline.steps)

    def _on_pipeline_changed(self):
        """当解析器推送新步骤时，自动加载并刷新预览."""
        current = [{"type": s["type"], "params": dict(s["params"])} for s in shared_pipeline.steps]
        built = [{"type": s["type"], "params": dict(s["params"])} for s in self._built_steps]
        if current != built:
            if not current:
                self._clear_all()
            else:
                self._load_steps(shared_pipeline.steps)
        else:
            # 步骤没变但项目切换了, 刷新预览显示项目代码
            self._preview_code()

    def _merge_step_params(self, step: dict) -> dict:
        """默认参数 + 步骤参数；空 field 不沿用默认空串盖住有效值."""
        op = step.get("type") or ""
        params = self._default_params(op)
        incoming = dict(step.get("params") or {})
        # 空字符串视为未填，避免 AI/同步时用 "" 覆盖掉默认 field
        for k, v in list(incoming.items()):
            if isinstance(v, str) and not v.strip() and k in ("field", "key", "iv"):
                if k == "field":
                    incoming.pop(k, None)
                elif k == "key" and not str(params.get("key") or "").strip():
                    pass  # 保留空 key，由上层提示
                elif k == "iv":
                    incoming.pop(k, None)
        params.update(incoming)
        if op in ("🔓 解密字段", "🔒 加密字段", "🔓 解密响应字段", "🔒 加密响应字段"):
            if not str(params.get("field") or "").strip():
                params["field"] = "data"
        return params

    def apply_pipeline_steps(
        self,
        steps: list,
        *,
        preview_code: str | None = None,
        persist: bool = True,
        notify: bool | None = None,
    ) -> None:
        """一次性写入完整步骤（合并默认参数），避免 _add_step 空默认触发自动保存把 state 写坏."""
        if notify is None:
            notify = persist
        if not steps:
            self._clear_all()
            if preview_code is not None:
                self.code_preview.setPlainText(preview_code)
            elif persist:
                self._auto_save_steps()
            return
        built = []
        for step in steps:
            if not isinstance(step, dict) or not step.get("type"):
                continue
            built.append({"type": step["type"], "params": self._merge_step_params(step)})
        if not built:
            self._clear_all()
            return
        # 清除旧 UI
        for i in range(self.steps_layout.count() - 1, -1, -1):
            w = self.steps_layout.itemAt(i).widget()
            if w and w.property("step_idx") is not None:
                w.deleteLater()
        shared_pipeline.steps = built
        self._built_steps = [{"type": s["type"], "params": dict(s["params"])} for s in built]
        self._rebuild_steps()
        if preview_code is not None:
            self.code_preview.setPlainText(preview_code)
        else:
            self._preview_code()
        self._refresh_empty_hint()
        if notify:
            # 通知解析器标记；AI 同步时应在外部最后再写回带 MATCH 的完整代码
            shared_pipeline.update_from_builder(list(shared_pipeline.steps))
        if persist:
            self._auto_save_steps()

    def _load_steps(self, steps: list):
        """从共享数据加载步骤（不写盘、不二次通知，避免冲掉 plugin 预览）."""
        self.apply_pipeline_steps(steps, persist=False, notify=False)

    def _auto_save_steps(self):
        main_win = self.window()
        if hasattr(main_win, "control"):
            name = main_win.control.profile_combo.currentText()
            if name:
                try:
                    save_project_state(name, getattr(main_win.control, "_last_raw", ""))
                except Exception:
                    pass

    def _notify_change(self):
        self._built_steps = list(shared_pipeline.steps)  # 标记为自身修改
        shared_pipeline.update_from_builder(list(shared_pipeline.steps))
        self._preview_code()
        self._auto_save_steps()

    def _build_ui(self):
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ---- 左侧: 操作步骤列表 ----
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(4, 4, 4, 4)
        ll.setSpacing(6)

        header = QHBoxLayout()
        header.setSpacing(6)
        tpl_lbl = QLabel("案例模板")
        style_muted_label(tpl_lbl)
        header.addWidget(tpl_lbl)
        self.template_combo = QComboBox()
        self.template_combo.setMinimumWidth(180)
        self.template_combo.setToolTip("选一个常见场景，一键填入可改的步骤")
        self._populate_template_combo()
        self.template_combo.currentIndexChanged.connect(self._on_template_picked)
        header.addWidget(self.template_combo, 1)
        ll.addLayout(header)

        self.template_hint = QLabel("选模板可快速起步，参数按实际接口改密钥/字段即可")
        style_muted_label(self.template_hint)
        self.template_hint.setWordWrap(True)
        ll.addWidget(self.template_hint)

        header2 = QHBoxLayout()
        header2.setSpacing(6)
        steps_lbl = QLabel("操作步骤")
        style_step_title(steps_lbl)
        header2.addWidget(steps_lbl)
        self.steps_count_label = QLabel("")
        style_muted_label(self.steps_count_label)
        header2.addWidget(self.steps_count_label)
        header2.addStretch()
        add_btn = QPushButton("添加步骤")
        add_btn.clicked.connect(lambda: self._add_step())
        style_button(add_btn, "primary")
        set_btn_icon(add_btn, "add")
        header2.addWidget(add_btn)
        ll.addLayout(header2)

        self.steps_scroll = QScrollArea()
        self.steps_scroll.setWidgetResizable(True)
        self.steps_widget = QWidget()
        self.steps_layout = QVBoxLayout(self.steps_widget)
        self.steps_layout.setSpacing(6)
        self.steps_layout.setContentsMargins(0, 0, 0, 0)
        self.steps_empty_hint = QLabel(
            "暂无步骤\n\n从上方选案例模板，或点「添加步骤」\n右侧会实时生成插件代码"
        )
        self.steps_empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.steps_empty_hint.setWordWrap(True)
        style_muted_label(self.steps_empty_hint)
        self.steps_empty_hint.setMinimumHeight(120)
        self.steps_layout.addWidget(self.steps_empty_hint)
        self.steps_layout.addStretch()
        self.steps_scroll.setWidget(self.steps_widget)
        ll.addWidget(self.steps_scroll, 1)

        bottom_row = QHBoxLayout()
        bottom_row.setSpacing(6)
        undo_btn = QPushButton("撤销")
        undo_btn.setToolTip("删除最后一步")
        undo_btn.clicked.connect(self._undo_last)
        bottom_row.addWidget(undo_btn)
        clear_btn = QPushButton("清空")
        clear_btn.setToolTip("清空全部步骤")
        clear_btn.clicked.connect(self._clear_all)
        bottom_row.addWidget(clear_btn)
        bottom_row.addStretch()
        save_btn = QPushButton("保存代码")
        save_btn.clicked.connect(self._save_plugin)
        bottom_row.addWidget(save_btn)
        ll.addLayout(bottom_row)
        style_button(undo_btn, "ghost")
        style_button(clear_btn, "ghost")
        style_button(save_btn, "primary")
        set_btn_icon(undo_btn, "undo")
        set_btn_icon(clear_btn, "clear")
        set_btn_icon(save_btn, "save")

        # ---- 右侧: 代码预览 ----
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(4, 0, 4, 4)
        rl.setSpacing(4)
        rl.addWidget(QLabel("生成的插件代码（与请求解析器同步，改步骤即刷新）"))
        self.code_preview = QPlainTextEdit()
        self.code_preview.setFont(QFont("Cascadia Code", 11))
        setup_code_editor(self.code_preview)
        self.code_preview.setReadOnly(True)
        self.code_preview.setPlaceholderText("添加操作步骤 → 自动生成代码")
        self.code_preview.setMaximumBlockCount(3000)
        rl.addWidget(self.code_preview)
        self.copy_btn = QPushButton("复制代码")
        self.copy_btn.clicked.connect(self._copy_code)
        rl.addWidget(self.copy_btn)
        style_button(self.copy_btn, "ghost")
        set_btn_icon(self.copy_btn, "copy")

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([550, 650])

        top_layout = QVBoxLayout(self)
        top_layout.setContentsMargins(4, 4, 4, 4)
        top_layout.addWidget(splitter)
        self._refresh_empty_hint()

    def _default_params(self, op_type: str) -> dict:
        """按操作类型生成默认参数."""
        params = {}
        op_types = self.get_op_types()
        schema = op_types.get(op_type, [])
        for _pname, pkey, ptype in schema:
            if isinstance(ptype, list):
                if pkey == "scope":
                    params[pkey] = {
                        "json": "📋 Body (JSON)",
                        "form": "📋 Body (Form)",
                    }.get(shared_pipeline.body_format, "📋 Body (JSON)")
                elif pkey == "data_scope":
                    params[pkey] = (
                        "🔗 URL Query" if shared_pipeline.parsed_query else "📋 Body"
                    )
                else:
                    params[pkey] = ptype[0]
            else:
                params[pkey] = ""
        if op_type.startswith("🔌 "):
            meta = get_meta(op_type, params)
            if meta:
                params["extension_id"] = meta["id"]
        return params

    @staticmethod
    def _step_summary(op_type: str, params: dict) -> str:
        """步骤卡片一行摘要，方便扫读."""
        p = params or {}
        parts: list[str] = []
        field = p.get("field") or p.get("field_path") or p.get("source") or p.get("target_field")
        if field:
            parts.append(str(field))
        algo = p.get("algo")
        mode = p.get("mode")
        if algo and mode:
            parts.append(f"{algo}/{mode}")
        elif algo:
            parts.append(str(algo))
        key = p.get("key") or p.get("hmac_key") or p.get("key_name") or p.get("base_key")
        if key:
            k = str(key)
            parts.append(k if len(k) <= 18 else k[:16] + "…")
        target = p.get("target") or p.get("header_name")
        if target and target != field:
            parts.append(f"→ {target}")
        encode = p.get("encode_type") or p.get("clean_type") or p.get("ts_type") or p.get("rand_type")
        if encode:
            parts.append(str(encode))
        if p.get("source_path"):
            parts.append(f"← {p['source_path']}")
        if not parts:
            return "点击下方填写参数"
        return " · ".join(parts)

    def _refresh_empty_hint(self) -> None:
        n = len(shared_pipeline.steps)
        if hasattr(self, "steps_empty_hint"):
            self.steps_empty_hint.setVisible(n == 0)
        if hasattr(self, "steps_count_label"):
            self.steps_count_label.setText(f"{n} 步" if n else "")

    def _add_step(self, op_type: str = None):
        """添加一个操作步骤行."""
        if op_type is None or op_type is False:
            sections = [("内置操作", list(self._OP_TYPES))]
            ext = get_extension_choices()
            if ext:
                sections.append(("自定义扩展", ext))
            selected = pick_from_list(self, "选择操作类型", sections=sections)
            if selected:
                self._add_step(selected)
            return

        params = self._default_params(op_type)
        shared_pipeline.steps.append({"type": op_type, "params": params})
        self._rebuild_steps()
        self._notify_change()

    def _update_param(self, step_idx: int, key: str, value: str):
        if step_idx < len(shared_pipeline.steps):
            shared_pipeline.steps[step_idx]["params"][key] = value
            row = self._step_row_at(step_idx)
            if row is not None:
                summary = getattr(row, "_summary_label", None)
                if summary is not None:
                    summary.setText(
                        self._step_summary(
                            shared_pipeline.steps[step_idx]["type"],
                            shared_pipeline.steps[step_idx]["params"],
                        )
                    )
            self._notify_change()

    def _step_row_at(self, idx: int):
        for i in range(self.steps_layout.count()):
            w = self.steps_layout.itemAt(i).widget()
            if w is not None and w.property("step_idx") == idx:
                return w
        return None

    def _remove_step(self, idx: int):
        if idx < 0 or idx >= len(shared_pipeline.steps):
            return
        shared_pipeline.steps.pop(idx)
        self._rebuild_steps()
        self._notify_change()

    def _move_step(self, idx: int, direction: int):
        new_idx = idx + direction
        if new_idx < 0 or new_idx >= len(shared_pipeline.steps):
            return
        shared_pipeline.steps[idx], shared_pipeline.steps[new_idx] = (
            shared_pipeline.steps[new_idx],
            shared_pipeline.steps[idx],
        )
        self._rebuild_steps()
        self._notify_change()

    def _rebuild_steps(self):
        """重新构建所有步骤 UI."""
        old_steps = list(shared_pipeline.steps)
        for i in range(self.steps_layout.count() - 1, -1, -1):
            w = self.steps_layout.itemAt(i).widget()
            if w is not None and w.property("step_idx") is not None:
                w.deleteLater()
        for idx, step in enumerate(old_steps):
            self._add_step_row(step, idx)
        self._refresh_empty_hint()

    def _add_step_row(self, step: dict, step_idx: int):
        op_type = step["type"]
        params = step["params"]
        op_types = self.get_op_types()
        schema = op_types.get(op_type, [])

        row = QFrame()
        row.setFrameShape(QFrame.Shape.StyledPanel)
        row.setProperty("card", True)
        repolish_widget(row)
        row_layout = QVBoxLayout(row)
        row_layout.setSpacing(4)
        row_layout.setContentsMargins(8, 6, 8, 6)

        title_row = QHBoxLayout()
        title_row.setSpacing(4)
        type_label = QLabel(f"#{step_idx + 1}  {op_type}")
        style_step_title(type_label)
        title_row.addWidget(type_label, 1)

        up_btn = QPushButton("↑")
        up_btn.setMaximumWidth(28)
        up_btn.setToolTip("上移")
        up_btn.setEnabled(step_idx > 0)
        up_btn.clicked.connect(lambda _=False, i=step_idx: self._move_step(i, -1))
        style_compact_button(up_btn)

        down_btn = QPushButton("↓")
        down_btn.setMaximumWidth(28)
        down_btn.setToolTip("下移")
        down_btn.setEnabled(step_idx < len(shared_pipeline.steps) - 1)
        down_btn.clicked.connect(lambda _=False, i=step_idx: self._move_step(i, 1))
        style_compact_button(down_btn)

        del_btn = QPushButton("×")
        del_btn.setMaximumWidth(28)
        del_btn.setToolTip("删除此步")
        style_compact_button(del_btn, "danger")
        del_btn.clicked.connect(lambda _=False, i=step_idx: self._remove_step(i))

        title_row.addWidget(up_btn)
        title_row.addWidget(down_btn)
        title_row.addWidget(del_btn)
        row_layout.addLayout(title_row)

        summary = QLabel(self._step_summary(op_type, params))
        style_muted_label(summary)
        summary.setWordWrap(True)
        row_layout.addWidget(summary)
        row._summary_label = summary

        params_layout = QGridLayout()
        params_layout.setHorizontalSpacing(8)
        params_layout.setVerticalSpacing(4)
        for i, (pname, pkey, ptype) in enumerate(schema):
            lbl = QLabel(pname)
            style_muted_label(lbl)
            params_layout.addWidget(lbl, i // 2, (i % 2) * 2)
            if isinstance(ptype, list):
                w = QComboBox()
                w.blockSignals(True)
                w.addItems(ptype)
                if params.get(pkey) in ptype:
                    w.setCurrentText(params.get(pkey, ""))
                w.blockSignals(False)
                w.currentTextChanged.connect(
                    lambda val, k=pkey, si=step_idx: self._update_param(si, k, val)
                )
            else:
                w = QLineEdit()
                w.setPlaceholderText(pname)
                w.blockSignals(True)
                if params.get(pkey):
                    w.setText(params.get(pkey, ""))
                w.blockSignals(False)
                w.textChanged.connect(
                    lambda val, k=pkey, si=step_idx: self._update_param(si, k, val)
                )
            params_layout.addWidget(w, i // 2, (i % 2) * 2 + 1)
        row_layout.addLayout(params_layout)
        row.setProperty("step_idx", step_idx)
        # 插在 stretch 之前；empty hint 在最前，有步骤时已隐藏
        insert_at = max(0, self.steps_layout.count() - 1)
        self.steps_layout.insertWidget(insert_at, row)

    def _undo_last(self):
        """撤销最后一步."""
        if not shared_pipeline.steps:
            return
        shared_pipeline.steps.pop()
        self._rebuild_steps()
        self._notify_change()

    def _clear_all(self):
        shared_pipeline.steps = []
        self._built_steps = []
        for i in range(self.steps_layout.count() - 1, -1, -1):
            w = self.steps_layout.itemAt(i).widget()
            if w is not None and w.property("step_idx") is not None:
                w.deleteLater()
        self.code_preview.clear()
        self._refresh_empty_hint()
        # 与解析器同步空步骤（避免标记残留）
        shared_pipeline.update_from_builder([])

    # ---- 案例模板 ----
    # group / desc 用于下拉分组与说明；steps 只写差异参数，其余走默认值
    _TEMPLATE_DEFS = [
        {
            "name": "简单AES解密",
            "group": "解密",
            "desc": "请求体 data 字段 AES-ECB 解密 — 解密端最常用",
            "steps": [
                {
                    "type": "🔓 解密字段",
                    "params": {
                        "field": "data",
                        "algo": "AES",
                        "mode": "ECB",
                        "key": "your-16-byte-key!",
                        "padding": "PKCS7",
                    },
                },
            ],
        },
        {
            "name": "简单AES加密",
            "group": "加密",
            "desc": "请求体 data 字段 AES-ECB 加密 — 加密端回包前",
            "steps": [
                {
                    "type": "🔒 加密字段",
                    "params": {
                        "field": "data",
                        "algo": "AES",
                        "mode": "ECB",
                        "key": "your-16-byte-key!",
                        "padding": "PKCS7",
                    },
                },
            ],
        },
        {
            "name": "简单RSA加密",
            "group": "加密",
            "desc": "字段 RSA-OAEP 公钥加密（登录密码等短字段常见）",
            "steps": [
                {
                    "type": "🔒 加密字段",
                    "params": {
                        "field": "password",
                        "algo": "RSA",
                        "mode": "OAEP",
                        "key": "-----BEGIN PUBLIC KEY-----\n...(粘贴 PEM)...\n-----END PUBLIC KEY-----",
                        "padding": "OAEP",
                    },
                },
            ],
        },
        {
            "name": "AES+签名+时间戳",
            "group": "加密",
            "desc": "加密 data + SHA256/HMAC 头签名 + 时间戳与 nonce",
            "steps": [
                {
                    "type": "🔒 加密字段",
                    "params": {
                        "field": "data",
                        "algo": "AES",
                        "mode": "ECB",
                        "key": "your-16-byte-key!",
                        "padding": "PKCS7",
                    },
                },
                {
                    "type": "📝 签名(Hash)",
                    "params": {
                        "algo": "SHA256",
                        "source": "data",
                        "output": "hex",
                        "target_type": "Header",
                        "target": "X-Sign",
                    },
                },
                {
                    "type": "📝 签名(HMAC带密钥)",
                    "params": {
                        "algo": "HMAC-SHA256",
                        "hmac_key": "your-hmac-key",
                        "source": "data",
                        "output": "base64",
                        "target_type": "Header",
                        "target": "X-HMAC",
                    },
                },
                {
                    "type": "🏷 设置Header",
                    "params": {
                        "header_name": "X-Timestamp",
                        "value_type": "⏰ 时间戳(毫秒)",
                        "value": "",
                    },
                },
                {
                    "type": "🎲 生成随机数",
                    "params": {"rand_type": "16位hex", "target_field": "nonce"},
                },
            ],
        },
        {
            "name": "3DES+AuthToken",
            "group": "加密",
            "desc": "3DES 加密 + Hash 签名 + AuthToken 头",
            "steps": [
                {
                    "type": "🔒 加密字段",
                    "params": {
                        "field": "data",
                        "algo": "3DES",
                        "mode": "ECB",
                        "key": "your-24-byte-3des-key!!",
                        "padding": "PKCS7",
                    },
                },
                {
                    "type": "📝 签名(Hash)",
                    "params": {
                        "algo": "SHA256",
                        "source": "data",
                        "output": "hex",
                        "target_type": "Header",
                        "target": "signature",
                    },
                },
                {
                    "type": "🔐 AuthToken生成",
                    "params": {
                        "base_key": "your-24-byte-3des-key!!",
                        "jwt_src": "Header字段",
                        "jwt_value": "Authorization",
                        "sign_source": "data",
                        "origin": "https://example.com",
                        "strip_prefix": "/api",
                        "algo": "AES",
                    },
                },
                {
                    "type": "🏷 设置Header",
                    "params": {
                        "header_name": "Content-Type",
                        "value_type": "📝 固定文本",
                        "value": "application/json",
                    },
                },
            ],
        },
        {
            "name": "动态密钥(响应提取)",
            "group": "高级",
            "desc": "从响应提取密钥变量，再加密并签名",
            "steps": [
                {
                    "type": "🔑 提取密钥(从响应)",
                    "params": {
                        "key_name": "encKey",
                        "source_type": "响应body字段",
                        "source_path": "result.secretKey",
                    },
                },
                {
                    "type": "🔒 加密字段",
                    "params": {
                        "field": "data",
                        "algo": "AES",
                        "mode": "ECB",
                        "key": "$encKey",
                        "padding": "PKCS7",
                    },
                },
                {
                    "type": "📝 签名(Hash)",
                    "params": {
                        "algo": "SHA256",
                        "source": "data",
                        "output": "hex",
                        "target_type": "Header",
                        "target": "X-Sign",
                    },
                },
            ],
        },
        {
            "name": "时间戳+MD5签名",
            "group": "高级",
            "desc": "生成 _t 与 nonce，对 _t 做 MD5 写入 Header",
            "steps": [
                {
                    "type": "⏰ 生成时间戳",
                    "params": {
                        "ts_type": "毫秒时间戳",
                        "target_field": "_t",
                        "scope": "📋 Body (JSON)",
                    },
                },
                {
                    "type": "🎲 生成随机数",
                    "params": {
                        "rand_type": "16位hex",
                        "target_field": "nonce",
                        "scope": "📋 Body (JSON)",
                    },
                },
                {
                    "type": "📝 签名(Hash)",
                    "params": {
                        "algo": "MD5",
                        "source": "_t",
                        "output": "hex",
                        "target_type": "Header",
                        "target": "signData",
                    },
                },
            ],
        },
        {
            "name": "排序拼接签名",
            "group": "高级",
            "desc": "URL Query 排序拼接 + secret 后缀 MD5 → sign",
            "steps": [
                {
                    "type": "🎲 生成随机数",
                    "params": {
                        "rand_type": "16位hex",
                        "target_field": "nonce",
                        "scope": "🔗 URL Query",
                    },
                },
                {
                    "type": "📝 签名(排序拼接)",
                    "params": {
                        "algo": "MD5",
                        "data_scope": "🔗 URL Query",
                        "separator": "|",
                        "secret_suffix": "your-secret-key",
                        "include_key": "否(仅value|)",
                        "target_type": "URL参数字段",
                        "target": "sign",
                    },
                },
            ],
        },
    ]

    # 兼容旧代码：name → steps
    @property
    def _TEMPLATES(self) -> dict:
        return {t["name"]: t["steps"] for t in self._TEMPLATE_DEFS}

    def _populate_template_combo(self) -> None:
        self.template_combo.blockSignals(True)
        self.template_combo.clear()
        self.template_combo.addItem("选择案例加载…", None)
        last_group = None
        for tpl in self._TEMPLATE_DEFS:
            if tpl["group"] != last_group:
                # 分组标题（不可选）
                idx = self.template_combo.count()
                self.template_combo.addItem(f"── {tpl['group']} ──")
                model = self.template_combo.model()
                item = model.item(idx) if hasattr(model, "item") else None
                if item is not None:
                    item.setEnabled(False)
                last_group = tpl["group"]
            self.template_combo.addItem(tpl["name"], tpl)
            tip_idx = self.template_combo.count() - 1
            self.template_combo.setItemData(
                tip_idx, tpl["desc"], Qt.ItemDataRole.ToolTipRole
            )
        self.template_combo.blockSignals(False)

    def _on_template_picked(self, index: int) -> None:
        tpl = self.template_combo.itemData(index)
        if not isinstance(tpl, dict):
            return
        self._load_template(tpl["name"])

    def _load_template(self, name: str):
        tpl = next((t for t in self._TEMPLATE_DEFS if t["name"] == name), None)
        if tpl is None:
            return
        steps = tpl["steps"]
        desc = tpl.get("desc") or ""
        msg = f"将加载「{name}」共 {len(steps)} 步，并清空当前步骤。"
        if desc:
            msg = f"{desc}\n\n{msg}"
        reply = QMessageBox.question(
            self,
            "加载案例",
            msg + "\n\n确认加载？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        # 无论是否确认都复位下拉，避免重复触发
        self.template_combo.blockSignals(True)
        self.template_combo.setCurrentIndex(0)
        self.template_combo.blockSignals(False)
        if reply != QMessageBox.StandardButton.Yes:
            return

        built = []
        for step in steps:
            params = self._default_params(step["type"])
            params.update(step.get("params") or {})
            built.append({"type": step["type"], "params": params})
        shared_pipeline.steps = built
        self._rebuild_steps()
        self._notify_change()
        if hasattr(self, "template_hint"):
            self.template_hint.setText(f"已加载「{name}」— {desc}")
        log_signal.append_log.emit("INFO", f"已加载案例模板: {name}")

    def _preview_code(self):
        if shared_pipeline.steps:
            self.code_preview.setPlainText(
                codegen_for_pipeline(
                    shared_pipeline.steps,
                    shared_pipeline.body_format,
                    _profile_from_window(self.window()),
                )
            )
        elif hasattr(shared_pipeline, "_plugin_code") and shared_pipeline._plugin_code:
            self.code_preview.setPlainText(shared_pipeline._plugin_code)
        self._refresh_empty_hint()

    def _copy_code(self):
        QApplication.clipboard().setText(self.code_preview.toPlainText())
        QMessageBox.information(self, "已复制", "代码已复制到剪贴板")

    def _save_plugin(self):
        code = codegen_for_pipeline(shared_pipeline.steps, shared_pipeline.body_format, _profile_from_window(self.window()))
        if not code or not shared_pipeline.steps:
            QMessageBox.information(self, "提示", "请先添加操作步骤")
            return
        main_win = self.window()
        name = ""
        if hasattr(main_win, "control"):
            name = main_win.control.profile_combo.currentText()
        if not name:
            name, ok = QInputDialog.getText(self, "保存代码", "项目名称:")
            if not ok or not name.strip():
                return
            name = normalize_project_name(name.strip())
        plugin_name = get_plugin_name(name) or name
        plugin_dir = os.path.join(PLUGINS_DIR, plugin_name)
        os.makedirs(plugin_dir, exist_ok=True)
        with open(os.path.join(plugin_dir, "plugin.py"), "w", encoding="utf-8") as f:
            f.write(code)
        shared_pipeline._plugin_code = code
        state_path = os.path.join(plugin_dir, "state.json")
        raw = getattr(main_win.control, "_last_raw", "") if hasattr(main_win, "control") else ""
        with open(state_path, "w", encoding="utf-8") as f:
            json.dump({
                "steps": shared_pipeline.steps,
                "parsed_fields": shared_pipeline.parsed_fields,
                "raw_input": raw,
            }, f, ensure_ascii=False)
        profile_path = os.path.join(PROFILES_DIR, f"{name}.yaml")
        if not os.path.exists(profile_path):
            with open(profile_path, "w", encoding="utf-8") as f:
                f.write(
                    f"name: {name}\ndescription: ''\nplugin: {plugin_name}\n"
                    f"roles: [decrypt, encrypt]\n{default_profile_match_yaml()}"
                )
        log_signal.append_log.emit("INFO", f"可视化构建器: 已保存代码 → 项目 {name}")
        QMessageBox.information(self, "成功", f"代码已保存到 plugins/{plugin_name}/plugin.py")

# ============================================================
# 加密分析 Tab (集成analyzer)
# ============================================================
class CryptoAnalyzerTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        head = QLabel("粘贴密文、Token 或编码串，自动识别类型")
        head.setWordWrap(True)
        style_muted_label(head)
        layout.addWidget(head)

        self.analyze_input = QPlainTextEdit()
        setup_mono_field(self.analyze_input)
        self.analyze_input.setPlaceholderText("粘贴密文、Base64、Hex、JWT Token…")
        self.analyze_input.setMinimumHeight(120)
        layout.addWidget(self.analyze_input)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        analyze_btn = QPushButton("分析")
        analyze_btn.clicked.connect(self._analyze)
        style_button(analyze_btn, "primary")
        set_btn_icon(analyze_btn, "analyzer")
        btn_row.addWidget(analyze_btn)
        clear_btn = QPushButton("清空")
        clear_btn.clicked.connect(self._clear)
        style_button(clear_btn, "ghost")
        set_btn_icon(clear_btn, "clear")
        btn_row.addWidget(clear_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        result_lbl = QLabel("识别结果")
        result_lbl.setObjectName("cryptoFieldLabel")
        layout.addWidget(result_lbl)
        self.result_view = QTreeWidget()
        self.result_view.setHeaderLabels(["类型", "详情"])
        self.result_view.setColumnWidth(0, 200)
        self.result_view.setAlternatingRowColors(True)
        self.result_view.setRootIsDecorated(False)
        layout.addWidget(self.result_view, 1)
        self.empty_hint = QLabel("尚无结果。粘贴数据后点「分析」。")
        self.empty_hint.setObjectName("analyzerEmptyHint")
        self.empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_hint.setWordWrap(True)
        layout.addWidget(self.empty_hint)
        self._show_empty(True)

    def _show_empty(self, empty: bool) -> None:
        self.empty_hint.setVisible(empty)
        self.result_view.setVisible(not empty)

    def _clear(self) -> None:
        self.analyze_input.clear()
        self.result_view.clear()
        self._show_empty(True)

    def _analyze(self):
        text = self.analyze_input.toPlainText().strip()
        if not text:
            return
        self.result_view.clear()
        try:
            from analyzer.crypto_detector import detect
            results = detect(text)
            for type_name, detail in results:
                QTreeWidgetItem(self.result_view, [type_name, detail])
            self.result_view.expandAll()
        except ImportError:
            # fallback: 简单分析
            self._simple_analyze(text)
        self._show_empty(self.result_view.topLevelItemCount() == 0)

    def _simple_analyze(self, text):
        if len(text) >= 8 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in text):
            QTreeWidgetItem(self.result_view, ["Base64编码", f"长度 {len(text)}"])
            try:
                d = base64.b64decode(text); QTreeWidgetItem(self.result_view, ["→解码", f"{len(d)} 字节"])
                try:
                    t = d.decode("utf-8")
                    if t.isprintable(): QTreeWidgetItem(self.result_view, ["→UTF-8", t[:60]])
                except: pass
            except: QTreeWidgetItem(self.result_view, ["→解码失败", ""])
        if len(text) >= 6 and all(c in '0123456789abcdefABCDEF' for c in text):
            QTreeWidgetItem(self.result_view, ["Hex编码", f"长度 {len(text)}"])
        if text.count(".") == 2: QTreeWidgetItem(self.result_view, ["可能JWT", f"{len(text)} 字符"])


# ============================================================
# 加解密测试 Tab (保留, 从旧版)
# ============================================================
class CryptoTab(QWidget):
    _FUNC_TREE = CRYPTO_FUNC_TREE

    _AES_MODES = ["ECB", "CBC", "CFB", "OFB", "CTR", "GCM"]
    _BLOCK_MODES = ["ECB", "CBC"]
    _RSA_MODES = ["OAEP", "PKCS1v15"]
    _SM2_MODES = ["C1C3C2", "C1C2C3"]
    _IV_MODES = {"CBC", "CFB", "OFB", "GCM"}

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("cryptoWorkbench")
        self._build_ui()
        self._on_algo_changed(self.algo_cb.currentText())

    def _field_label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName("cryptoFieldLabel")
        return lbl

    def _build_ui(self):
        top = QVBoxLayout(self)
        top.setContentsMargins(0, 0, 0, 0)
        top.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        # ---- 左侧：内置函数 ----
        func_panel = QFrame()
        func_panel.setObjectName("cryptoSidePanel")
        fl = QVBoxLayout(func_panel)
        fl.setContentsMargins(12, 12, 12, 12)
        fl.setSpacing(8)
        side_title = QLabel("内置函数")
        side_title.setObjectName("cryptoPanelTitle")
        fl.addWidget(side_title)
        side_hint = QLabel("双击填入明文区")
        style_muted_label(side_hint)
        fl.addWidget(side_hint)
        self.func_tree = QTreeWidget()
        self.func_tree.setHeaderHidden(True)
        self.func_tree.setMinimumWidth(200)
        self.func_tree.setAlternatingRowColors(True)
        self.func_tree.itemDoubleClicked.connect(self._on_func_double_clicked)
        for cat, funcs in self._FUNC_TREE.items():
            ci = QTreeWidgetItem(self.func_tree, [cat])
            for n in funcs:
                QTreeWidgetItem(ci, [n])
        self.func_tree.expandAll()
        fl.addWidget(self.func_tree, 1)
        scan_btn = QPushButton("扫描密钥")
        scan_btn.clicked.connect(self._scan_key)
        style_button(scan_btn, "ghost")
        set_btn_icon(scan_btn, "search")
        fl.addWidget(scan_btn)
        self.scan_result = QLabel("")
        self.scan_result.setWordWrap(True)
        style_muted_label(self.scan_result)
        fl.addWidget(self.scan_result)
        splitter.addWidget(func_panel)

        # ---- 右侧：算法 + 编码（可纵向拉伸）----
        right = QSplitter(Qt.Orientation.Vertical)
        right.setChildrenCollapsible(False)

        crypto_grp = QGroupBox("算法加解密")
        cg = QVBoxLayout(crypto_grp)
        cg.setContentsMargins(12, 14, 12, 12)
        cg.setSpacing(8)

        ar = QHBoxLayout()
        ar.setSpacing(8)
        ar.addWidget(self._field_label("算法"))
        self.algo_cb = QComboBox()
        self.algo_cb.addItems(["AES", "DES", "3DES", "SM4", "RSA", "SM2", "XOR"])
        configure_combo_popup(self.algo_cb)
        self.algo_cb.currentTextChanged.connect(self._on_algo_changed)
        ar.addWidget(self.algo_cb)
        ar.addWidget(self._field_label("模式"))
        self.mode_cb = QComboBox()
        configure_combo_popup(self.mode_cb)
        self.mode_cb.currentTextChanged.connect(lambda _m: self._update_iv_visibility())
        ar.addWidget(self.mode_cb)
        self.pad_label = self._field_label("填充")
        ar.addWidget(self.pad_label)
        self.pad_cb = QComboBox()
        self.pad_cb.addItems(["PKCS7", "PKCS5", "ZeroPadding", "NoPadding"])
        configure_combo_popup(self.pad_cb)
        ar.addWidget(self.pad_cb)
        ar.addStretch()
        cg.addLayout(ar)

        kr = QHBoxLayout()
        kr.setSpacing(8)
        kr.addWidget(self._field_label("密钥"))
        self.key_edit = QLineEdit()
        self.key_edit.setPlaceholderText("对称密钥 / RSA PEM 公钥或私钥")
        setup_mono_field(self.key_edit)
        kr.addWidget(self.key_edit, 1)
        self.iv_label = self._field_label("IV")
        kr.addWidget(self.iv_label)
        self.iv_edit = QLineEdit()
        self.iv_edit.setPlaceholderText("CBC/GCM 等需要")
        setup_mono_field(self.iv_edit)
        self.iv_edit.setMaximumWidth(180)
        kr.addWidget(self.iv_edit)
        cg.addLayout(kr)

        cg.addWidget(self._field_label("明文"))
        self.pt_edit = QPlainTextEdit()
        setup_mono_field(self.pt_edit)
        self.pt_edit.setPlaceholderText("输入明文…")
        self.pt_edit.setMinimumHeight(100)
        cg.addWidget(self.pt_edit, 1)

        br = QHBoxLayout()
        br.setSpacing(10)
        br.addStretch()
        self.enc_btn = QPushButton("加密 →")
        self.enc_btn.clicked.connect(self._encrypt)
        self.dec_btn = QPushButton("← 解密")
        self.dec_btn.clicked.connect(self._decrypt)
        style_button(self.enc_btn, "primary")
        style_button(self.dec_btn, "ghost")
        set_btn_icon(self.enc_btn, "encrypt")
        set_btn_icon(self.dec_btn, "decrypt")
        br.addWidget(self.enc_btn)
        br.addWidget(self.dec_btn)
        br.addStretch()
        cg.addLayout(br)

        cg.addWidget(self._field_label("密文（Base64）"))
        self.ct_edit = QPlainTextEdit()
        setup_mono_field(self.ct_edit)
        self.ct_edit.setPlaceholderText("加密输出 / 解密输入…")
        self.ct_edit.setMinimumHeight(100)
        cg.addWidget(self.ct_edit, 1)
        right.addWidget(crypto_grp)

        util_grp = QGroupBox("编码 / 哈希")
        ug = QVBoxLayout(util_grp)
        ug.setContentsMargins(12, 14, 12, 12)
        ug.setSpacing(8)
        ug.addWidget(self._field_label("输入"))
        self.tool_input = QPlainTextEdit()
        setup_mono_field(self.tool_input)
        self.tool_input.setPlaceholderText("待处理文本（可与上方明文独立；留空则用明文）")
        self.tool_input.setMinimumHeight(72)
        ug.addWidget(self.tool_input, 1)

        ur = QHBoxLayout()
        ur.setSpacing(8)
        ur.addWidget(self._field_label("操作"))
        self.encode_cb = QComboBox()
        self.encode_cb.addItems(list(ENCODING_FUNCTIONS.keys()) + list(HASH_FUNCTIONS.keys()))
        configure_combo_popup(self.encode_cb)
        ur.addWidget(self.encode_cb, 1)
        self.encode_btn = QPushButton("执行")
        self.encode_btn.clicked.connect(self._do_encode)
        style_button(self.encode_btn, "primary")
        ur.addWidget(self.encode_btn)
        ug.addLayout(ur)

        ug.addWidget(self._field_label("结果"))
        self.tool_output = QPlainTextEdit()
        self.tool_output.setReadOnly(True)
        setup_mono_field(self.tool_output)
        self.tool_output.setPlaceholderText("编码 / 哈希结果…")
        self.tool_output.setMinimumHeight(72)
        ug.addWidget(self.tool_output, 1)
        right.addWidget(util_grp)
        right.setStretchFactor(0, 3)
        right.setStretchFactor(1, 2)
        right.setSizes([420, 260])

        splitter.addWidget(right)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([240, 780])
        top.addWidget(splitter)

    def _on_algo_changed(self, algo: str):
        self.mode_cb.blockSignals(True)
        self.pad_cb.blockSignals(True)
        self.mode_cb.clear()
        self.mode_cb.setEnabled(True)
        if algo == "RSA":
            self.mode_cb.addItems(self._RSA_MODES)
            self.pad_label.hide()
            self.pad_cb.hide()
            self.iv_label.hide()
            self.iv_edit.hide()
            self.key_edit.setPlaceholderText("RSA PEM 公钥（加密）或私钥（解密）")
        elif algo == "SM2":
            self.mode_cb.addItems(self._SM2_MODES)
            self.pad_label.hide()
            self.pad_cb.hide()
            self.iv_label.hide()
            self.iv_edit.hide()
            self.key_edit.setPlaceholderText("SM2 公钥 hex（加密）或私钥 hex（解密）")
        elif algo == "XOR":
            self.mode_cb.addItem("—")
            self.mode_cb.setEnabled(False)
            self.pad_label.hide()
            self.pad_cb.hide()
            self.iv_label.hide()
            self.iv_edit.hide()
            self.key_edit.setPlaceholderText("XOR 密钥")
        else:
            self.pad_label.show()
            self.pad_cb.show()
            self.key_edit.setPlaceholderText("对称密钥")
            modes = self._BLOCK_MODES if algo in ("DES", "3DES", "SM4") else self._AES_MODES
            self.mode_cb.addItems(modes)
            if self.pad_cb.count() == 0:
                self.pad_cb.addItems(["PKCS7", "PKCS5", "ZeroPadding", "NoPadding"])
            self.pad_cb.setEnabled(True)
            self._update_iv_visibility()
        self.mode_cb.blockSignals(False)
        self.pad_cb.blockSignals(False)

    def _update_iv_visibility(self):
        algo = self.algo_cb.currentText()
        mode = self.mode_cb.currentText()
        need_iv = algo in ("AES", "DES", "3DES", "SM4") and mode in self._IV_MODES
        self.iv_label.setVisible(need_iv)
        self.iv_edit.setVisible(need_iv)

    def _get_algo(self):
        algo = self.algo_cb.currentText()
        key = self.key_edit.text().strip()
        if algo == "RSA":
            if not key or "BEGIN" not in key:
                raise ValueError("RSA 请在密钥框粘贴 PEM 格式公钥或私钥")
            return create_algorithm({
                "algorithm": "RSA",
                "key": key,
                "padding": self.mode_cb.currentText(),
            })
        if algo == "SM2":
            if not key:
                raise ValueError("SM2 请填写公钥/私钥 hex")
            return create_algorithm({
                "algorithm": "SM2",
                "key": key,
                "mode": self.mode_cb.currentText(),
            })
        cfg = {
            "algorithm": algo,
            "mode": self.mode_cb.currentText(),
            "key": key or "1234567890abcdef",
            "padding": self.pad_cb.currentText(),
        }
        iv = self.iv_edit.text().strip()
        if iv:
            cfg["iv"] = iv
        return create_algorithm(cfg)

    def _encrypt(self):
        pt = self.pt_edit.toPlainText()
        if not pt.strip():
            QMessageBox.information(self, "提示", "请输入明文")
            return
        try:
            self.ct_edit.setPlainText(self._get_algo().encrypt(pt.strip()))
        except Exception as e:
            QMessageBox.critical(self, "加密失败", str(e))

    def _decrypt(self):
        ct = self.ct_edit.toPlainText()
        if not ct.strip():
            QMessageBox.information(self, "提示", "请输入密文")
            return
        try:
            self.pt_edit.setPlainText(self._get_algo().decrypt(ct.strip()))
        except Exception as e:
            QMessageBox.critical(self, "解密失败", str(e))

    def _do_encode(self):
        action = self.encode_cb.currentText()
        text = self.tool_input.toPlainText().strip()
        if not text:
            text = self.pt_edit.toPlainText().strip()
        if not text:
            QMessageBox.information(self, "提示", "请在「编码/哈希」或明文区输入内容")
            return
        try:
            if action in ENCODING_FUNCTIONS:
                result = ENCODING_FUNCTIONS[action](text)
            elif action in HASH_FUNCTIONS:
                result = HASH_FUNCTIONS[action](text)
            else:
                return
            self.tool_output.setPlainText(result)
        except Exception as e:
            QMessageBox.critical(self, "执行失败", str(e))

    def _on_func_double_clicked(self, item):
        if item.childCount() > 0:
            return
        parent = item.parent()
        if parent is None:
            return
        cat = parent.text(0)
        fn = self._FUNC_TREE.get(cat, {}).get(item.text(0))
        if not fn:
            return
        try:
            src = self.pt_edit.toPlainText().strip() or self.tool_input.toPlainText().strip()
            try:
                result = fn(src)
            except TypeError:
                result = fn()
            self.pt_edit.setPlainText(str(result))
        except Exception as e:
            QMessageBox.critical(self, "失败", str(e))

    def _scan_key(self):
        text = (
            self.pt_edit.toPlainText().strip()
            or self.ct_edit.toPlainText().strip()
            or self.tool_input.toPlainText().strip()
        )
        if not text:
            QMessageBox.information(self, "提示", "请先在明文/密文/编码区输入待扫描文本")
            return
        patterns = {
            "16字节ASCII密钥": r"\b[a-zA-Z0-9]{16}\b",
            "24字节密钥": r"\b[a-zA-Z0-9]{24}\b",
            "32字节密钥": r"\b[a-zA-Z0-9]{32}\b",
            "Base64值": r"[A-Za-z0-9+/]{20,}={0,2}",
            "Hex(32+)": r"\b[a-fA-F0-9]{32,}\b",
        }
        rs = []
        for label, pat in patterns.items():
            matches = re.findall(pat, text)
            if matches:
                uniq = list(dict.fromkeys(matches))[:3]
                rs.append(f"{label}: {', '.join(uniq)}")
        self.scan_result.setText("\n".join(rs) if rs else "未检测到密钥模式")
        style_feedback(self.scan_result, "success" if rs else "muted")


# ============================================================
# 独立日志窗口（解密端 / 加密端）
# ============================================================
class ProxyLogWindow(QWidget):
    """非模态独立窗口，与 LogTab 对应分栏共享同一文档."""

    def __init__(self, title: str, source_view: QPlainTextEdit, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setWindowFlags(
            Qt.WindowType.Window
            | Qt.WindowType.WindowCloseButtonHint
            | Qt.WindowType.WindowMinMaxButtonsHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, False)
        self.resize(780, 520)
        self.setMinimumSize(480, 320)
        self._source_view = source_view

        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        self.view = QPlainTextEdit()
        self.view.setReadOnly(True)
        self.view.setDocument(source_view.document())
        self.view.setMaximumBlockCount(source_view.maximumBlockCount())
        setup_log_view(self.view)
        root.addWidget(self.view)

        br = QHBoxLayout()
        br.setContentsMargins(0, 4, 0, 0)
        br.addStretch()
        clear_btn = QPushButton("清空")
        clear_btn.setToolTip("清空本端日志")
        clear_btn.clicked.connect(self._clear)
        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(self.close)
        br.addWidget(clear_btn)
        br.addWidget(close_btn)
        root.addLayout(br)
        style_button(clear_btn, "ghost")
        style_button(close_btn, "ghost")
        set_btn_icon(clear_btn, "clear")

        apply_app_icon(self)
        source_view.document().contentsChanged.connect(self._follow_tail)
        self.view.moveCursor(QTextCursor.MoveOperation.End)

    def _clear(self) -> None:
        self._source_view.clear()

    def _follow_tail(self) -> None:
        if self.isVisible():
            self.view.moveCursor(QTextCursor.MoveOperation.End)

    def showEvent(self, event):
        super().showEvent(event)
        self.view.moveCursor(QTextCursor.MoveOperation.End)


# ============================================================
# 日志 Tab（全部 / 解密端 / 加密端 分栏）
# ============================================================
class LogTab(QWidget):
    CHANNEL_ALL = "all"
    CHANNEL_DECRYPT = "decrypt"
    CHANNEL_ENCRYPT = "encrypt"

    def __init__(self, parent=None):
        super().__init__(parent)
        self._views: dict[str, QPlainTextEdit] = {}
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        self.channel_tabs = QTabWidget()
        setup_sub_tabs(self.channel_tabs)
        for key, title in (
            (self.CHANNEL_ALL, "全部"),
            (self.CHANNEL_DECRYPT, "解密端"),
            (self.CHANNEL_ENCRYPT, "加密端"),
        ):
            view = QPlainTextEdit()
            view.setReadOnly(True)
            view.setMaximumBlockCount(5000)
            setup_log_view(view)
            self._views[key] = view
            self.channel_tabs.addTab(view, title)
        root.addWidget(self.channel_tabs)

        # 兼容旧代码仍引用 log_view
        self.log_view = self._views[self.CHANNEL_ALL]

        br = QHBoxLayout()
        br.setContentsMargins(0, 4, 0, 0)
        br.addStretch()
        cb = QPushButton("清空当前")
        cb.setToolTip("清空当前分栏日志")
        cb.clicked.connect(self._clear_current)
        br.addWidget(cb)
        ca = QPushButton("清空全部")
        ca.setToolTip("清空三个分栏")
        ca.clicked.connect(self.clear_all)
        br.addWidget(ca)
        root.addLayout(br)
        style_button(cb, "ghost")
        style_button(ca, "ghost")
        set_btn_icon(cb, "clear")
        set_btn_icon(ca, "clear")

    def channel_view(self, channel: str) -> QPlainTextEdit | None:
        key = self._normalize_channel(channel)
        if key in (self.CHANNEL_DECRYPT, self.CHANNEL_ENCRYPT):
            return self._views.get(key)
        return None

    def _clear_current(self) -> None:
        w = self.channel_tabs.currentWidget()
        if isinstance(w, QPlainTextEdit):
            w.clear()

    def clear_all(self) -> None:
        for v in self._views.values():
            v.clear()

    def show_channel(self, channel: str) -> None:
        key = self._normalize_channel(channel)
        idx = {
            self.CHANNEL_ALL: 0,
            self.CHANNEL_DECRYPT: 1,
            self.CHANNEL_ENCRYPT: 2,
        }.get(key, 0)
        self.channel_tabs.setCurrentIndex(idx)

    @staticmethod
    def _normalize_channel(channel: str | None) -> str:
        c = (channel or "").strip().lower()
        if c in ("decrypt", "dec", "解密", "解密端"):
            return LogTab.CHANNEL_DECRYPT
        if c in ("encrypt", "enc", "加密", "加密端"):
            return LogTab.CHANNEL_ENCRYPT
        return LogTab.CHANNEL_ALL

    @classmethod
    def detect_channel(cls, msg: str) -> str:
        """从消息内容推断通道."""
        m = msg or ""
        up = m.upper()
        if (
            "[DECRYPT]" in up
            or "PROXY_ROLE=DECRYPT" in up
            or "解密端" in m
            or "解密端口" in m
        ):
            return cls.CHANNEL_DECRYPT
        if (
            "[ENCRYPT]" in up
            or "PROXY_ROLE=ENCRYPT" in up
            or "加密端" in m
            or "加密端口" in m
        ):
            return cls.CHANNEL_ENCRYPT
        if "代理链:" in m or "→ Burp" in m or "Burp 端口" in m:
            return cls.CHANNEL_DECRYPT
        return cls.CHANNEL_ALL

    def _append_to(self, view: QPlainTextEdit, level: str, msg: str) -> None:
        cm = LOG_COLORS
        fg, dim = C["code_fg"], "#8b929e"
        view.appendHtml(
            f'<span style="color:{dim}">[{datetime.now().strftime("%H:%M:%S")}]</span> '
            f'<span style="color:{cm.get(level, fg)}">{html.escape(msg)}</span>'
        )
        view.moveCursor(QTextCursor.MoveOperation.End)

    def append(self, level, msg, channel: str | None = None):
        """通用日志。channel 为空时自动识别 DECRYPT/ENCRYPT，并同步写入「全部」。"""
        ch = self._normalize_channel(channel) if channel else self.detect_channel(msg or "")
        display = msg or ""
        if ch == self.CHANNEL_DECRYPT:
            display = re.sub(r"^\[DECRYPT\]\s*", "", display, flags=re.I)
        elif ch == self.CHANNEL_ENCRYPT:
            display = re.sub(r"^\[ENCRYPT\]\s*", "", display, flags=re.I)

        self._append_to(self._views[self.CHANNEL_ALL], level, msg or "")
        if ch in (self.CHANNEL_DECRYPT, self.CHANNEL_ENCRYPT):
            self._append_to(self._views[ch], level, display)

    def append_http(self, tag, content, channel: str | None = None):
        content = content.replace(HTTP_LOG_BLANK, "")
        label = "请求" if "[request]" in tag else "响应"
        ts = datetime.now().strftime("%H:%M:%S")
        dim = "#8b929e"
        block = (
            f'<div style="margin:8px 0 4px 0;">'
            f'<span style="color:{dim}">[{ts}] {html.escape(label)}</span> '
            f'<span style="color:{dim}">{html.escape(tag)}</span>'
            f'<pre style="color:{C["code_fg"]}; background:{C["code_bg"]}; padding:8px; margin:4px 0 0 0; '
            f'border:1px solid {C["border"]}; white-space:pre-wrap; '
            f'font-family:Consolas,monospace; font-size:11px;">'
            f'{html.escape(content)}</pre></div>'
        )
        ch = self._normalize_channel(channel) if channel else self.detect_channel(tag or "")
        targets = [self._views[self.CHANNEL_ALL]]
        if ch in (self.CHANNEL_DECRYPT, self.CHANNEL_ENCRYPT):
            targets.append(self._views[ch])
        for view in targets:
            view.appendHtml(block)
            view.moveCursor(QTextCursor.MoveOperation.End)


# ============================================================
# 主窗口
# ============================================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.setMinimumSize(1200, 760)
        self.resize(1420, 900)
        self.decrypt_process = None; self.encrypt_process = None
        self._output_buffer = ""
        self._tls_warned = False
        self._match_miss_warned = False
        self._proxy_fail_tips: set[str] = set()
        self._decrypt_user_stop = False
        self._encrypt_user_stop = False
        self._http_log_buffer = None
        self._http_log_tag = ""
        self._http_log_channel = None
        self._proxy_log_windows: dict[str, ProxyLogWindow] = {}
        self._mitm_line_prefix = re.compile(r"^\[\d{2}:\d{2}:\d{2}\.\d+\]\s*")
        self._build_ui(); self._connect_signals()
        apply_app_icon(self)
        self.control._refresh_profiles()  # 所有Tab创建完成后加载首个项目
        self._refresh_home_status()

    def showEvent(self, event):
        super().showEvent(event)
        self.refresh_window_frame()

    def refresh_window_frame(self) -> None:
        """Windows: 标题栏/边框与主题同色."""
        from core.window_frame import apply_window_frame
        from core.theme import current_theme, C
        apply_window_frame(self, current_theme(), C)

    def _build_ui(self):
        c = QWidget()
        self.setCentralWidget(c)
        s = QSplitter(Qt.Orientation.Horizontal)
        self.control = ControlPanel()
        self.control.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)
        s.addWidget(self.control)
        self.tabs = QTabWidget()
        setup_main_tabs(self.tabs)
        self.home_tab = HomeTab()
        # 主页 → AI 分析 → 其余
        self._tab_icon_names = (
            "home", "ai", "parser", "builder", "plugin", "analyzer", "setting",
        )
        self.tabs.addTab(self.home_tab, "主页")
        self.ai_lab_tab = AILabTab()
        self.tabs.addTab(self.ai_lab_tab, "AI 分析")
        self._start_burp_inbox()
        self.parser_tab = RequestParserTab()
        self.tabs.addTab(self.parser_tab, "解析器")
        self.visual_builder_tab = VisualBuilderTab()
        self.tabs.addTab(self.visual_builder_tab, "构建器")
        self.plugin_editor_tab = ExtensionEditorTab()
        self.tabs.addTab(self.plugin_editor_tab, "扩展")
        self.analyzer_tab = CryptoAnalyzerTab()
        self.tabs.addTab(self.analyzer_tab, "识别")
        self.crypto_tab = CryptoTab()
        self.log_tab = LogTab()
        self.settings_hub_tab = SettingsHubTab(
            self.control, self.crypto_tab, self.log_tab,
        )
        self.tabs.addTab(self.settings_hub_tab, "设置")
        _tab_tips = (
            "主页总览",
            "AI 自动化分析 — Hook / 流量 / Agent",
            "请求解析器 — 粘贴报文、标记字段",
            "可视化构建器 — 步骤编排与代码预览",
            "插件扩展编辑器",
            "加密分析 — 编码识别",
            "设置 / 加解密测试 / 日志",
        )
        for i, tip in enumerate(_tab_tips):
            if i < self.tabs.count():
                self.tabs.setTabToolTip(i, tip)
        self.refresh_tab_icons()
        self.home_tab.bind_tabs(self.tabs, {
            "parser": self.parser_tab,
            "builder": self.visual_builder_tab,
            "editor": self.plugin_editor_tab,
            "plugin": self.plugin_editor_tab,
            "analyzer": self.analyzer_tab,
            "crypto": self.crypto_tab,
            "ai": self.ai_lab_tab,
            "log": self.log_tab,
            "settings": self.settings_hub_tab,
        })
        # 工作区嵌板（直角、无阴影，少一点模板感）
        work = QFrame()
        work.setObjectName("workspacePane")
        work_layout = QVBoxLayout(work)
        work_layout.setContentsMargins(0, 0, 0, 0)
        work_layout.setSpacing(0)
        work_layout.addWidget(self.tabs)
        s.addWidget(work)
        s.setSizes([248, 1032])
        s.setStretchFactor(0, 0)
        s.setStretchFactor(1, 1)
        ml = QHBoxLayout(c)
        ml.setContentsMargins(0, 0, 0, 0)
        ml.setSpacing(0)
        ml.addWidget(s)

    def open_settings_hub(self, page: int | None = None) -> None:
        """打开设置中心；page 见 SettingsHubTab.PAGE_*."""
        self.tabs.setCurrentWidget(self.settings_hub_tab)
        if page is None:
            page = SettingsHubTab.PAGE_GENERAL
        self.settings_hub_tab.show_page(page)

    def open_proxy_log(self, channel: str = "decrypt") -> None:
        """弹出解密端/加密端独立日志窗口（非模态，可与主界面并存）."""
        ch = LogTab._normalize_channel(channel)
        if ch not in (LogTab.CHANNEL_DECRYPT, LogTab.CHANNEL_ENCRYPT):
            ch = LogTab.CHANNEL_DECRYPT
        source = self.log_tab.channel_view(ch)
        if source is None:
            return
        titles = {
            LogTab.CHANNEL_DECRYPT: f"{APP_TITLE} — 解密端日志",
            LogTab.CHANNEL_ENCRYPT: f"{APP_TITLE} — 加密端日志",
        }
        win = self._proxy_log_windows.get(ch)
        if win is None:
            win = ProxyLogWindow(titles[ch], source, self)
            self._proxy_log_windows[ch] = win
        win.show()
        win.raise_()
        win.activateWindow()

    def _proxy_log(self, level: str, msg: str, channel: str) -> None:
        """写入指定通道的代理日志（同时进「全部」）."""
        self.log_tab.append(level, msg, channel)

    def refresh_tab_icons(self) -> None:
        """主题/切换后刷新 Tab 图标：选中用主色，其余用次级灰。"""
        names = getattr(self, "_tab_icon_names", None) or (
            "home", "ai", "parser", "builder", "plugin", "analyzer", "setting",
        )
        current = self.tabs.currentIndex()
        for idx, name in enumerate(names):
            if idx >= self.tabs.count():
                break
            # 解析器/构建器为彩色自定义图标，保持原色
            if name in ("parser", "builder"):
                self.tabs.setTabIcon(idx, icon(name))
            else:
                tint = C["primary"] if idx == current else C["text_dim"]
                self.tabs.setTabIcon(idx, icon(name, tint=tint))

    def _has_project(self) -> bool:
        c = self.control.profile_combo
        return c.count() > 0 and bool(c.currentText())

    def _on_main_tab_changed(self, index: int) -> None:
        """无项目时进入解析器/构建器，引导新建项目."""
        self.refresh_tab_icons()
        if index < 0:
            return
        w = self.tabs.widget(index)
        if w not in (self.parser_tab, self.visual_builder_tab):
            return
        if self._has_project():
            return
        QMessageBox.information(
            self, "需要项目",
            "当前还没有项目。\n\n请先新建一个加解密方案，再使用请求解析器或可视化构建器。",
        )
        self.control._new_project()
        if not self._has_project():
            self.tabs.blockSignals(True)
            self.tabs.setCurrentWidget(self.home_tab)
            self.tabs.blockSignals(False)
            self.refresh_tab_icons()

    def _connect_signals(self):
        self.control.start_decrypt.connect(self._start_decrypt)
        self.control.stop_decrypt.connect(self._stop_decrypt)
        self.control.start_encrypt.connect(self._start_encrypt)
        self.control.stop_encrypt.connect(self._stop_encrypt)
        self.control.view_decrypt_log.connect(lambda: self.open_proxy_log("decrypt"))
        self.control.view_encrypt_log.connect(lambda: self.open_proxy_log("encrypt"))
        log_signal.append_log.connect(self.log_tab.append)
        extension_signal.changed.connect(self._on_extensions_changed)
        self.tabs.currentChanged.connect(self._on_main_tab_changed)

    def _on_extensions_changed(self):
        if hasattr(self, "visual_builder_tab"):
            self.visual_builder_tab._preview_code()

    def _start_burp_inbox(self) -> None:
        """启动本机收件箱，接收 Burp 右键「发送到密桥」的流量。"""
        try:
            from core.burp_inbox import BurpFlowInbox

            self._burp_inbox = BurpFlowInbox(parent=self)
            self._burp_inbox.flows_received.connect(self._on_burp_flows_received)
            self._burp_inbox.status.connect(
                lambda m: log_signal.append_log.emit("INFO", m)
            )
            self._burp_inbox.start()
        except Exception as e:
            logging.warning("Burp inbox start failed: %s", e)

    def _on_burp_flows_received(self, flows: list) -> None:
        lab = getattr(self, "ai_lab_tab", None)
        if lab is None or not hasattr(lab, "ingest_burp_flows"):
            return
        n = lab.ingest_burp_flows(flows)
        if n:
            try:
                self.tabs.setCurrentWidget(lab)
            except Exception:
                pass
            log_signal.append_log.emit("INFO", f"Burp → 密桥「AI分析/网页/流量」：已导入 {n} 条")

    def _refresh_home_status(self) -> None:
        if hasattr(self, "home_tab"):
            self.home_tab.refresh_status(self.control)

    def _start_decrypt(self, port, profile=""):
        profile = profile or self.control.profile_combo.currentText()
        burp_port = self.control.burp_port.value()
        use_main = self.control.load_mode_combo.currentData() == "main"
        ch = LogTab.CHANNEL_DECRYPT
        if not profile:
            QMessageBox.warning(self, "提示", "请先在控制面板选择项目")
            return
        ok_role, role_msg = check_roles(profile, "decrypt")
        if not ok_role:
            QMessageBox.warning(self, "角色不可用", role_msg)
            self._proxy_log("WARNING", role_msg.replace("\n", " | "), ch)
            return
        plugin_script = get_plugin_script_path(profile)
        if not os.path.isfile(plugin_script):
            QMessageBox.warning(
                self, "插件不存在",
                f"未找到:\n{plugin_script}\n\n请在「可视化构建器」添加步骤并保存项目。",
            )
            return
        if port == burp_port:
            QMessageBox.warning(
                self, "端口冲突",
                f"解密端端口 ({port}) 与 Burp 端口相同，请修改其中一个。\n"
                "常见配置：Burp 8080，解密端监听 8083。",
            )
            return
        if is_port_in_use(port):
            msg = port_in_use_message(port, "解密端")
            QMessageBox.warning(self, "端口占用", msg)
            self._proxy_log("ERROR", msg.replace("\n", " | "), ch)
            return
        if is_port_in_use(burp_port):
            self._proxy_log(
                "INFO",
                f"检测到 :{burp_port} 已有服务（通常是 Burp）。请确认 Burp 已打开且端口一致。",
                ch,
            )
        else:
            self._proxy_log(
                "WARNING",
                f"Burp 端口 :{burp_port} 当前无进程监听。解密后转发可能失败，请先启动 Burp。",
                ch,
            )

        cert_level, cert_msg = check_cert_before_decrypt()
        if cert_level == "warn" and cert_msg:
            self._proxy_log("WARNING", cert_msg.replace("\n", " | "), ch)
            reply = QMessageBox.question(
                self, "HTTPS 证书未就绪",
                cert_msg,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        mitmdump = _resolve_mitmdump()
        if not _mitmdump_available():
            QMessageBox.warning(
                self, "未找到 mitmdump",
                "未找到 mitmdump。\n\n请 pip install mitmproxy，或将 mitmdump.exe 放在程序目录。",
            )
            self._proxy_log("ERROR", "未找到 mitmdump，无法启动解密端", ch)
            return

        auto_install_if_needed(self)
        if hasattr(self.control, "refresh_cert_status"):
            self.control.refresh_cert_status()
        _, args, env_map = build_proxy_launch(
            profile, "decrypt", port, use_main=use_main, burp_port=burp_port,
        )
        self._tls_warned = False
        self._match_miss_warned = False
        self._proxy_fail_tips = set()
        self.decrypt_process = QProcess(self)
        env = QProcessEnvironment.systemEnvironment()
        for k, v in env_map.items():
            env.insert(k, v)
        self.decrypt_process.setProcessEnvironment(env)
        self.decrypt_process.setWorkingDirectory(PROJECT_ROOT)
        self.decrypt_process.setProgram(mitmdump)
        self.decrypt_process.setArguments(args)
        self.decrypt_process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.decrypt_process.readyReadStandardOutput.connect(lambda: self._on_output(self.decrypt_process, "DECRYPT"))
        self.decrypt_process.finished.connect(lambda c, s: self._on_decrypt_finished(c, s, port))
        self.decrypt_process.start()
        if not self.decrypt_process.waitForStarted(5000):
            err = self.decrypt_process.errorString()
            QMessageBox.warning(
                self, "解密端启动失败",
                f"无法启动 mitmdump。\n\n{err}\n\n请确认 mitmdump 已安装且路径正确。",
            )
            self._proxy_log("ERROR", f"解密端启动失败: {err}", ch)
            self.decrypt_process = None
            return
        self.control.set_decrypt_running(True)
        self._refresh_home_status()
        mode_label = "main.py 框架" if use_main else "plugin.py 直接"
        self._proxy_log("INFO", f"解密端 [{mode_label}]: mitmdump {' '.join(args)}", ch)
        if use_main:
            self._proxy_log("INFO", f"PROFILE={profile} PROXY_ROLE=decrypt → Burp {burp_port}", ch)
        else:
            self._proxy_log(
                "INFO",
                f"直接加载 plugins/{get_plugin_name(profile) or profile}/plugin.py",
                ch,
            )
        self._proxy_log("INFO", f"代理链: 浏览器 → 127.0.0.1:{port} → Burp {burp_port}", ch)
        for tip in match_startup_tips(profile):
            self._proxy_log("INFO", tip, ch)
        plugin_rel = f"plugins/{get_plugin_name(profile) or profile}/plugin.py"
        load_hint = (
            f"加载: main.py (PROFILE={profile})\n"
            f"插件: {plugin_rel}\n\n"
            if use_main
            else f"插件: {plugin_rel}\n\n"
        )
        match_line = ""
        cfg = load_profile(profile)
        if cfg.get("match"):
            from core.launch_checks import format_match_summary
            match_line = f"匹配: {format_match_summary(cfg.get('match'))}\n\n"

        # AI「网页」浏览器若在跑：等 mitmdump 稍就绪后，关掉并用解密代理重开
        browser_line = ""
        lab = getattr(self, "ai_lab_tab", None)
        if lab is not None and hasattr(lab, "is_lab_browser_running") and lab.is_lab_browser_running():
            from PyQt6.QtCore import QTimer

            def _reattach_lab_browser(p=port, lab_ref=lab, channel=ch):
                try:
                    if not lab_ref.is_lab_browser_running():
                        return
                    if lab_ref.reattach_browser_to_decrypt_proxy(p):
                        self._proxy_log(
                            "INFO",
                            f"网页浏览器已安排接入 127.0.0.1:{p}",
                            channel,
                        )
                except Exception as e:
                    self._proxy_log(
                        "WARNING",
                        f"网页浏览器切换解密代理失败: {e}",
                        channel,
                    )

            QTimer.singleShot(800, _reattach_lab_browser)
            browser_line = (
                f"7. 检测到 AI「网页」浏览器 → 约 1 秒后自动切到 127.0.0.1:{port}\n"
                f"   （窗口会重启一次，已采流量/Hook/JS 保留）\n"
            )
            self._proxy_log(
                "INFO",
                f"检测到 AI 网页浏览器 → 将重开并代理 127.0.0.1:{port}",
                ch,
            )

        # 启动成功后直接弹出解密端日志窗
        self.open_proxy_log("decrypt")
        QMessageBox.information(
            self, "解密端已启动",
            f"项目: {profile}\n"
            f"模式: {mode_label}\n"
            f"{load_hint}"
            f"{match_line}"
            f"1. 浏览器代理 → 127.0.0.1:{port}\n"
            f"2. Burp 监听 → {burp_port}（请关闭 Intercept，否则会卡住）\n"
            f"3. 解密端已用 upstream 转发 Burp（勿在插件里再用 requests 转发）\n"
            f"4. 修改 plugin.py 后需重启解密端\n"
            f"5. 验证 HTTPS → https://mitm.it\n"
            f"6. 若字段未解密 → 看日志「未匹配」并点左侧「规则」\n"
            f"{browser_line}",
        )

    def _start_encrypt(self, port, profile=""):
        profile = profile or self.control.profile_combo.currentText()
        use_main = self.control.load_mode_combo.currentData() == "main"
        ch = LogTab.CHANNEL_ENCRYPT
        if not profile:
            QMessageBox.warning(self, "提示", "请先在控制面板选择项目")
            return
        ok_role, role_msg = check_roles(profile, "encrypt")
        if not ok_role:
            QMessageBox.warning(self, "角色不可用", role_msg)
            self._proxy_log("WARNING", role_msg.replace("\n", " | "), ch)
            return
        plugin_script = get_plugin_script_path(profile)
        if not os.path.isfile(plugin_script):
            QMessageBox.warning(
                self, "插件不存在",
                f"未找到:\n{plugin_script}\n\n请在「可视化构建器」添加步骤并保存项目。",
            )
            return
        if is_port_in_use(port):
            msg = port_in_use_message(port, "加密端")
            QMessageBox.warning(self, "端口占用", msg)
            self._proxy_log("ERROR", msg.replace("\n", " | "), ch)
            return
        mitmdump = _resolve_mitmdump()
        if not _mitmdump_available():
            QMessageBox.warning(
                self, "未找到 mitmdump",
                "未找到 mitmdump。\n\n请 pip install mitmproxy，或将 mitmdump.exe 放在程序目录。",
            )
            self._proxy_log("ERROR", "未找到 mitmdump，无法启动加密端", ch)
            return
        _, args, env_map = build_proxy_launch(profile, "encrypt", port, use_main=use_main)
        self._match_miss_warned = False
        self._proxy_fail_tips = set()
        self.encrypt_process = QProcess(self)
        env = QProcessEnvironment.systemEnvironment()
        for k, v in env_map.items():
            env.insert(k, v)
        self.encrypt_process.setProcessEnvironment(env)
        self.encrypt_process.setWorkingDirectory(PROJECT_ROOT)
        self.encrypt_process.setProgram(mitmdump)
        self.encrypt_process.setArguments(args)
        self.encrypt_process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.encrypt_process.readyReadStandardOutput.connect(lambda: self._on_output(self.encrypt_process, "ENCRYPT"))
        self.encrypt_process.finished.connect(lambda c, s: self._on_encrypt_finished(c, s, port))
        self.encrypt_process.start()
        if not self.encrypt_process.waitForStarted(5000):
            err = self.encrypt_process.errorString()
            QMessageBox.warning(
                self, "加密端启动失败",
                f"无法启动 mitmdump。\n\n{err}\n\n请确认 mitmdump 已安装且路径正确。",
            )
            self._proxy_log("ERROR", f"加密端启动失败: {err}", ch)
            self.encrypt_process = None
            return
        self.control.set_encrypt_running(True)
        self._refresh_home_status()
        mode_label = "main.py 框架" if use_main else "plugin.py 直接"
        self._proxy_log(
            "INFO",
            f"加密端 [{mode_label}]: mitmdump {' '.join(args)} (项目: {profile})",
            ch,
        )
        if use_main:
            self._proxy_log("INFO", f"PROFILE={profile} PROXY_ROLE=encrypt", ch)
        for tip in match_startup_tips(profile):
            self._proxy_log("INFO", tip, ch)

        # 通知 Burp 扩展：上游 → 本加密端口
        try:
            from core.burp_upstream import set_burp_upstream

            ok, msg = set_burp_upstream("127.0.0.1", int(port))
            self._proxy_log("INFO" if ok else "WARNING", msg, ch)
            if not ok:
                jar = os.path.join(PROJECT_ROOT, "tools", "burp", "CipherBridge-Upstream.jar")
                self._proxy_log(
                    "WARNING",
                    f"请在 Burp 加载扩展: {jar}",
                    ch,
                )
        except Exception as e:
            self._proxy_log("WARNING", f"通知 Burp 上游失败: {e}", ch)

        # 启动成功后直接弹出加密端日志窗
        self.open_proxy_log("encrypt")
        QMessageBox.information(
            self,
            "加密端已启动",
            f"项目: {profile}\n"
            f"加密端口: {port}\n\n"
            f"已尝试把 Burp 上游设为 127.0.0.1:{port}\n"
            f"（需已加载 tools/burp/CipherBridge-Upstream.jar）\n\n"
            f"链路: 浏览器 → 解密 → Burp → 加密:{port} → 服务器",
        )

    def _stop_decrypt(self):
        self._decrypt_user_stop = True
        port = self.control.decrypt_port.value() if hasattr(self, "control") else 0
        stop_qprocess(self.decrypt_process, wait_ms=1500, label="decrypt")
        if port:
            killed = free_listen_port(port, reason="stop decrypt")
            if killed:
                self._proxy_log(
                    "INFO",
                    f"已清理占用解密端口 :{port} 的残留进程 PID={killed}",
                    LogTab.CHANNEL_DECRYPT,
                )

    def _stop_encrypt(self):
        self._encrypt_user_stop = True
        port = self.control.encrypt_port.value() if hasattr(self, "control") else 0
        stop_qprocess(self.encrypt_process, wait_ms=1500, label="encrypt")
        if port:
            killed = free_listen_port(port, reason="stop encrypt")
            if killed:
                self._proxy_log(
                    "INFO",
                    f"已清理占用加密端口 :{port} 的残留进程 PID={killed}",
                    LogTab.CHANNEL_ENCRYPT,
                )
        try:
            from core.burp_upstream import clear_burp_upstream

            ok, msg = clear_burp_upstream()
            self._proxy_log(
                "INFO" if ok else "WARNING",
                msg,
                LogTab.CHANNEL_ENCRYPT,
            )
        except Exception as e:
            self._proxy_log(
                "WARNING",
                f"清除 Burp 上游失败: {e}",
                LogTab.CHANNEL_ENCRYPT,
            )

    def _kill(self, p):
        stop_qprocess(p, wait_ms=800, label="proxy")

    def _on_output(self, p, tag):
        if not p:
            return
        chunk = p.readAllStandardOutput().data().decode("utf-8", errors="replace")
        self._output_buffer += chunk
        while "\n" in self._output_buffer:
            line, self._output_buffer = self._output_buffer.split("\n", 1)
            self._process_output_line(line, tag)

    def _clean_proxy_line(self, line):
        return self._mitm_line_prefix.sub("", line)

    def _emit_proxy_tip(self, tip: str, *, level: str = "WARNING", once_key: str | None = None, channel: str | None = None) -> None:
        if not tip:
            return
        key = once_key or tip
        tips = getattr(self, "_proxy_fail_tips", None)
        if tips is None:
            self._proxy_fail_tips = set()
            tips = self._proxy_fail_tips
        if key in tips:
            return
        tips.add(key)
        ch = channel or LogTab.detect_channel(tip)
        if ch in (LogTab.CHANNEL_DECRYPT, LogTab.CHANNEL_ENCRYPT):
            self._proxy_log(level, tip.replace("\n", " | "), ch)
        else:
            log_signal.append_log.emit(level, tip.replace("\n", " | "))

    def _process_output_line(self, line, tag):
        line = self._clean_proxy_line(line)
        ch = (
            LogTab.CHANNEL_DECRYPT if tag == "DECRYPT"
            else LogTab.CHANNEL_ENCRYPT if tag == "ENCRYPT"
            else LogTab.CHANNEL_ALL
        )
        if HTTP_LOG_BEGIN in line:
            self._http_log_buffer = []
            idx = line.index(HTTP_LOG_BEGIN)
            self._http_log_tag = line[idx + len(HTTP_LOG_BEGIN):].strip()
            self._http_log_channel = ch
            return
        if line.strip() == HTTP_LOG_END:
            if self._http_log_buffer is not None:
                self.log_tab.append_http(
                    self._http_log_tag,
                    "\n".join(self._http_log_buffer),
                    getattr(self, "_http_log_channel", None),
                )
            self._http_log_buffer = None
            self._http_log_tag = ""
            self._http_log_channel = None
            return
        if self._http_log_buffer is not None:
            self._http_log_buffer.append("" if line.strip() == HTTP_LOG_BLANK else line)
            return
        if line.strip():
            tip = diagnose_proxy_line(line)
            if tip:
                if "证书" in tip or "TLS" in line or "tls handshake" in line.lower():
                    if not getattr(self, "_tls_warned", False):
                        self._tls_warned = True
                        self._emit_proxy_tip(tip, once_key="tls", channel=ch)
                elif "未匹配" in tip or "未匹配" in line or "跳过(未匹配" in line:
                    if not getattr(self, "_match_miss_warned", False):
                        self._match_miss_warned = True
                        self._emit_proxy_tip(tip, once_key="match", channel=ch)
                elif "端口" in tip:
                    self._emit_proxy_tip(tip, level="ERROR", once_key="port", channel=ch)
                else:
                    self._emit_proxy_tip(tip, once_key=tip[:40], channel=ch)
            self._proxy_log("INFO", f"[{tag}] {line.strip()}", ch)

    def _on_decrypt_finished(self, c, s, port: int = 8083):
        user_stop = getattr(self, "_decrypt_user_stop", False)
        self._decrypt_user_stop = False
        self.control.set_decrypt_running(False)
        self.decrypt_process = None
        self._refresh_home_status()
        hint = exit_code_hint(c, "解密端", port)
        ch = LogTab.CHANNEL_DECRYPT
        if user_stop or c == 0:
            self._proxy_log("INFO", "解密端已停止", ch)
            return
        self._proxy_log("ERROR", hint.replace("\n", " | "), ch)
        QMessageBox.warning(self, "解密端异常退出", hint)

    def _on_encrypt_finished(self, c, s, port: int = 8081):
        user_stop = getattr(self, "_encrypt_user_stop", False)
        self._encrypt_user_stop = False
        self.control.set_encrypt_running(False)
        self.encrypt_process = None
        self._refresh_home_status()
        hint = exit_code_hint(c, "加密端", port)
        ch = LogTab.CHANNEL_ENCRYPT
        if user_stop or c == 0:
            self._proxy_log("INFO", "加密端已停止", ch)
            return
        self._proxy_log("ERROR", hint.replace("\n", " | "), ch)
        QMessageBox.warning(self, "加密端异常退出", hint)

    def closeEvent(self, e):
        self._decrypt_user_stop = True
        self._encrypt_user_stop = True
        name = self.control.profile_combo.currentText()
        if name:
            try:
                save_project_state(name, getattr(self.control, "_last_raw", ""))
            except Exception as ex:
                logging.warning("关闭时保存项目状态失败: %s", ex)
        # 先停 Burp 收件箱
        try:
            inbox = getattr(self, "_burp_inbox", None)
            if inbox is not None:
                inbox.stop()
        except Exception:
            pass
        # 先停小程序抓包，恢复系统代理，避免退出后整机上网异常
        try:
            lab = getattr(self, "ai_lab_tab", None)
            panel = getattr(lab, "miniprogram_panel", None) if lab else None
            if panel is not None and hasattr(panel, "stop_capture_if_running"):
                panel.stop_capture_if_running()
            if lab is not None and hasattr(lab, "stop_btn") and lab.stop_btn.isEnabled():
                lab._stop_browser()
        except Exception as ex:
            logging.warning("关闭时停止采集失败: %s", ex)
        try:
            if hasattr(self.control, "_stop_proxy_browser"):
                self.control._stop_proxy_browser()
                br = getattr(self.control, "_proxy_browser", None)
                if br is not None and br.isRunning():
                    br.wait(3000)
        except Exception as ex:
            logging.warning("关闭时停止代理浏览器失败: %s", ex)

        # 彻底停解密/加密端（mitmdump 常有子进程，仅 terminate 会残留占端口）
        dec_port = 0
        enc_port = 0
        try:
            dec_port = int(self.control.decrypt_port.value())
            enc_port = int(self.control.encrypt_port.value())
        except Exception:
            pass
        try:
            stop_qprocess(self.decrypt_process, wait_ms=1200, label="decrypt-exit")
            stop_qprocess(self.encrypt_process, wait_ms=1200, label="encrypt-exit")
        except Exception as ex:
            logging.warning("关闭时停止代理进程失败: %s", ex)
        for port, label in ((dec_port, "decrypt"), (enc_port, "encrypt")):
            if not port:
                continue
            try:
                killed = free_listen_port(port, reason=f"app exit {label}")
                if killed:
                    logging.info("exit freed :%s pids=%s", port, killed)
            except Exception as ex:
                logging.warning("关闭时释放端口 %s 失败: %s", port, ex)
        self.decrypt_process = None
        self.encrypt_process = None
        e.accept()


def main():
    import argparse
    import traceback

    parser = argparse.ArgumentParser(description="密桥 CipherBridge")
    parser.add_argument(
        "--qt",
        action="store_true",
        help="使用经典 PyQt 界面（非前端壳）",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="使用 Vue 前端壳（QWebEngine）",
    )
    args, _unknown = parser.parse_known_args()

    # 默认经典 PyQt；可用 --web 或 settings gui.ui=web 开前端壳
    use_web = False
    if args.web:
        use_web = True
    elif args.qt:
        use_web = False
    else:
        try:
            from core.app_settings import load_settings
            ui = str((load_settings().get("gui") or {}).get("ui", "qt")).lower()
            use_web = ui == "web"
        except Exception:
            use_web = False

    if use_web:
        try:
            from core.web_shell import run_web_shell
            sys.exit(run_web_shell())
        except Exception as e:
            traceback.print_exc()
            try:
                # 前端启动失败时回退经典界面
                print(f"[密桥] 前端壳启动失败，回退经典界面: {e}", file=sys.stderr)
            except Exception:
                pass

    try:
        app = QApplication(sys.argv)
        apply_theme(app)
        ic = app_icon()
        if not ic.isNull():
            app.setWindowIcon(ic)
        w = MainWindow()
        w.show()
        sys.exit(app.exec())
    except Exception as e:
        traceback.print_exc()
        try:
            QMessageBox.critical(None, "启动失败", f"{e}\n\n请查看终端完整错误信息。")
        except Exception:
            pass
        sys.exit(1)

if __name__=="__main__": main()
