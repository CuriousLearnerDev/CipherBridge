"""Mitm引擎 — mitmproxy addon，核心入口.

端口职责:
  8080 解密端 (PROXY_ROLE=decrypt): request() 解密请求体 → 转发Burp
  8081 加密端 (PROXY_ROLE=encrypt): request() 加密请求体+签名 → 转发服务器

插件标准: def request(ctx) / def response(ctx)
环境变量:
  PROFILE  — GUI 指定项目名时跳过自动匹配
  PROXY_ROLE — decrypt | encrypt
  BURP_PORT — 解密端 Burp 端口
"""

import inspect
import os
import sys
import logging
import requests
from mitmproxy import http

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.context import Context
from core.http_message import log_http_message
from core.plugin_loader import PluginLoader

from core.brand import APP_NAME

logger = logging.getLogger(__name__)


def _cp_log(msg: str) -> None:
    """输出到 mitmdump stdout，确保 GUI 日志 Tab 可见."""
    print(f"[{APP_NAME}] {msg}", flush=True)
    logger.info(msg)


class MitmEngine:
    def __init__(self):
        self.loader = PluginLoader()
        self.loader.load_all_profiles()
        self.role = os.environ.get("PROXY_ROLE", "decrypt")
        self.burp_port = os.environ.get("BURP_PORT", "8083")
        self.forced_profile = os.environ.get("PROFILE", "").strip()
        _cp_log(
            f"MitmEngine 已初始化 | role={self.role} | profile={self.forced_profile or '(auto)'} | →Burp:{self.burp_port}"
        )

    def _resolve_profile(self, flow: http.HTTPFlow) -> str:
        if self.forced_profile:
            if self.loader.profile_matches(self.forced_profile, flow):
                return self.forced_profile
            return ""
        return self.loader.match_profile(flow)

    def _invoke_plugin_handler(self, handler, flow: http.HTTPFlow):
        """兼容 request(ctx) 与 request(flow) 两种插件风格."""
        params = list(inspect.signature(handler).parameters.values())
        if params and params[0].name == "flow":
            handler(flow)
        else:
            ctx = Context(flow)
            ctx._role = self.role
            handler(ctx)

    def _call_plugin(self, profile_name: str, flow: http.HTTPFlow, phase: str):
        plugin = self.loader.load_plugin(profile_name)
        if not plugin:
            logger.error("无法加载插件: %s", profile_name)
            return
        cfg = self.loader.get_profile_config(profile_name)
        roles = cfg.get("roles") or ["decrypt", "encrypt"]
        if self.role not in roles:
            logger.warning(
                "[%s] 当前为 %s 端，但项目 roles=%s，插件可能不会修改请求体",
                profile_name, self.role, roles,
            )
        handler = getattr(plugin, phase, None)
        if not handler:
            return
        before_content = flow.request.content or b""
        try:
            logger.info("[%s][%s] 调用 plugin.%s()", profile_name, self.role, phase)
            self._invoke_plugin_handler(handler, flow)
            after_content = flow.request.content or b""
            if before_content != after_content:
                _cp_log(
                    f"[{profile_name}][{self.role}] 请求体已修改 "
                    f"({len(before_content)} → {len(after_content)} bytes)"
                )
                try:
                    preview = after_content.decode("utf-8")[:240]
                    _cp_log(f"转发 body 预览: {preview}")
                except Exception:
                    pass
            else:
                _cp_log(
                    f"[{profile_name}][{self.role}] 请求体未变化！"
                    "请检查：1) 是否选对项目 2) 项目 roles 是否含 decrypt 3) 密钥是否正确"
                )
            logger.info(
                "[%s][%s] %s 完成: %s %s",
                profile_name, self.role, phase, flow.request.method, flow.request.path,
            )
        except Exception as e:
            import traceback
            _cp_log(f"[{profile_name}] {phase} 处理异常: {e}")
            _cp_log(traceback.format_exc())
            logger.error("[%s] %s 处理异常: %s", profile_name, phase, e)

    def _handle_response(self, profile_name: str, flow: http.HTTPFlow) -> None:
        if getattr(flow, "_cryptoproxy_response_logged", False):
            return
        self._call_plugin(profile_name, flow, "response")
        log_http_message(flow, "response", self.role, profile_name)
        flow._cryptoproxy_response_logged = True

    def request(self, flow: http.HTTPFlow) -> None:
        profile_name = self._resolve_profile(flow)
        if not profile_name:
            _cp_log(
                f"未匹配项目，跳过: {flow.request.method} {flow.request.host}{flow.request.path}"
                f" （请检查 profiles 匹配规则 / 左侧「规则」）"
            )
            return
        _cp_log(f"处理请求: {profile_name} | {flow.request.method} {flow.request.host}{flow.request.path}")
        self._call_plugin(profile_name, flow, "request")
        log_http_message(flow, "request", self.role, profile_name)

        # 插件已含 requests 转发时 flow.response 已设置，避免重复转发
        if self.role == "decrypt" and flow.response is None:
            self._forward_to_burp(flow)
        elif self.role == "encrypt" and flow.response is None:
            self._forward_to_server(flow)

        if flow.response is not None:
            self._handle_response(profile_name, flow)

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        profile_name = self._resolve_profile(flow)
        if not profile_name:
            return
        self._handle_response(profile_name, flow)

    def _prepare_forward_headers(self, flow: http.HTTPFlow) -> dict:
        """修正转发头 — 同步修改后的 Content-Length / Host."""
        headers = dict(flow.request.headers)
        for h in ("Connection", "Transfer-Encoding", "Proxy-Connection", "Keep-Alive", "Content-Length"):
            headers.pop(h, None)
        host = flow.request.host
        port = flow.request.port
        if (flow.request.scheme == "https" and port != 443) or (
            flow.request.scheme == "http" and port != 80
        ):
            headers["Host"] = f"{host}:{port}"
        else:
            headers["Host"] = host
        content = flow.request.content or b""
        if content:
            headers["Content-Length"] = str(len(content))
        return headers

    def _forward_to_burp(self, flow: http.HTTPFlow):
        """解密端: 用 requests 将修改后的请求经 Burp 代理转发（与用户脚本一致）."""
        body = flow.request.content or b""
        headers = self._prepare_forward_headers(flow)
        burp_url = f"http://127.0.0.1:{self.burp_port}"
        proxies = {"http": burp_url, "https": burp_url}
        target_url = flow.request.url

        _cp_log(f"requests → Burp {burp_url} | {flow.request.method} {target_url} | body {len(body)} bytes")
        try:
            _cp_log(f"转发 body: {body.decode('utf-8')[:300]}")
        except Exception:
            pass

        try:
            burp_resp = requests.request(
                method=flow.request.method,
                url=target_url,
                headers=headers,
                data=body,
                allow_redirects=False,
                proxies=proxies,
                timeout=30,
                verify=False,
            )
            flow.response = http.Response.make(
                burp_resp.status_code,
                burp_resp.content,
                {k: v for k, v in burp_resp.headers.items()},
            )
            _cp_log(f"Burp 响应: {burp_resp.status_code} ({len(burp_resp.content)} bytes)")
        except Exception as e:
            import traceback
            _cp_log(f"转发到 Burp 失败: {e}")
            _cp_log(traceback.format_exc())
            logger.error("转发到Burp失败: %s", e)

    def _forward_to_server(self, flow: http.HTTPFlow):
        """加密端: 将修改后的请求转发到真实服务器."""
        try:
            server_resp = requests.request(
                method=flow.request.method,
                url=flow.request.url,
                headers=self._prepare_forward_headers(flow),
                data=flow.request.content,
                allow_redirects=False,
                timeout=30,
                verify=False,
            )
            flow.response = http.Response.make(
                server_resp.status_code,
                server_resp.content,
                {k: v for k, v in server_resp.headers.items()},
            )
            logger.debug("转发到服务器成功: %s -> %s", flow.request.url, server_resp.status_code)
        except Exception as e:
            logger.error("转发到服务器失败: %s", e)


addons = [MitmEngine()]
