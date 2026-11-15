"""转发模块 — 将请求转发到 Burp / 上游代理."""

import requests
import logging
from mitmproxy import http

logger = logging.getLogger(__name__)


class Forwarder:
    def __init__(self, decrypt_to: str = None, encrypt_to: str = None, timeout: int = 30):
        self.decrypt_to = decrypt_to
        self.encrypt_to = encrypt_to
        self.timeout = timeout
        self.session = requests.Session()
        self.session.trust_env = False

    def forward_decrypt(self, flow) -> bool:
        """解密模式下：修改后的请求转发到Burp，返回的响应直接作为mitmproxy响应."""
        if not self.decrypt_to:
            return False
        try:
            proxies = {"http": self.decrypt_to, "https": self.decrypt_to}
            burp_response = self.session.request(
                method=flow.request.method,
                url=flow.request.url,
                headers=dict(flow.request.headers),
                data=flow.request.content,
                allow_redirects=False,
                proxies=proxies,
                timeout=self.timeout,
                verify=False,
            )
            flow.response = http.Response.make(
                burp_response.status_code,
                burp_response.content,
                {k: v for k, v in burp_response.headers.items()},
            )
            logger.info("转发到Burp成功: %s -> %s", flow.request.url, burp_response.status_code)
            return True
        except requests.exceptions.Timeout:
            logger.warning("转发到Burp超时: %s", flow.request.url)
            flow.response = http.Response.make(504, b"Gateway Timeout", {"Content-Type": "text/plain"})
            return True
        except requests.exceptions.RequestException as e:
            logger.error("转发到Burp失败: %s", e)
            flow.response = http.Response.make(502, f"Bad Gateway: {e}".encode(), {"Content-Type": "text/plain"})
            return True

    def forward_encrypt(self, flow) -> bool:
        """加密模式下：修改后的请求直接发给目标服务器，返回真实的服务器响应."""
        if not self.encrypt_to:
            return False
        try:
            proxies = {"http": self.encrypt_to, "https": self.encrypt_to}
            server_response = self.session.request(
                method=flow.request.method,
                url=flow.request.url,
                headers=dict(flow.request.headers),
                data=flow.request.content,
                allow_redirects=False,
                proxies=proxies,
                timeout=self.timeout,
                verify=False,
            )
            flow.response = http.Response.make(
                server_response.status_code,
                server_response.content,
                {k: v for k, v in server_response.headers.items()},
            )
            logger.info("转发到上游成功: %s -> %s", flow.request.url, server_response.status_code)
            return True
        except requests.exceptions.Timeout:
            logger.warning("转发到上游超时: %s", flow.request.url)
            flow.response = http.Response.make(504, b"Gateway Timeout", {"Content-Type": "text/plain"})
            return True
        except requests.exceptions.RequestException as e:
            logger.error("转发到上游失败: %s", e)
            flow.response = http.Response.make(502, f"Bad Gateway: {e}".encode(), {"Content-Type": "text/plain"})
            return True
