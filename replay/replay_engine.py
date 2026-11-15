"""重放引擎 — 修改明文后自动签名+加密+发送."""

import requests
import json


class ReplayEngine:
    """重放请求，自动重新签名和加密."""

    def __init__(self, encrypt_fn=None, sign_fn=None):
        self.encrypt_fn = encrypt_fn  # (plaintext: str) -> str
        self.sign_fn = sign_fn        # (data: dict) -> dict (headers to add)
        self.session = requests.Session()
        self.session.verify = False

    def replay(self, method: str, url: str, plain_data: dict,
               headers: dict = None) -> requests.Response:
        """发送明文数据，自动加密+签名.

        Args:
            method: HTTP方法
            url: 目标URL
            plain_data: 明文JSON数据
            headers: 已有的headers

        Returns:
            服务器响应
        """
        data = dict(plain_data)

        # 1. 加密
        if self.encrypt_fn:
            for k, v in data.items():
                if isinstance(v, str):
                    data[k] = self.encrypt_fn(v)

        # 2. 签名
        hdrs = dict(headers or {})
        if self.sign_fn:
            hdrs.update(self.sign_fn(data))

        # 3. 发送
        return self.session.request(method, url, json=data, headers=hdrs, timeout=30)
