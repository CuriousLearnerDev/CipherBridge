"""mitmproxy addon — 单配置文件模式.

通过环境变量 PROFILE 指定 profiles/ 下的配置文件名(不含 .yaml 后缀):
  PROFILE=myapp mitmdump -s main.py -p 8080

配置文件位于 profiles/ 目录下.
"""

import os
import sys
import yaml
import logging
from mitmproxy import http
from forwarder import Forwarder

sys.path.insert(0, os.path.dirname(__file__))

logger = logging.getLogger(__name__)


class DecryptHandler:
    def __init__(self):
        profile_name = os.environ.get("PROFILE", "").strip()
        self.mode = os.environ.get("PROXY_ROLE", "decrypt")
        profile_dir = os.path.join(os.path.dirname(__file__), "profiles")

        profile_path = os.path.join(profile_dir, f"{profile_name}.yaml") if profile_name else ""
        if profile_path and os.path.exists(profile_path):
            with open(profile_path, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f)
        else:
            config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
            with open(config_path, "r", encoding="utf-8") as f:
                old_config = yaml.safe_load(f) or {}
            apps = old_config.get("apps") or []
            self.config = apps[0] if apps else {
                "name": profile_name or "default",
                "match": {},
                "request": {},
                "response": {},
            }

        # 初始化
        self._init_encryption()
        self._init_signer()
        self._init_forwarder()
        logger.info("已加载配置: %s, mode=%s", self.config.get("name", "unknown"), self.mode)

    def _init_encryption(self):
        from plugins.plugin import Plugin
        self.plugin = Plugin({"name": "main", "request": self.config.get("request", {}),
                              "response": self.config.get("response", {}),
                              "match": self.config.get("match", {})})

    def _init_signer(self):
        from signers import create_signer
        sign_cfg = self.config.get("request", {}).get("sign")
        self.signer = create_signer(sign_cfg) if sign_cfg else None

    def _init_forwarder(self):
        proxy = self.config.get("proxy", {})
        decrypt_to = proxy.get("decrypt_forward")
        if not decrypt_to:
            burp = os.environ.get("BURP_PORT", "8080").strip() or "8080"
            decrypt_to = f"http://127.0.0.1:{burp}"
        fwd = {
            "decrypt_to": decrypt_to,
            "encrypt_to": proxy.get("encrypt_forward"),
            "timeout": proxy.get("timeout", 30),
        }
        self.forwarder = Forwarder(**fwd)

    def request(self, flow: http.HTTPFlow) -> None:
        matched = self.plugin.match_request(flow)
        if matched:
            self.plugin.process_request(flow, self.mode)
            if self.signer:
                self.signer.sign({}, flow, self.plugin.algorithm)
        # 解密端：由 mitmdump --mode upstream 进 Burp，勿再 requests 转发
        if self.mode == "encrypt" and matched:
            self.forwarder.forward_encrypt(flow)

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None or not flow.response.content:
            return
        if self.plugin.match_request(flow):
            self.plugin.process_response(flow, self.mode)


addons = [DecryptHandler()]
