"""Plugin基类 — 配置驱动的通用加解密处理管道."""

import logging
from algorithms import create_algorithm
from signers import create_signer
from body_parser import BodyParser

logger = logging.getLogger(__name__)


class Plugin:
    """配置驱动的插件。仅在需要特殊预处理/后处理时子类化."""

    def __init__(self, app_config: dict):
        self.cfg = app_config
        self.name = app_config["name"]
        self.body_parser = BodyParser()
        self.algorithm = self._build_encryption()
        self.signer = self._build_signer()

    # ---- Public API ----

    def match_request(self, flow) -> bool:
        match = self.cfg.get("match", {})
        methods = match.get("methods", [])
        if methods and flow.request.method not in methods:
            return False
        ctypes = match.get("content_type", [])
        if ctypes:
            actual_ct = flow.request.headers.get("Content-Type", "").lower()
            if not any(ct in actual_ct for ct in ctypes):
                return False
        fields = match.get("require_fields", [])
        if fields:
            try:
                req_cfg = self.cfg.get("request", {})
                body = self.body_parser.parse(flow, req_cfg.get("body_format"))
            except Exception:
                return False
            if not all(f in body for f in fields):
                return False
        return True

    def process_request(self, flow, mode: str):
        req_cfg = self.cfg.get("request")
        if not req_cfg:
            return
        body = self.body_parser.parse(flow, req_cfg.get("body_format"))
        direction = "decrypt" if mode == "decrypt" else "encrypt"
        enc_cfg = req_cfg.get("encryption", {})
        if enc_cfg:
            self._transform_fields(body, enc_cfg, direction)
        if mode == "encrypt" and "sign" in req_cfg:
            self.signer.sign(body, flow, self.algorithm)
        self.body_parser.write(flow, body, req_cfg.get("body_format"))
        logger.info("[%s] request %s: %d fields transformed", self.name, direction, len(enc_cfg.get("fields", [])))

    def process_response(self, flow, mode: str):
        resp_cfg = self.cfg.get("response")
        if not resp_cfg:
            return
        enc_cfg = resp_cfg.get("encryption")
        if not enc_cfg:
            return
        body = self.body_parser.parse_response(flow, resp_cfg.get("body_format"))
        direction = "encrypt" if mode == "decrypt" else "decrypt"
        self._transform_fields(body, enc_cfg, direction)
        self.body_parser.write_response(flow, body, resp_cfg.get("body_format"))
        logger.info("[%s] response %s: %d fields transformed", self.name, direction, len(enc_cfg.get("fields", [])))

    # ---- Internals ----

    def _build_encryption(self):
        for section in ("request", "response"):
            enc = self.cfg.get(section, {}).get("encryption")
            if enc and "algorithm" in enc:
                return create_algorithm(enc)
        return None

    def _build_signer(self):
        sign_cfg = self.cfg.get("request", {}).get("sign")
        if sign_cfg:
            return create_signer(sign_cfg)
        return None

    def _transform_fields(self, body: dict, enc_cfg: dict, direction: str):
        for field_name in enc_cfg.get("fields", []):
            value = _get_nested(body, field_name)
            if direction == "encrypt":
                value = self.algorithm.encrypt(value)
            else:
                value = self.algorithm.decrypt(value)
            _set_nested(body, field_name, value)


def _get_nested(d: dict, path: str):
    parts = path.split(".")
    current = d
    for part in parts:
        current = current[part]
    return current


def _set_nested(d: dict, path: str, value):
    parts = path.split(".")
    for part in parts[:-1]:
        d = d[part]
    d[parts[-1]] = value
