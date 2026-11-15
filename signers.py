"""签名处理工厂 + SHA256 / MD5 / HMAC / RemoteSign / URL参数 / 排序拼接 / AuthToken."""

import hashlib
import hmac
import json
import secrets
import time
import base64
import urllib.parse
from datetime import datetime
import requests
from sm_crypto import sm3_hmac


_HMAC_HASH_MAP = {
    "hmac_md5": "md5",
    "hmac_sha1": "sha1",
    "hmac_sha256": "sha256",
    "hmac_sha384": "sha384",
    "hmac_sha512": "sha512",
}


def create_signer(sign_cfg: dict):
    algo = sign_cfg["algorithm"]
    if algo in _HMAC_HASH_MAP or algo == "hmac_sm3":
        return HMACSigner(sign_cfg)
    signer_cls = {
        "sha256": SHA256Signer,
        "md5": MD5Signer,
        "remote": RemoteSigner,
        "url_params": URLParamsSigner,
        "sorted_concat": SortedConcatSigner,
        "auth_token": CompositeAuthTokenSigner,
    }.get(algo)
    if signer_cls is None:
        raise ValueError(f"不支持的签名算法: {algo}")
    return signer_cls(sign_cfg)


# ============================================================
# 基础签名器
# ============================================================

class SHA256Signer:
    def __init__(self, sign_cfg: dict):
        self.source_field = sign_cfg["source_field"]
        self.target_name = sign_cfg["target_name"]

    def sign(self, body: dict, flow, algorithm):
        encrypted_value = body.get(self.source_field, "")
        signature = hashlib.sha256(encrypted_value.encode("utf-8")).hexdigest()
        flow.request.headers[self.target_name] = signature


class MD5Signer:
    def __init__(self, sign_cfg: dict):
        self.source_field = sign_cfg.get("source_field", "")
        self.target_name = sign_cfg.get("target_name", "sign")

    def sign(self, body: dict, flow, algorithm):
        value = body.get(self.source_field, "")
        sig = hashlib.md5(value.encode("utf-8")).hexdigest()
        flow.request.headers[self.target_name] = sig


class RemoteSigner:
    def __init__(self, sign_cfg: dict):
        self.api = sign_cfg["api"]
        self.actions = sign_cfg.get("target_actions", [])

    def sign(self, body: dict, flow, algorithm):
        now = datetime.now()
        dyn = {
            "${timestamp_str}": now.strftime("%Y-%m-%d %H:%M:%S"),
            "${timestamp_micro}": str(int(now.timestamp() * 1000000)),
        }
        api_body = self._resolve_template(self.api["body_template"], dyn)
        resp = requests.post(
            self.api["url"],
            json=api_body,
            headers=self.api.get("headers", {}),
            verify=False,
            timeout=30,
        )
        resp.raise_for_status()
        result = resp.json()
        for action in self.actions:
            if "from_response" in action:
                body[action["set_field"]] = result.get(action["from_response"])
            elif "value" in action:
                body[action["set_field"]] = dyn.get(action["value"], action["value"])

    @staticmethod
    def _resolve_template(template: dict, dyn: dict) -> dict:
        result = {}
        for k, v in template.items():
            if isinstance(v, str) and v in dyn:
                result[k] = dyn[v]
            else:
                result[k] = v
        return result


class HMACSigner:
    """HMAC 签名 — 支持 MD5 / SHA1 / SHA256 / SHA384 / SHA512 / SM3."""

    def __init__(self, sign_cfg: dict):
        self.algo = sign_cfg["algorithm"]
        self.source_field = sign_cfg.get("source_field", "")
        self.target_name = sign_cfg.get("target_name", "sign")
        self.key = sign_cfg.get("key", "")
        self.output = sign_cfg.get("output", "hex")

    def sign(self, body: dict, flow, algorithm):
        value = body.get(self.source_field, "")
        key_bytes = self.key.encode("utf-8")
        data_bytes = value.encode("utf-8")

        if self.algo == "hmac_sm3":
            sig = sm3_hmac(key_bytes, data_bytes)
        else:
            hash_name = _HMAC_HASH_MAP.get(self.algo, "sha256")
            sig = hmac.new(key_bytes, data_bytes, hash_name).hexdigest()

        if self.output == "base64":
            sig = base64.b64encode(bytes.fromhex(sig)).decode("utf-8")

        flow.request.headers[self.target_name] = sig


# ============================================================
# 高级签名器 — URL参数注入 (动态时间戳)
# ============================================================

class URLParamsSigner:
    """MD5 时间戳+nonce 签名, 注入URL query参数 (_t, nonce, signData).

    算法: nonce=MD5(timestamp), signData=MD5(timestamp+nonce)
    """

    def __init__(self, sign_cfg: dict):
        self.t_field = sign_cfg.get("t_field", "_t")
        self.nonce_field = sign_cfg.get("nonce_field", "nonce")
        self.sign_field = sign_cfg.get("sign_field", "signData")

    def sign(self, body: dict, flow, algorithm):
        _t = round(time.time(), 3)
        nonce = hashlib.md5(str(_t).encode()).hexdigest()
        sign_data = hashlib.md5((str(int(_t)) + str(nonce)).encode()).hexdigest()

        query = flow.request.query
        query[self.t_field] = str(_t)
        query[self.nonce_field] = nonce
        query[self.sign_field] = sign_data
        flow.request.query = query


# ============================================================
# 高级签名器 — 参数排序拼接 + 密钥后缀
# ============================================================

class SortedConcatSigner:
    """参数按key排序 → 值用|拼接 → 追加secret → MD5 → 写入body字段.

    还自动生成 random nonce (16字节hex).

    配置示例:
      secret_suffix: "your-secret-key"  (密钥后缀)
      sign_field: "sign"
      nonce_field: "nonce"
    """

    def __init__(self, sign_cfg: dict):
        self.secret_suffix = sign_cfg.get("secret_suffix", "")
        self.sign_field = sign_cfg.get("sign_field", "sign")
        self.nonce_field = sign_cfg.get("nonce_field", "nonce")

    def sign(self, body: dict, flow, algorithm):
        # 生成随机 nonce
        if self.nonce_field:
            body[self.nonce_field] = secrets.token_bytes(16).hex()

        # 删除旧的 sign
        body.pop(self.sign_field, None)

        # 按key排序拼接
        parts = []
        for key in sorted(body.keys()):
            value = body[key]
            if value is None or value == "":
                continue
            if isinstance(value, (dict, list)):
                parts.append(json.dumps(value, separators=(',', ':')))
            else:
                parts.append(str(value))

        sign_str = "|".join(parts) + self.secret_suffix
        body[self.sign_field] = hashlib.md5(sign_str.encode("utf-8")).hexdigest()


# ============================================================
# 高级签名器 — 复合 AuthToken
# ============================================================

class CompositeAuthTokenSigner:
    """多片段拼装 + AES加密 → AuthToken 请求头.

    流程:
      1. 从 body/headers 提取片段: url路径, JWT[-20:], signature[-20:], key[8:], origin
      2. 用 "@@" 拼接各片段
      3. 用 AES(reversed_key) 加密拼接结果
      4. 写入 AuthToken 请求头

    配置示例:
      base_key: "your-24-byte-3des-key!!"
      origin: "https://example.com"
      jwt_source: "header" / "config" / "body"
      jwt_header_name: "JwtToken"    (当 jwt_source=header)
      jwt_config_value: "eyJ..."     (当 jwt_source=config)
      url_prefix_to_strip: "/manager"  (URL路径前缀剥离)
    """

    def __init__(self, sign_cfg: dict):
        self.base_key = sign_cfg.get("base_key", "")
        self.origin = sign_cfg.get("origin", "")
        self.jwt_source = sign_cfg.get("jwt_source", "config")
        self.jwt_header_name = sign_cfg.get("jwt_header_name", "JwtToken")
        self.jwt_config_value = sign_cfg.get("jwt_config_value", "")
        self.url_prefix_to_strip = sign_cfg.get("url_prefix_to_strip", "")
        self.sign_target_name = sign_cfg.get("target_name", "signature")

    def sign(self, body: dict, flow, algorithm):
        # 1. 计算签名 (与主签名器保持一致)
        source_field = body.get("data", "")
        if isinstance(source_field, str) and source_field:
            encrypted_value = algorithm.encrypt(source_field) if algorithm else source_field
            signature = hashlib.sha256(encrypted_value.encode("utf-8")).hexdigest()
        else:
            signature = hashlib.sha256(json.dumps(body).encode("utf-8")).hexdigest()

        flow.request.headers[self.sign_target_name] = signature

        # 2. 获取JWT
        jwt_token = ""
        if self.jwt_source == "header":
            jwt_token = flow.request.headers.get(self.jwt_header_name, "")
        elif self.jwt_source == "config":
            jwt_token = self.jwt_config_value

        if not jwt_token:
            return

        # 3. 提取URL路径
        parsed = urllib.parse.urlparse(flow.request.url)
        url_path = parsed.path
        if self.url_prefix_to_strip and url_path.startswith(self.url_prefix_to_strip):
            url_path = url_path[len(self.url_prefix_to_strip):]

        # 4. 拼接AuthToken片段
        jwt_fragment = jwt_token[-20:] if jwt_token else ""
        sign_fragment = signature[-20:] if signature else ""
        key_fragment = self.base_key[8:] if len(self.base_key) > 8 else ""
        auth_str = "@@".join([url_path, jwt_fragment, sign_fragment, key_fragment, self.origin])

        # 5. AES加密 (使用反转密钥)
        reversed_key = self.base_key[::-1]
        from algorithms import create_algorithm
        aes = create_algorithm({"algorithm": "AES", "mode": "ECB", "key": reversed_key, "padding": "PKCS7"})
        encrypted_auth = aes.encrypt(auth_str)

        flow.request.headers["AuthToken"] = encrypted_auth
        if jwt_token and self.jwt_source == "config":
            flow.request.headers[self.jwt_header_name] = jwt_token
