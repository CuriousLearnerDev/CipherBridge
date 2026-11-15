"""JWT 解码/编码."""

import base64
import json


def jwt_decode(token: str) -> dict:
    """解码JWT payload (不验证签名)."""
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("无效的JWT格式")
    payload = parts[1]
    # 补齐base64 padding
    padding = 4 - len(payload) % 4
    if padding != 4:
        payload += "=" * padding
    return json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))


def jwt_encode(header: dict, payload: dict, secret: str = "", algo: str = "HS256") -> str:
    """编码JWT (仅支持HS256)."""
    import hmac, hashlib
    h_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(',', ':')).encode()).rstrip(b'=').decode()
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).rstrip(b'=').decode()
    msg = f"{h_b64}.{p_b64}"
    if not secret:
        return msg + "."
    sig = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()
    s_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
    return f"{msg}.{s_b64}"
