"""签名算法检测器 — 自动匹配Header/Body中的签名."""

import hashlib
import hmac
import re
from sm_crypto import sm3_hash


def detect_signature(sign_value: str, candidates: list) -> list:
    """尝试用多种算法匹配签名值.

    Args:
        sign_value: header中的签名值
        candidates: [("源数据", "描述"), ...] 如 [("body_raw", "完整Body"), ("field_val", "data字段")]

    Returns:
        匹配结果列表
    """
    results = []
    sign_value = sign_value.strip()

    for data, desc in candidates:
        db = data.encode("utf-8") if isinstance(data, str) else data

        # 哈希算法
        hashes = {
            "MD5": hashlib.md5(db).hexdigest(),
            "SHA1": hashlib.sha1(db).hexdigest(),
            "SHA256": hashlib.sha256(db).hexdigest(),
            "SHA512": hashlib.sha512(db).hexdigest(),
            "SM3": sm3_hash(db),
        }
        for name, h in hashes.items():
            if h == sign_value:
                results.append(f"✓ {name}({desc})")

        # HMAC (仅当有密钥时)
        # (这里需要用户提供密钥，暂不自动检测)

    # 按长度推测
    if not results:
        l = len(sign_value)
        if l == 32:
            results.append("推测: MD5 (32 hex)")
        elif l == 40:
            results.append("推测: SHA1 (40 hex)")
        elif l == 64:
            results.append("推测: SHA256/SM3 (64 hex)")
        elif l == 128:
            results.append("推测: SHA512 (128 hex)")

    return results
