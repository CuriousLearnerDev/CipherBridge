"""加密类型自动检测器.

自动分析输入数据，识别:
  - Base64编码 (判断是否为有效Base64)
  - Hex编码
  - JWT Token
  - 可能的加密算法 (AES/SM4/RSA 等基于密文长度)
  - GZIP压缩数据
"""

import base64
import re
import json


def detect(data: str) -> list:
    """分析字符串，返回可能的编码/加密类型列表."""
    results = []
    if not data or len(data) < 4:
        return [("未知", "数据太短")]

    # Base64检测
    b64_pattern = r'^[A-Za-z0-9+/]+={0,2}$'
    if re.match(b64_pattern, data) and len(data) >= 8:
        results.append(("Base64", f"长度{len(data)}, 编码概率高"))
        # 尝试解码
        try:
            decoded = base64.b64decode(data)
            results.append(("→解码后", f"{len(decoded)} 字节"))
            # 解码后如果是文本
            try:
                text = decoded.decode("utf-8")
                if text.isprintable():
                    results.append(("→UTF-8文本", text[:50]))
            except:
                pass
            # 解码后长度分析
            if len(decoded) % 16 == 0:
                results.append(("疑似AES/SM4", f"块对齐 {len(decoded)}B (16的倍数)"))
            elif len(decoded) % 8 == 0:
                results.append(("疑似DES/3DES", f"块对齐 {len(decoded)}B (8的倍数)"))
        except:
            pass

    # Hex检测
    if re.match(r'^[0-9a-fA-F]+$', data) and len(data) >= 6:
        results.append(("Hex", f"长度{len(data)}"))
        if len(data) == 32:
            results.append(("可能MD5", "32位hex"))
        elif len(data) == 40:
            results.append(("可能SHA1", "40位hex"))
        elif len(data) == 64:
            results.append(("可能SHA256/SM3", "64位hex"))
        elif len(data) == 128:
            results.append(("可能SHA512", "128位hex"))

    # JWT检测
    if data.count(".") == 2 and len(data) > 20:
        parts = data.split(".")
        if all(re.match(r'^[A-Za-z0-9_-]+$', p) for p in parts):
            results.append(("JWT Token", f"{len(data)} 字符"))
            try:
                payload = parts[1]
                padding = 4 - len(payload) % 4
                if padding != 4:
                    payload += "=" * padding
                jwt_data = json.loads(base64.urlsafe_b64decode(payload))
                results.append(("→JWT内容", str(jwt_data)[:100]))
            except:
                pass

    # GZIP检测 (看前2字节)
    try:
        raw = data.encode("latin-1") if not all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in data) else base64.b64decode(data)
        if raw[:2] == b'\x1f\x8b':
            results.append(("GZIP压缩", f"{len(raw)} 字节"))
    except:
        pass

    if not results:
        results.append(("纯文本", f"长度{len(data)}"))
    return results


def detect_from_request(raw_body: str) -> dict:
    """检测请求体中的加密字段."""
    result = {}
    try:
        obj = json.loads(raw_body)
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str) and len(v) > 10:
                    analysis = detect(v)
                    result[k] = analysis
    except (json.JSONDecodeError, ValueError):
        result["_raw"] = detect(raw_body)
    return result
