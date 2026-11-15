"""SDK 加解密 / 编码 / 识别 — 供 MCP 调用的纯函数封装。"""

from __future__ import annotations

from typing import Any

from mcp_server.paths import ensure_sys_path

ensure_sys_path()


def analyze_ciphertext(text: str) -> dict[str, Any]:
    """识别 Base64 / Hex / JWT / 熵等（本地规则，不调用外网）。"""
    from analyzer.crypto_detector import detect
    from analyzer.entropy import analyze as entropy_analyze

    t = text or ""
    hints = detect(t)
    ent: dict[str, Any] = {}
    try:
        raw = t.encode("utf-8", errors="ignore")
        ent = entropy_analyze(raw)
    except Exception as e:
        ent = {"error": str(e)}
    return {
        "length": len(t),
        "hints": [{"label": a, "detail": b} for a, b in hints],
        "entropy": ent,
    }


def crypto_aes(
    *,
    op: str,
    data: str,
    key: str,
    mode: str = "ECB",
    padding: str = "PKCS7",
    iv: str = "",
    fmt: str = "base64",
) -> dict[str, Any]:
    from sdk.crypto.aes import aes_decrypt, aes_encrypt

    op = (op or "").lower().strip()
    try:
        if op in ("encrypt", "enc", "加密"):
            out = aes_encrypt(data, key, mode=mode, padding=padding, iv=iv, output=fmt)
            return {"ok": True, "op": "encrypt", "result": out}
        if op in ("decrypt", "dec", "解密"):
            out = aes_decrypt(data, key, mode=mode, padding=padding, iv=iv, input_fmt=fmt)
            return {"ok": True, "op": "decrypt", "result": out}
        return {"ok": False, "error": "op 必须是 encrypt 或 decrypt"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def crypto_hash(algo: str, data: str, key: str = "") -> dict[str, Any]:
    """MD5/SHA*/HMAC/SM3。"""
    import hashlib

    algo_u = (algo or "md5").upper().replace("-", "")
    raw = (data or "").encode("utf-8")
    try:
        if algo_u.startswith("HMAC"):
            import hmac

            inner = algo_u.replace("HMAC", "") or "SHA256"
            if inner == "SM3":
                from sdk.sign.sm3 import sm3_hex

                # 简易 HMAC-SM3：无标准库时回退说明
                return {
                    "ok": False,
                    "error": "请用 hmac_sha*；HMAC-SM3 请走 GUI/扩展",
                }
            dig = getattr(hashlib, inner.lower(), None)
            if dig is None:
                return {"ok": False, "error": f"不支持 HMAC 内部算法: {inner}"}
            out = hmac.new((key or "").encode("utf-8"), raw, dig).hexdigest()
            return {"ok": True, "algo": algo_u, "result": out}
        if algo_u == "SM3":
            from sdk.sign.sm3 import sm3

            return {"ok": True, "algo": "SM3", "result": sm3(data or "")}
        if algo_u == "MD5":
            return {"ok": True, "algo": "MD5", "result": hashlib.md5(raw).hexdigest()}
        if algo_u in ("SHA1", "SHA256", "SHA512"):
            h = getattr(hashlib, algo_u.lower())
            return {"ok": True, "algo": algo_u, "result": h(raw).hexdigest()}
        return {"ok": False, "error": f"不支持算法: {algo}，可用 MD5/SHA1/SHA256/SHA512/SM3/HMAC-SHA256"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def encode_convert(*, op: str, data: str) -> dict[str, Any]:
    import base64
    import urllib.parse

    op_l = (op or "").lower().strip()
    try:
        if op_l in ("b64_encode", "base64_encode"):
            return {
                "ok": True,
                "result": base64.b64encode((data or "").encode("utf-8")).decode("ascii"),
            }
        if op_l in ("b64_decode", "base64_decode"):
            pad = "=" * ((4 - len(data or "") % 4) % 4)
            return {
                "ok": True,
                "result": base64.b64decode((data or "") + pad).decode("utf-8", errors="replace"),
            }
        if op_l in ("hex_encode",):
            return {"ok": True, "result": (data or "").encode("utf-8").hex()}
        if op_l in ("hex_decode",):
            return {
                "ok": True,
                "result": bytes.fromhex(data or "").decode("utf-8", errors="replace"),
            }
        if op_l in ("url_encode",):
            return {"ok": True, "result": urllib.parse.quote(data or "", safe="")}
        if op_l in ("url_decode",):
            return {"ok": True, "result": urllib.parse.unquote(data or "")}
        return {
            "ok": False,
            "error": "op: b64_encode|b64_decode|hex_encode|hex_decode|url_encode|url_decode",
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}
