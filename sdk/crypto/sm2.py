"""SM2 国密非对称加密/解密（可选依赖 gmssl）."""

from __future__ import annotations

import base64
import binascii


def _require_gmssl():
    try:
        from gmssl import sm2  # type: ignore
        return sm2
    except ImportError as e:
        raise ImportError(
            "SM2 需要安装 gmssl：pip install gmssl"
        ) from e


def _normalize_key_hex(key: str) -> str:
    """接受裸 hex / 带 04 前缀的公钥 / 去掉空白."""
    k = (key or "").strip().replace(" ", "").replace("\n", "")
    if k.startswith("0x"):
        k = k[2:]
    return k


def sm2_encrypt(data: str, key: str, mode: str = "C1C3C2", padding: str = "",
                output: str = "base64", **_ignored) -> str:
    """公钥加密。key 为公钥 hex（可含 04 未压缩前缀）."""
    sm2 = _require_gmssl()
    pub = _normalize_key_hex(key)
    crypt = sm2.CryptSM2(public_key=pub, private_key="")
    # gmssl: mode 1=C1C3C2(默认), 0=C1C2C3
    crypt.mode = 0 if "C1C2C3" in (mode or "").upper() else 1
    cipher = crypt.encrypt(data.encode("utf-8"))
    if isinstance(cipher, str):
        cipher = binascii.unhexlify(cipher)
    if output == "hex":
        return binascii.hexlify(cipher).decode("ascii")
    return base64.b64encode(cipher).decode("utf-8")


def sm2_decrypt(data: str, key: str, mode: str = "C1C3C2", padding: str = "",
                input_fmt: str = "base64", **_ignored) -> str:
    """私钥解密。key 为私钥 hex."""
    sm2 = _require_gmssl()
    pri = _normalize_key_hex(key)
    crypt = sm2.CryptSM2(public_key="", private_key=pri)
    crypt.mode = 0 if "C1C2C3" in (mode or "").upper() else 1
    if input_fmt == "hex":
        raw = binascii.unhexlify(data.strip())
    else:
        raw = base64.b64decode(data)
    plain = crypt.decrypt(raw)
    if isinstance(plain, bytes):
        return plain.decode("utf-8")
    return str(plain)
