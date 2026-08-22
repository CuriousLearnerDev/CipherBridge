"""RSA 非对称加密/解密/签名/验签."""

from Crypto.PublicKey import RSA as _RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, SHA1, MD5
import base64

_HASH_MAP = {"SHA256": SHA256, "SHA1": SHA1, "MD5": MD5}
_RSA_PADS = {"OAEP", "PKCS1v15", "PKCS1", "PKCS1_v1_5", "PKCS#1"}


def _normalize_padding(padding: str = "", mode: str = "") -> str:
    """模式框若选了 OAEP/PKCS1v15，也当作填充."""
    raw = (padding or mode or "OAEP").strip()
    if raw in ("PKCS1v15", "PKCS1", "PKCS1_v1_5", "PKCS#1"):
        return "PKCS1v15"
    if raw == "OAEP":
        return "OAEP"
    # 误选对称模式时默认 OAEP（前端 RSA 常见）
    return "OAEP"


def rsa_encrypt(data: str, key_pem: str, padding: str = "OAEP", mode: str = "",
                **_ignored) -> str:
    """公钥加密，返回 Base64。忽略对称算法用的 mode/iv 等多余参数."""
    key = _RSA.import_key(key_pem)
    pad = _normalize_padding(padding, mode)
    cipher = PKCS1_OAEP.new(key) if pad == "OAEP" else PKCS1_v1_5.new(key)
    return base64.b64encode(cipher.encrypt(data.encode("utf-8"))).decode("utf-8")


def rsa_decrypt(data: str, key_pem: str, padding: str = "OAEP", mode: str = "",
                input_fmt: str = "base64", **_ignored) -> str:
    """私钥解密。input_fmt: base64 | hex."""
    key = _RSA.import_key(key_pem)
    pad = _normalize_padding(padding, mode)
    raw = base64.b64decode(data) if input_fmt != "hex" else bytes.fromhex(data)
    if pad == "OAEP":
        return PKCS1_OAEP.new(key).decrypt(raw).decode("utf-8")
    result = PKCS1_v1_5.new(key).decrypt(raw, None)
    if result is None:
        raise ValueError("RSA PKCS1v15 解密失败")
    return result.decode("utf-8")


def rsa_sign(data: str, private_key_pem: str, hash_algo: str = "SHA256") -> str:
    key = _RSA.import_key(private_key_pem)
    h = _HASH_MAP.get(hash_algo, SHA256).new(data.encode("utf-8"))
    return base64.b64encode(pkcs1_15.new(key).sign(h)).decode("utf-8")


def rsa_verify(data: str, signature_b64: str, public_key_pem: str,
               hash_algo: str = "SHA256") -> bool:
    try:
        key = _RSA.import_key(public_key_pem)
        h = _HASH_MAP.get(hash_algo, SHA256).new(data.encode("utf-8"))
        pkcs1_15.new(key).verify(h, base64.b64decode(signature_b64))
        return True
    except (ValueError, TypeError):
        return False
