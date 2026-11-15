"""AES 加密/解密 — 简化API."""

from Crypto.Cipher import AES as _AES
from Crypto.Util.Padding import pad, unpad
import base64

_MODE_MAP = {
    "ECB": _AES.MODE_ECB, "CBC": _AES.MODE_CBC, "CFB": _AES.MODE_CFB,
    "OFB": _AES.MODE_OFB, "CTR": _AES.MODE_CTR, "GCM": _AES.MODE_GCM,
}
_PAD_MAP = {"PKCS7": "pkcs7", "ZeroPadding": "zero", "NoPadding": "no"}


def aes_encrypt(data: str, key: str, mode: str = "ECB", padding: str = "PKCS7",
                iv: str = "", output: str = "base64") -> str:
    key_bytes = key.encode("utf-8")
    cipher_mode = _MODE_MAP.get(mode, _AES.MODE_ECB)
    kwargs = {}
    if cipher_mode in (_AES.MODE_CBC, _AES.MODE_CFB, _AES.MODE_OFB):
        kwargs["iv"] = (iv or key).encode("utf-8")[:16].ljust(16, b'\x00')
    if cipher_mode == _AES.MODE_GCM:
        kwargs["iv"] = (iv or key).encode("utf-8")[:16]
    cipher = _AES.new(key_bytes, cipher_mode, **kwargs)
    data_bytes = data.encode("utf-8")
    if padding != "NoPadding":
        data_bytes = pad(data_bytes, _AES.block_size, style=_PAD_MAP.get(padding, "pkcs7"))
    encrypted = cipher.encrypt(data_bytes)
    if output == "base64":
        return base64.b64encode(encrypted).decode("utf-8")
    return encrypted.hex()


def aes_decrypt(data: str, key: str, mode: str = "ECB", padding: str = "PKCS7",
                iv: str = "", input_fmt: str = "base64") -> str:
    key_bytes = key.encode("utf-8")
    cipher_mode = _MODE_MAP.get(mode, _AES.MODE_ECB)
    kwargs = {}
    if cipher_mode in (_AES.MODE_CBC, _AES.MODE_CFB, _AES.MODE_OFB):
        kwargs["iv"] = (iv or key).encode("utf-8")[:16].ljust(16, b'\x00')
    cipher = _AES.new(key_bytes, cipher_mode, **kwargs)
    raw = base64.b64decode(data) if input_fmt == "base64" else bytes.fromhex(data)
    decrypted = cipher.decrypt(raw)
    if padding != "NoPadding":
        decrypted = unpad(decrypted, _AES.block_size, style=_PAD_MAP.get(padding, "pkcs7"))
    return decrypted.decode("utf-8")


def aes_decrypt_iv_prefix(data: str, key: str, mode: str = "CBC", padding: str = "PKCS7",
                          input_fmt: str = "base64", iv_len: int = 16) -> str:
    """密文前 N 字节为 IV、后面为密文（前端随机 IV 常见拼包方式）."""
    key_bytes = key.encode("utf-8")
    raw = base64.b64decode(data) if input_fmt == "base64" else bytes.fromhex(data)
    iv_bytes = raw[:iv_len]
    ct = raw[iv_len:]
    cipher_mode = _MODE_MAP.get(mode, _AES.MODE_CBC)
    kwargs = {"iv": iv_bytes.ljust(16, b"\x00")[:16]}
    cipher = _AES.new(key_bytes, cipher_mode, **kwargs)
    decrypted = cipher.decrypt(ct)
    if padding != "NoPadding":
        decrypted = unpad(decrypted, _AES.block_size, style=_PAD_MAP.get(padding, "pkcs7"))
    return decrypted.decode("utf-8")
