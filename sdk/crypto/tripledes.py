"""3DES 加密/解密."""

from Crypto.Cipher import DES3 as _DES3
from Crypto.Util.Padding import pad, unpad
import base64

_PAD_MAP = {"PKCS7": "pkcs7", "ZeroPadding": "zero", "NoPadding": "no"}


def tripledes_encrypt(data: str, key: str, mode: str = "ECB", padding: str = "PKCS7",
                      iv: str = "", output: str = "base64") -> str:
    key_bytes = key.encode("utf-8")
    if len(key_bytes) < 16: key_bytes = key_bytes.ljust(16, b'\x00')
    elif 16 < len(key_bytes) < 24: key_bytes = key_bytes.ljust(24, b'\x00')
    elif len(key_bytes) > 24: key_bytes = key_bytes[:24]
    cipher_mode = _DES3.MODE_ECB if mode == "ECB" else _DES3.MODE_CBC
    kwargs = {}
    if cipher_mode == _DES3.MODE_CBC:
        kwargs["iv"] = (iv or key).encode("utf-8")[:8].ljust(8, b'\x00')
    cipher = _DES3.new(key_bytes, cipher_mode, **kwargs)
    data_bytes = data.encode("utf-8")
    if padding != "NoPadding":
        data_bytes = pad(data_bytes, _DES3.block_size, style=_PAD_MAP.get(padding, "pkcs7"))
    encrypted = cipher.encrypt(data_bytes)
    return base64.b64encode(encrypted).decode("utf-8") if output == "base64" else encrypted.hex()


def tripledes_decrypt(data: str, key: str, mode: str = "ECB", padding: str = "PKCS7",
                      iv: str = "", input_fmt: str = "base64") -> str:
    key_bytes = key.encode("utf-8")
    if len(key_bytes) < 16: key_bytes = key_bytes.ljust(16, b'\x00')
    elif 16 < len(key_bytes) < 24: key_bytes = key_bytes.ljust(24, b'\x00')
    elif len(key_bytes) > 24: key_bytes = key_bytes[:24]
    cipher_mode = _DES3.MODE_ECB if mode == "ECB" else _DES3.MODE_CBC
    kwargs = {}
    if cipher_mode == _DES3.MODE_CBC:
        kwargs["iv"] = (iv or key).encode("utf-8")[:8].ljust(8, b'\x00')
    cipher = _DES3.new(key_bytes, cipher_mode, **kwargs)
    raw = base64.b64decode(data) if input_fmt == "base64" else bytes.fromhex(data)
    decrypted = cipher.decrypt(raw)
    if padding != "NoPadding":
        decrypted = unpad(decrypted, _DES3.block_size, style=_PAD_MAP.get(padding, "pkcs7"))
    return decrypted.decode("utf-8")
