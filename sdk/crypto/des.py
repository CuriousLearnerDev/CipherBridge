"""DES 加密/解密."""

from Crypto.Cipher import DES as _DES
from Crypto.Util.Padding import pad, unpad
import base64

_PAD_MAP = {"PKCS7": "pkcs7", "ZeroPadding": "zero", "NoPadding": "no"}


def des_encrypt(data: str, key: str, mode: str = "ECB", padding: str = "PKCS7",
                iv: str = "", output: str = "base64") -> str:
    key_bytes = key.encode("utf-8")[:8].ljust(8, b'\x00')
    cipher_mode = _DES.MODE_ECB if mode == "ECB" else _DES.MODE_CBC
    kwargs = {}
    if cipher_mode == _DES.MODE_CBC:
        kwargs["iv"] = (iv or key).encode("utf-8")[:8].ljust(8, b'\x00')
    cipher = _DES.new(key_bytes, cipher_mode, **kwargs)
    data_bytes = data.encode("utf-8")
    if padding != "NoPadding":
        data_bytes = pad(data_bytes, _DES.block_size, style=_PAD_MAP.get(padding, "pkcs7"))
    encrypted = cipher.encrypt(data_bytes)
    return base64.b64encode(encrypted).decode("utf-8") if output == "base64" else encrypted.hex()


def des_decrypt(data: str, key: str, mode: str = "ECB", padding: str = "PKCS7",
                iv: str = "", input_fmt: str = "base64") -> str:
    key_bytes = key.encode("utf-8")[:8].ljust(8, b'\x00')
    cipher_mode = _DES.MODE_ECB if mode == "ECB" else _DES.MODE_CBC
    kwargs = {}
    if cipher_mode == _DES.MODE_CBC:
        kwargs["iv"] = (iv or key).encode("utf-8")[:8].ljust(8, b'\x00')
    cipher = _DES.new(key_bytes, cipher_mode, **kwargs)
    raw = base64.b64decode(data) if input_fmt == "base64" else bytes.fromhex(data)
    decrypted = cipher.decrypt(raw)
    if padding != "NoPadding":
        decrypted = unpad(decrypted, _DES.block_size, style=_PAD_MAP.get(padding, "pkcs7"))
    return decrypted.decode("utf-8")
