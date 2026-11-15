"""加密算法工厂 + AES / DES / 3DES / SM4 / XOR 实现."""

from Crypto.Cipher import AES as _AES, DES3 as _DES3, DES as _DES
from Crypto.PublicKey import RSA as _RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256 as _SHA256, SHA1 as _SHA1, MD5 as _MD5
from Crypto.Util.Padding import pad, unpad
import base64
from sm_crypto import sm4_encrypt_ecb, sm4_decrypt_ecb, sm4_encrypt_cbc, sm4_decrypt_cbc


_PADDING_MAP = {"PKCS7": "pkcs7", "PKCS5": "pkcs7", "ZeroPadding": "zero", "NoPadding": "no", "ISO10126": "iso7816"}

_AES_MODE_MAP = {
    "ECB": _AES.MODE_ECB, "CBC": _AES.MODE_CBC, "GCM": _AES.MODE_GCM,
    "CFB": _AES.MODE_CFB, "OFB": _AES.MODE_OFB, "CTR": _AES.MODE_CTR,
}


def create_algorithm(enc_cfg: dict):
    """工厂函数：从配置创建算法实例."""
    algo_cls = {
        "AES": AESAlgorithm,
        "DES": DESAlgorithm,
        "3DES": TripleDESAlgorithm,
        "SM4": SM4Algorithm,
        "XOR": XORAlgorithm,
        "RSA": RSAAlgorithm,
        "SM2": SM2Algorithm,
    }.get(enc_cfg["algorithm"])
    if algo_cls is None:
        raise ValueError(f"不支持的算法: {enc_cfg['algorithm']}")
    return algo_cls(enc_cfg)


class AESAlgorithm:
    def __init__(self, enc_cfg: dict):
        self.key = enc_cfg["key"].encode("utf-8")
        self.padding = enc_cfg.get("padding", "PKCS7")
        mode_name = enc_cfg.get("mode", "ECB")
        if mode_name not in _AES_MODE_MAP:
            raise ValueError(f"不支持的AES模式: {mode_name}")
        self.mode = _AES_MODE_MAP[mode_name]
        self._iv = enc_cfg.get("iv")
        self._nonce = enc_cfg.get("nonce")
        self._input_fmt = enc_cfg.get("input_fmt", "base64")

    def _cipher(self, for_decrypt: bool = False):
        kwargs = {}
        if self.mode in (_AES.MODE_CBC, _AES.MODE_CFB, _AES.MODE_OFB):
            iv = self._iv.encode("utf-8") if self._iv else self.key[:16]
            kwargs["iv"] = iv
            if self.mode == _AES.MODE_CFB:
                kwargs["segment_size"] = 128
        elif self.mode == _AES.MODE_GCM:
            iv = self._iv.encode("utf-8") if self._iv else self.key[:16]
            kwargs["iv"] = iv
            kwargs["nonce"] = iv
        elif self.mode == _AES.MODE_CTR:
            nonce = self._nonce.encode("utf-8") if self._nonce else b'\x00' * 8
            kwargs["nonce"] = nonce
            kwargs["initial_value"] = 0
        return _AES.new(self.key, self.mode, **kwargs)

    def encrypt(self, plaintext: str) -> str:
        cipher = self._cipher()
        padding_style = _PADDING_MAP.get(self.padding, "pkcs7")
        if self.padding == "NoPadding" or self.mode in (_AES.MODE_CTR, _AES.MODE_GCM):
            data_bytes = plaintext.encode("utf-8")
        else:
            data_bytes = pad(plaintext.encode("utf-8"), _AES.block_size, style=padding_style)
        encrypted = cipher.encrypt(data_bytes)
        return base64.b64encode(encrypted).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        cipher = self._cipher(for_decrypt=True)
        padding_style = _PADDING_MAP.get(self.padding, "pkcs7")
        raw = base64.b64decode(ciphertext) if self._input_fmt == "base64" else bytes.fromhex(ciphertext)
        decrypted = cipher.decrypt(raw)
        if self.padding == "NoPadding" or self.mode in (_AES.MODE_CTR, _AES.MODE_GCM):
            return decrypted.decode("utf-8")
        return unpad(decrypted, _AES.block_size, style=padding_style).decode("utf-8")


class DESAlgorithm:
    def __init__(self, enc_cfg: dict):
        key_bytes = enc_cfg["key"].encode("utf-8")
        if len(key_bytes) < 8:
            key_bytes = key_bytes.ljust(8, b'\0')
        elif len(key_bytes) > 8:
            key_bytes = key_bytes[:8]
        self.key = key_bytes
        self.padding = enc_cfg.get("padding", "PKCS7")
        mode_name = enc_cfg.get("mode", "ECB")
        mode_map = {"ECB": _DES.MODE_ECB, "CBC": _DES.MODE_CBC}
        if mode_name not in mode_map:
            raise ValueError(f"不支持的DES模式: {mode_name}")
        self.mode = mode_map[mode_name]
        self._iv = enc_cfg.get("iv")
        self._input_fmt = enc_cfg.get("input_fmt", "base64")

    def _cipher(self):
        if self.mode == _DES.MODE_CBC:
            iv = self._iv.encode("utf-8") if self._iv else self.key
            return _DES.new(self.key, self.mode, iv=iv)
        return _DES.new(self.key, self.mode)

    def encrypt(self, plaintext: str) -> str:
        cipher = self._cipher()
        padding_style = _PADDING_MAP.get(self.padding, "pkcs7")
        if self.padding == "NoPadding":
            data_bytes = plaintext.encode("utf-8")
        else:
            data_bytes = pad(plaintext.encode("utf-8"), _DES.block_size, style=padding_style)
        encrypted = cipher.encrypt(data_bytes)
        return base64.b64encode(encrypted).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        cipher = self._cipher()
        padding_style = _PADDING_MAP.get(self.padding, "pkcs7")
        raw = base64.b64decode(ciphertext) if self._input_fmt == "base64" else bytes.fromhex(ciphertext)
        decrypted = cipher.decrypt(raw)
        if self.padding == "NoPadding":
            return decrypted.decode("utf-8")
        return unpad(decrypted, _DES.block_size, style=padding_style).decode("utf-8")


class TripleDESAlgorithm:
    def __init__(self, enc_cfg: dict):
        key_bytes = enc_cfg["key"].encode("utf-8")
        if len(key_bytes) < 16:
            key_bytes = key_bytes.ljust(16, b'\0')
        elif len(key_bytes) > 24:
            key_bytes = key_bytes[:24]
        elif 16 < len(key_bytes) < 24:
            key_bytes = key_bytes.ljust(24, b'\0')
        self.key = key_bytes
        self.padding = enc_cfg.get("padding", "PKCS7")
        mode_name = enc_cfg.get("mode", "ECB")
        mode_map = {"ECB": _DES3.MODE_ECB, "CBC": _DES3.MODE_CBC}
        if mode_name not in mode_map:
            raise ValueError(f"不支持的3DES模式: {mode_name}")
        self.mode = mode_map[mode_name]
        self._iv = enc_cfg.get("iv")
        self._input_fmt = enc_cfg.get("input_fmt", "base64")

    def _cipher(self):
        if self.mode == _DES3.MODE_CBC:
            iv = self._iv.encode("utf-8") if self._iv else self.key[:8]
            return _DES3.new(self.key, self.mode, iv=iv)
        return _DES3.new(self.key, self.mode)

    def encrypt(self, plaintext: str) -> str:
        cipher = self._cipher()
        padding_style = _PADDING_MAP.get(self.padding, "pkcs7")
        if self.padding == "NoPadding":
            data_bytes = plaintext.encode("utf-8")
        else:
            data_bytes = pad(plaintext.encode("utf-8"), _DES3.block_size, style=padding_style)
        encrypted = cipher.encrypt(data_bytes)
        return base64.b64encode(encrypted).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        cipher = self._cipher()
        padding_style = _PADDING_MAP.get(self.padding, "pkcs7")
        raw = base64.b64decode(ciphertext) if self._input_fmt == "base64" else bytes.fromhex(ciphertext)
        decrypted = cipher.decrypt(raw)
        if self.padding == "NoPadding":
            return decrypted.decode("utf-8")
        return unpad(decrypted, _DES3.block_size, style=padding_style).decode("utf-8")


class SM4Algorithm:
    def __init__(self, enc_cfg: dict):
        self.key = enc_cfg["key"]
        self.padding = enc_cfg.get("padding", "PKCS7")
        self.mode = enc_cfg.get("mode", "ECB")
        self._iv = enc_cfg.get("iv", "0000000000000000")
        self._input_fmt = enc_cfg.get("input_fmt", "base64")

    def encrypt(self, plaintext: str) -> str:
        if self.mode == "CBC":
            return sm4_encrypt_cbc(plaintext, self.key, self._iv, self.padding)
        return sm4_encrypt_ecb(plaintext, self.key, self.padding)

    def decrypt(self, ciphertext: str) -> str:
        if self.mode == "CBC":
            return sm4_decrypt_cbc(ciphertext, self.key, self._iv, self.padding, self._input_fmt)
        return sm4_decrypt_ecb(ciphertext, self.key, self.padding, self._input_fmt)


class XORAlgorithm:
    def __init__(self, enc_cfg: dict):
        self.key = enc_cfg["key"].encode("utf-8")
        self._input_fmt = enc_cfg.get("input_fmt", "base64")

    def _xor(self, data: bytes) -> bytes:
        return bytes(data[i] ^ self.key[i % len(self.key)] for i in range(len(data)))

    def encrypt(self, plaintext: str) -> str:
        return base64.b64encode(self._xor(plaintext.encode("utf-8"))).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        raw = base64.b64decode(ciphertext) if self._input_fmt == "base64" else bytes.fromhex(ciphertext)
        return self._xor(raw).decode("utf-8")


class RSAAlgorithm:
    """RSA 非对称加密/解密/签名/验签.

    配置字段:
      - key: PEM格式公钥或私钥字符串 (含 -----BEGIN...-----)
      - key_file: 密钥文件路径 (与key二选一)
      - padding: "OAEP"(默认) 或 "PKCS1v15"
      - operation: "encrypt" / "decrypt" / "sign" / "verify" (默认 encrypt)
      - hash: 签名哈希 "SHA256"(默认) / "SHA1" / "MD5"
    """

    _HASH_MAP = {"SHA256": _SHA256, "SHA1": _SHA1, "MD5": _MD5}

    def __init__(self, enc_cfg: dict):
        key_data = enc_cfg.get("key", "")
        key_file = enc_cfg.get("key_file", "")
        if key_file:
            with open(key_file, "r") as f:
                key_data = f.read()
        if not key_data:
            raise ValueError("RSA 需要提供 key 或 key_file")
        self._key = _RSA.import_key(key_data)
        self._padding_name = enc_cfg.get("padding", "OAEP")
        self._operation = enc_cfg.get("operation", "encrypt")
        self._hash_name = enc_cfg.get("hash", "SHA256")

    def encrypt(self, plaintext: str) -> str:
        if self._padding_name == "PKCS1v15":
            cipher = PKCS1_v1_5.new(self._key)
        else:
            cipher = PKCS1_OAEP.new(self._key)
        encrypted = cipher.encrypt(plaintext.encode("utf-8"))
        return base64.b64encode(encrypted).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        if self._padding_name == "PKCS1v15":
            cipher = PKCS1_v1_5.new(self._key)
            sentinel = None
            decrypted = cipher.decrypt(base64.b64decode(ciphertext), sentinel)
            if decrypted is None:
                raise ValueError("RSA PKCS1v15 解密失败")
        else:
            cipher = PKCS1_OAEP.new(self._key)
            decrypted = cipher.decrypt(base64.b64decode(ciphertext))
        return decrypted.decode("utf-8")

    def sign(self, data: str) -> str:
        """用私钥对数据签名, 返回Base64签名."""
        hash_cls = self._HASH_MAP.get(self._hash_name, _SHA256)
        h = hash_cls.new(data.encode("utf-8"))
        signature = pkcs1_15.new(self._key).sign(h)
        return base64.b64encode(signature).decode("utf-8")

    def verify(self, data: str, signature_b64: str) -> bool:
        """用公钥验证签名."""
        try:
            hash_cls = self._HASH_MAP.get(self._hash_name, _SHA256)
            h = hash_cls.new(data.encode("utf-8"))
            pkcs1_15.new(self._key).verify(h, base64.b64decode(signature_b64))
            return True
        except (ValueError, TypeError):
            return False


class SM2Algorithm:
    """SM2 国密非对称（依赖 gmssl）."""

    def __init__(self, enc_cfg: dict):
        self.key = enc_cfg.get("key", "")
        self.mode = enc_cfg.get("mode", "C1C3C2")
        if not self.key:
            raise ValueError("SM2 需要提供 key（公钥/私钥 hex）")

    def encrypt(self, plaintext: str) -> str:
        from sdk.crypto.sm2 import sm2_encrypt
        return sm2_encrypt(plaintext, self.key, mode=self.mode)

    def decrypt(self, ciphertext: str) -> str:
        from sdk.crypto.sm2 import sm2_decrypt
        return sm2_decrypt(ciphertext, self.key, mode=self.mode)
