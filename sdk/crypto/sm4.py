"""SM4 国密加密/解密."""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from sm_crypto import sm4_encrypt_ecb, sm4_decrypt_ecb, sm4_encrypt_cbc, sm4_decrypt_cbc


def sm4_encrypt(data: str, key: str, mode: str = "ECB", padding: str = "PKCS7",
                iv: str = "0000000000000000", output: str = "base64") -> str:
    if mode == "CBC":
        return sm4_encrypt_cbc(data, key, iv, padding)
    return sm4_encrypt_ecb(data, key, padding)


def sm4_decrypt(data: str, key: str, mode: str = "ECB", padding: str = "PKCS7",
                iv: str = "0000000000000000") -> str:
    if mode == "CBC":
        return sm4_decrypt_cbc(data, key, iv, padding)
    return sm4_decrypt_ecb(data, key, padding)
