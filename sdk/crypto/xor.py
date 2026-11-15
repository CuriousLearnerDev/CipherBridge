"""XOR 加密/解密."""

import base64


def xor_encrypt(data: str, key: str, output: str = "base64") -> str:
    key_bytes = key.encode("utf-8")
    result = bytes(ord(data[i]) ^ key_bytes[i % len(key_bytes)] for i in range(len(data)))
    return base64.b64encode(result).decode("utf-8") if output == "base64" else result.hex()


def xor_decrypt(data: str, key: str, input_fmt: str = "base64") -> str:
    key_bytes = key.encode("utf-8")
    raw = base64.b64decode(data) if input_fmt == "base64" else bytes.fromhex(data)
    result = bytes(raw[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(raw)))
    return result.decode("utf-8")
