"""PC 微信小程序 .wxapkg 解密（V1MMWX）。

公开算法（PBKDF2-SHA1 + AES-CBC + 尾部 XOR），无需外部 exe。
"""

from __future__ import annotations

import hashlib
from typing import Final

from Crypto.Cipher import AES

MAGIC_V1MMWX: Final[bytes] = b"V1MMWX"
DEFAULT_SALT: Final[bytes] = b"saltiest"
DEFAULT_IV: Final[bytes] = b"the iv: 16 bytes"
HEADER_AES_LEN: Final[int] = 1024
HEADER_PLAIN_LEN: Final[int] = 1023


class WxapkgDecryptError(ValueError):
    """解密失败或包格式不支持."""


def is_encrypted(data: bytes) -> bool:
    return data.startswith(MAGIC_V1MMWX)


def looks_like_wxapkg(data: bytes) -> bool:
    """明文包以 0xBE ... 0xED 为头尾魔数."""
    if len(data) < 14:
        return False
    if is_encrypted(data):
        return True
    return data[0] == 0xBE and data[13] == 0xED


def guess_appid_from_path(path: str) -> str:
    """从常见目录结构猜测 AppID（父目录名 wx...）."""
    import os
    import re

    cur = os.path.abspath(path)
    for _ in range(6):
        name = os.path.basename(cur)
        if re.fullmatch(r"wx[0-9a-zA-Z]{16}", name):
            return name
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return ""


def decrypt_wxapkg(
    data: bytes,
    appid: str,
    *,
    salt: bytes = DEFAULT_SALT,
    iv: bytes = DEFAULT_IV,
) -> bytes:
    """解密 PC 端加密包；若已是明文包则原样返回."""
    if not data:
        raise WxapkgDecryptError("空文件")
    if not is_encrypted(data):
        if looks_like_wxapkg(data):
            return data
        raise WxapkgDecryptError("不是 V1MMWX 加密包，也不是合法明文 wxapkg")

    if not appid or not appid.strip():
        raise WxapkgDecryptError("加密包需要提供 AppID（一般是包所在文件夹名）")

    appid = appid.strip()
    key = hashlib.pbkdf2_hmac("sha1", appid.encode("utf-8"), salt, 1000, dklen=32)

    body = data[len(MAGIC_V1MMWX) :]
    if len(body) < HEADER_AES_LEN:
        raise WxapkgDecryptError("加密包过短，无法解密")

    enc_head = body[:HEADER_AES_LEN]
    enc_tail = body[HEADER_AES_LEN:]

    cipher = AES.new(key, AES.MODE_CBC, iv[:16].ljust(16, b"\0")[:16])
    dec_head = cipher.decrypt(enc_head)
    # 业界通用做法：只取前 1023 字节作为明文头，丢掉 AES 块末尾 1 字节
    plain_head = dec_head[:HEADER_PLAIN_LEN]

    if len(appid) < 2:
        xor_key = 0x66
    else:
        xor_key = appid.encode("utf-8")[-2]

    plain_tail = bytes(b ^ xor_key for b in enc_tail)
    plain = plain_head + plain_tail

    if not (plain[0] == 0xBE and len(plain) > 13 and plain[13] == 0xED):
        raise WxapkgDecryptError(
            "解密后魔数不匹配，请确认 AppID 是否正确（应为 wx 开头的小程序 ID）"
        )
    return plain
