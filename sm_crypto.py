"""国密算法 — SM4 对称加密 / SM3 哈希 (纯 Python 实现)."""

import base64


# ============================================================
# SM4 — 128位分组对称密码 (GB/T 32907-2016)
# ============================================================

SM4_SBOX = [
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
]

SM4_FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
SM4_CK = [
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
]


def _sm4_sbox(byte_val: int) -> int:
    return SM4_SBOX[byte_val]


def _sm4_rotl(value: int, n: int) -> int:
    return ((value << n) | (value >> (32 - n))) & 0xFFFFFFFF


def _sm4_round_key(k0: int, k1: int, k2: int, k3: int, ck: int) -> int:
    t = k1 ^ k2 ^ k3 ^ ck
    t = (_sm4_sbox((t >> 24) & 0xFF) << 24 |
         _sm4_sbox((t >> 16) & 0xFF) << 16 |
         _sm4_sbox((t >> 8) & 0xFF) << 8 |
         _sm4_sbox(t & 0xFF))
    t = t ^ _sm4_rotl(t, 13) ^ _sm4_rotl(t, 23)
    return k0 ^ t


def _sm4_expand_key(mk: bytes):
    k = [int.from_bytes(mk[i:i+4], "big") for i in range(0, 16, 4)]
    rk = []
    for i in range(4):
        k[i] ^= SM4_FK[i]
    for i in range(32):
        rk.append(_sm4_round_key(k[0], k[1], k[2], k[3], SM4_CK[i]))
        k = [k[1], k[2], k[3], rk[-1]]
    return rk


def _sm4_t_transform(x: int) -> int:
    b0 = _sm4_sbox((x >> 24) & 0xFF)
    b1 = _sm4_sbox((x >> 16) & 0xFF)
    b2 = _sm4_sbox((x >> 8) & 0xFF)
    b3 = _sm4_sbox(x & 0xFF)
    y = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    return y ^ _sm4_rotl(y, 2) ^ _sm4_rotl(y, 10) ^ _sm4_rotl(y, 18) ^ _sm4_rotl(y, 24)


def _sm4_round(x: list, rk: int) -> int:
    return x[0] ^ _sm4_t_transform(x[1] ^ x[2] ^ x[3] ^ rk)


def _sm4_crypt_block(block: bytes, rk: list) -> bytes:
    x = [int.from_bytes(block[i:i+4], "big") for i in range(0, 16, 4)]
    for i in range(32):
        x.append(_sm4_round(x[-4:], rk[i]))
    # Reverse order for output
    result = b""
    for val in reversed(x[-4:]):
        result += val.to_bytes(4, "big")
    return result


class SM4:
    """SM4-ECB 加解密."""
    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError("SM4 密钥必须为 16 字节")
        self.enc_rk = _sm4_expand_key(key)
        self.dec_rk = list(reversed(self.enc_rk))

    def encrypt_block(self, block: bytes) -> bytes:
        return _sm4_crypt_block(block, self.enc_rk)

    def decrypt_block(self, block: bytes) -> bytes:
        return _sm4_crypt_block(block, self.dec_rk)

    @staticmethod
    def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
        pad_len = block_size - len(data) % block_size
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def unpad_pkcs7(data: bytes) -> bytes:
        pad_len = data[-1]
        if pad_len == 0 or pad_len > 16:
            raise ValueError("PKCS7 去填充失败")
        if data[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("PKCS7 去填充失败")
        return data[:-pad_len]

    @staticmethod
    def pad_zero(data: bytes, block_size: int = 16) -> bytes:
        pad_len = block_size - len(data) % block_size
        if pad_len == block_size:
            return data
        return data + b'\x00' * pad_len

    @staticmethod
    def unpad_zero(data: bytes) -> bytes:
        return data.rstrip(b'\x00')


def sm4_encrypt_ecb(plaintext: str, key: str, padding: str = "PKCS7") -> str:
    sm4 = SM4(key.encode("utf-8"))
    data = plaintext.encode("utf-8")
    if padding == "PKCS7":
        data = SM4.pad_pkcs7(data)
    elif padding == "ZeroPadding":
        data = SM4.pad_zero(data)
    result = b""
    for i in range(0, len(data), 16):
        result += sm4.encrypt_block(data[i:i+16])
    return base64.b64encode(result).decode("utf-8")


def sm4_decrypt_ecb(ciphertext: str, key: str, padding: str = "PKCS7", input_fmt: str = "base64") -> str:
    sm4 = SM4(key.encode("utf-8"))
    data = base64.b64decode(ciphertext) if input_fmt == "base64" else bytes.fromhex(ciphertext)
    result = b""
    for i in range(0, len(data), 16):
        result += sm4.decrypt_block(data[i:i+16])
    if padding == "PKCS7":
        result = SM4.unpad_pkcs7(result)
    elif padding == "ZeroPadding":
        result = SM4.unpad_zero(result)
    return result.decode("utf-8")


def sm4_encrypt_cbc(plaintext: str, key: str, iv: str, padding: str = "PKCS7") -> str:
    sm4 = SM4(key.encode("utf-8"))
    iv_bytes = iv.encode("utf-8")[:16].ljust(16, b'\x00')
    data = plaintext.encode("utf-8")
    if padding == "PKCS7":
        data = SM4.pad_pkcs7(data)
    elif padding == "ZeroPadding":
        data = SM4.pad_zero(data)
    result = b""
    prev = iv_bytes
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[i:i+16], prev))
        encrypted = sm4.encrypt_block(block)
        result += encrypted
        prev = encrypted
    return base64.b64encode(result).decode("utf-8")


def sm4_decrypt_cbc(ciphertext: str, key: str, iv: str, padding: str = "PKCS7", input_fmt: str = "base64") -> str:
    sm4 = SM4(key.encode("utf-8"))
    iv_bytes = iv.encode("utf-8")[:16].ljust(16, b'\x00')
    data = base64.b64decode(ciphertext) if input_fmt == "base64" else bytes.fromhex(ciphertext)
    result = b""
    prev = iv_bytes
    for i in range(0, len(data), 16):
        decrypted = sm4.decrypt_block(data[i:i+16])
        result += bytes(a ^ b for a, b in zip(decrypted, prev))
        prev = data[i:i+16]
    if padding == "PKCS7":
        result = SM4.unpad_pkcs7(result)
    elif padding == "ZeroPadding":
        result = SM4.unpad_zero(result)
    return result.decode("utf-8")


# ============================================================
# SM3 — 密码杂凑算法 (GB/T 32905-2016)
# ============================================================

SM3_IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
          0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]

_SM3_T = [0x79CC4519] * 16 + [0x7A879D8A] * 48


def _sm3_rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _sm3_p0(x: int) -> int:
    return x ^ _sm3_rotl32(x, 9) ^ _sm3_rotl32(x, 17)


def _sm3_p1(x: int) -> int:
    return x ^ _sm3_rotl32(x, 15) ^ _sm3_rotl32(x, 23)


def _sm3_ff0(x: int, y: int, z: int) -> int:
    return x ^ y ^ z


def _sm3_ff1(x: int, y: int, z: int) -> int:
    return (x & y) | (x & z) | (y & z)


def _sm3_gg0(x: int, y: int, z: int) -> int:
    return x ^ y ^ z


def _sm3_gg1(x: int, y: int, z: int) -> int:
    return (x & y) | (~x & z)


def _sm3_cf(v: list, b: list) -> list:
    w = list(b) + [0] * 52
    for j in range(16, 68):
        w[j] = (_sm3_p1(w[j - 16] ^ w[j - 12] ^ _sm3_rotl32(w[j - 3], 15)) ^
                _sm3_rotl32(w[j - 13], 7) ^ w[j - 6])
    w1 = [w[j] ^ w[j + 4] for j in range(64)]

    a, b_val, c, d, e, f, g, h = v
    for j in range(64):
        t_val = _SM3_T[j]
        ss1 = _sm3_rotl32((_sm3_rotl32(a, 12) + e + _sm3_rotl32(t_val, j % 32)) & 0xFFFFFFFF, 7)
        ss2 = ss1 ^ _sm3_rotl32(a, 12)
        if j < 16:
            tt1 = (_sm3_ff0(a, b_val, c) + d + ss2 + w1[j]) & 0xFFFFFFFF
            tt2 = (_sm3_gg0(e, f, g) + h + ss1 + w[j]) & 0xFFFFFFFF
        else:
            tt1 = (_sm3_ff1(a, b_val, c) + d + ss2 + w1[j]) & 0xFFFFFFFF
            tt2 = (_sm3_gg1(e, f, g) + h + ss1 + w[j]) & 0xFFFFFFFF
        d = c
        c = _sm3_rotl32(b_val, 9)
        b_val = a
        a = tt1
        h = g
        g = _sm3_rotl32(f, 19)
        f = e
        e = _sm3_p0(tt2)

    return [(a ^ v[0]) & 0xFFFFFFFF, (b_val ^ v[1]) & 0xFFFFFFFF,
            (c ^ v[2]) & 0xFFFFFFFF, (d ^ v[3]) & 0xFFFFFFFF,
            (e ^ v[4]) & 0xFFFFFFFF, (f ^ v[5]) & 0xFFFFFFFF,
            (g ^ v[6]) & 0xFFFFFFFF, (h ^ v[7]) & 0xFFFFFFFF]


def sm3_hash(data: bytes) -> str:
    """SM3 哈希，返回十六进制字符串."""
    msg = bytearray(data)
    bit_len = len(msg) * 8
    msg.append(0x80)
    while (len(msg) * 8) % 512 != 448:
        msg.append(0x00)
    msg += bit_len.to_bytes(8, "big")

    v = list(SM3_IV)
    for i in range(0, len(msg), 64):
        block = [int.from_bytes(msg[i + j * 4:i + j * 4 + 4], "big") for j in range(16)]
        v = _sm3_cf(v, block)

    return "".join(f"{val:08x}" for val in v)


def sm3_hmac(key: bytes, data: bytes) -> str:
    """SM3 HMAC."""
    block_size = 64
    if len(key) > block_size:
        key = bytes.fromhex(sm3_hash(key))
    key = key.ljust(block_size, b'\x00')
    o_key_pad = bytes(k ^ 0x5C for k in key)
    i_key_pad = bytes(k ^ 0x36 for k in key)
    return sm3_hash(o_key_pad + bytes.fromhex(sm3_hash(i_key_pad + data)))
