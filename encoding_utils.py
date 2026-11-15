"""编码与哈希工具 — Base64 / Hex / URL / MD5 / SHA."""

import base64
import hashlib
import urllib.parse


# ---- Base64 ----

def b64encode(data: str) -> str:
    return base64.b64encode(data.encode("utf-8")).decode("utf-8")


def b64decode(data: str) -> str:
    return base64.b64decode(data).decode("utf-8")


# ---- Hex ----

def hex_encode(data: str) -> str:
    return data.encode("utf-8").hex()


def hex_decode(data: str) -> str:
    return bytes.fromhex(data).decode("utf-8")


# ---- URL ----

def url_encode(data: str) -> str:
    return urllib.parse.quote(data)


def url_decode(data: str) -> str:
    return urllib.parse.unquote(data)


def url_encode_all(data: str) -> str:
    return urllib.parse.quote(data, safe="")


# ---- MD5 ----

def md5(data: str) -> str:
    return hashlib.md5(data.encode("utf-8")).hexdigest()


def md5_16(data: str) -> str:
    """MD5 16位 (取32位中间16位)."""
    return hashlib.md5(data.encode("utf-8")).hexdigest()[8:24]


def md5_base64(data: str) -> str:
    return base64.b64encode(hashlib.md5(data.encode("utf-8")).digest()).decode("utf-8")


# ---- SHA ----

def sha1(data: str) -> str:
    return hashlib.sha1(data.encode("utf-8")).hexdigest()


def sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def sha512(data: str) -> str:
    return hashlib.sha512(data.encode("utf-8")).hexdigest()


# ---- SM3 ----

def sm3(data: str) -> str:
    from sm_crypto import sm3_hash
    return sm3_hash(data.encode("utf-8"))


# ---- 编码映射表 ----

ENCODING_FUNCTIONS = {
    "Base64 Encode": b64encode,
    "Base64 Decode": b64decode,
    "Hex Encode": hex_encode,
    "Hex Decode": hex_decode,
    "URL Encode": url_encode,
    "URL Decode": url_decode,
    "URL Encode All": url_encode_all,
}

HASH_FUNCTIONS = {
    "MD5": md5,
    "MD5 (16位)": md5_16,
    "MD5 (Base64)": md5_base64,
    "SHA1": sha1,
    "SHA256": sha256,
    "SHA512": sha512,
    "SM3": sm3,
}
