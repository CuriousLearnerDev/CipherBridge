"""SHA 签名."""

import hashlib


def sha1(data: str) -> str:
    return hashlib.sha1(data.encode("utf-8")).hexdigest()


def sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def sha384(data: str) -> str:
    return hashlib.sha384(data.encode("utf-8")).hexdigest()


def sha512(data: str) -> str:
    return hashlib.sha512(data.encode("utf-8")).hexdigest()
