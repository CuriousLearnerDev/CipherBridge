"""GZIP 压缩/解压."""

import gzip as _gzip


def gzip_compress(data: str) -> bytes:
    return _gzip.compress(data.encode("utf-8"))


def gzip_decompress(data: bytes) -> str:
    return _gzip.decompress(data).decode("utf-8")
