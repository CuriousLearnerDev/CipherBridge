"""Zlib 压缩/解压."""

import zlib as _zlib


def zlib_compress(data: str) -> bytes:
    return _zlib.compress(data.encode("utf-8"))


def zlib_decompress(data: bytes) -> str:
    return _zlib.decompress(data).decode("utf-8")
