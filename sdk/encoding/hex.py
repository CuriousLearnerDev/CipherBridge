"""Hex 编解码."""


def hex_encode(data: str) -> str:
    return data.encode("utf-8").hex()


def hex_decode(data: str) -> str:
    return bytes.fromhex(data).decode("utf-8")
