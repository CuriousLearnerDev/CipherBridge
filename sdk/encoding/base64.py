"""Base64 编解码."""

import base64 as _b64


def base64_encode(data: str) -> str:
    return _b64.b64encode(data.encode("utf-8")).decode("utf-8")


def base64_decode(data: str) -> str:
    return _b64.b64decode(data).decode("utf-8")
