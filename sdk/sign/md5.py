"""MD5 签名."""

import hashlib
import base64


def md5(data: str, output: str = "hex") -> str:
    h = hashlib.md5(data.encode("utf-8"))
    if output == "base64":
        return base64.b64encode(h.digest()).decode("utf-8")
    return h.hexdigest()


def md5_16(data: str) -> str:
    """MD5 16位 (取32位中间16位)."""
    return hashlib.md5(data.encode("utf-8")).hexdigest()[8:24]
