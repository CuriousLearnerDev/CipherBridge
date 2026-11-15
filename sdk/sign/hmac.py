"""HMAC 签名."""

import hmac as _hmac
import hashlib
import base64


_HASH_MAP = {"MD5": "md5", "SHA1": "sha1", "SHA256": "sha256",
             "SHA384": "sha384", "SHA512": "sha512"}


def hmac_sign(data: str, key: str, algo: str = "SHA256", output: str = "hex") -> str:
    hash_name = _HASH_MAP.get(algo, "sha256")
    sig = _hmac.new(key.encode("utf-8"), data.encode("utf-8"), hash_name)
    if output == "base64":
        return base64.b64encode(sig.digest()).decode("utf-8")
    return sig.hexdigest()
