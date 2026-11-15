"""URL-Encoded Form 解析器."""

import urllib.parse


def parse(data: str) -> dict:
    try:
        return dict(urllib.parse.parse_qsl(data))
    except Exception:
        return {"_raw": data}


def write(obj: dict) -> str:
    if "_raw" in obj and len(obj) == 1:
        return obj["_raw"]
    return urllib.parse.urlencode(obj, doseq=True)
