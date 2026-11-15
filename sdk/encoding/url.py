"""URL 编解码."""

import urllib.parse


def url_encode(data: str) -> str:
    return urllib.parse.quote(data)


def url_decode(data: str) -> str:
    return urllib.parse.unquote(data)


def url_encode_all(data: str) -> str:
    return urllib.parse.quote(data, safe="")
