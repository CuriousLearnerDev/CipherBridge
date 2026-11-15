"""请求/响应体解析与回写 — 支持 JSON / urlencoded / raw."""

import json
import urllib.parse


class BodyParser:
    def parse(self, flow, fmt: str = None) -> dict:
        content = flow.request.text or ""
        if fmt is None:
            fmt = self._detect(flow.request.headers.get("Content-Type", ""))
        if fmt == "json":
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                return {"_raw": content}
        elif fmt == "urlencoded":
            return dict(urllib.parse.parse_qsl(content))
        else:
            return {"_raw": content}

    def write(self, flow, data: dict, fmt: str):
        if "_raw" in data and len(data) == 1:
            flow.request.content = data["_raw"].encode("utf-8")
            return
        if fmt == "json":
            flow.request.content = json.dumps(data, ensure_ascii=False).encode("utf-8")
        elif fmt == "urlencoded":
            flow.request.content = urllib.parse.urlencode(data, doseq=True).encode("utf-8")
        else:
            flow.request.content = json.dumps(data, ensure_ascii=False).encode("utf-8")

    def parse_response(self, flow, fmt: str = None) -> dict:
        content = flow.response.text or ""
        if fmt is None:
            fmt = self._detect(flow.response.headers.get("Content-Type", ""))
        if fmt == "json":
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                return {"_raw": content}
        elif fmt == "urlencoded":
            return dict(urllib.parse.parse_qsl(content))
        else:
            return {"_raw": content}

    def write_response(self, flow, data: dict, fmt: str):
        if "_raw" in data and len(data) == 1:
            flow.response.content = data["_raw"].encode("utf-8")
            return
        if fmt == "json":
            flow.response.content = json.dumps(data, ensure_ascii=False).encode("utf-8")
        elif fmt == "urlencoded":
            flow.response.content = urllib.parse.urlencode(data, doseq=True).encode("utf-8")
        else:
            flow.response.content = json.dumps(data, ensure_ascii=False).encode("utf-8")

    @staticmethod
    def _detect(content_type: str) -> str:
        ct = content_type.lower()
        if "json" in ct:
            return "json"
        if "urlencoded" in ct:
            return "urlencoded"
        return "raw"
