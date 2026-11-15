"""WebSocket 消息处理."""

import json
import base64


def parse_message(data: bytes) -> dict:
    """解析WebSocket消息（尝试JSON, fallback base64）."""
    try:
        return json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"_binary_base64": base64.b64encode(data).decode()}


def build_message(obj: dict) -> bytes:
    """构建WebSocket消息."""
    if "_binary_base64" in obj:
        return base64.b64decode(obj["_binary_base64"])
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")
