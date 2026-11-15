"""Protobuf解析器 — 基础支持（需protobuf库）."""


def parse(data: bytes) -> dict:
    """Protobuf二进制数据解析为dict（目前返回原始信息）."""
    return {"_raw_hex": data.hex(), "_size": len(data), "_format": "protobuf_binary"}


def write(obj: dict) -> bytes:
    if "_raw_hex" in obj:
        return bytes.fromhex(obj["_raw_hex"])
    return b""
