"""熵值计算 — 用于识别加密/压缩数据."""

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """计算字节数据的香农熵 (0-8)"""
    if not data:
        return 0.0
    length = len(data)
    counter = Counter(data)
    entropy = 0.0
    for count in counter.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def is_encrypted(data: bytes, threshold: float = 7.5) -> bool:
    """判断数据是否可能是加密的（高熵 = 加密/压缩）."""
    return shannon_entropy(data) >= threshold


def is_compressed(data: bytes) -> bool:
    """判断是否压缩（GZIP魔数检查）."""
    return len(data) >= 2 and data[:2] == b'\x1f\x8b'


def analyze(data: bytes) -> dict:
    """综合分析一段数据."""
    entropy = shannon_entropy(data)
    return {
        "entropy": round(entropy, 2),
        "size": len(data),
        "likely_encrypted": entropy >= 7.5,
        "likely_compressed": is_compressed(data),
        "is_printable": all(32 <= b < 127 or b in (9, 10, 13) for b in data),
    }
