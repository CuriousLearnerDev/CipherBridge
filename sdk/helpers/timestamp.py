"""时间戳工具."""

import time


def timestamp_ms() -> int:
    """毫秒时间戳."""
    return int(time.time() * 1000)


def timestamp_s() -> int:
    """秒时间戳."""
    return int(time.time())
