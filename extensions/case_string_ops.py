"""字符串处理扩展 — 前缀/后缀/反转/截取.

演示用 class 封装多条字符串规则
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from core.extension_registry import register


class StringHelper:
    """字符串变换工具类."""

    def __init__(self, prefix: str = "", suffix: str = ""):
        self.prefix = prefix
        self.suffix = suffix

    def wrap(self, value: str) -> str:
        return f"{self.prefix}{value}{self.suffix}"

    @staticmethod
    def reverse(value: str) -> str:
        return value[::-1]

    @staticmethod
    def slice_tail(value: str, n: int = 20) -> str:
        n = max(1, int(n))
        return value[-n:] if len(value) >= n else value


@register(
    name="追加前后缀",
    category="transform",
    description="在字段值前后追加文本",
    params=[
        {"label": "前缀", "key": "prefix", "type": "str"},
        {"label": "后缀", "key": "suffix", "type": "str"},
    ],
)
def str_wrap(value: str, prefix: str = "", suffix: str = "", **kwargs) -> str:
    return StringHelper(prefix, suffix).wrap(value)


@register(
    name="字符串反转",
    category="transform",
    description="将字段值字符反转",
)
def str_reverse(value: str, **kwargs) -> str:
    return StringHelper.reverse(value)


@register(
    name="取字段后N位",
    category="transform",
    description="类似 [-20:] 截取末尾",
    params=[{"label": "位数", "key": "n", "type": "str"}],
)
def str_tail(value: str, n: str = "20", **kwargs) -> str:
    return StringHelper.slice_tail(value, int(n or 20))
