"""内置示例 — 可复制为 my_extension.py 修改. 文件名 _ 开头不会自动加载."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from core.extension_registry import register
import base64


class DoubleBase64Helper:
    """类示例: 封装可复用的变换逻辑."""

    @staticmethod
    def encode(value: str) -> str:
        return base64.b64encode(base64.b64encode(value.encode())).decode()


@register(
    name="双重Base64编码",
    category="transform",
    description="连续两次 Base64 编码",
)
def double_base64_encode(value: str, **kwargs) -> str:
    return DoubleBase64Helper.encode(value)


@register(
    name="MD5摘要",
    category="sign",
    description="对字段值计算 MD5 hex",
)
def md5_digest(value: str, **kwargs) -> str:
    import hashlib
    return hashlib.md5(value.encode()).hexdigest()
