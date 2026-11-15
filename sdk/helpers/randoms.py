"""随机字符串工具."""

import secrets
import uuid


def random_hex(n: int = 16) -> str:
    """n字节随机hex字符串."""
    return secrets.token_bytes(n).hex()


def random_string(n: int = 16) -> str:
    """n个随机字母+数字."""
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return ''.join(secrets.choice(alphabet) for _ in range(n))


def random_digits(n: int = 16) -> str:
    """n个随机数字."""
    return ''.join(secrets.choice("0123456789") for _ in range(n))


def uuid4() -> str:
    return str(uuid.uuid4())
