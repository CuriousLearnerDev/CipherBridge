"""项目名称规范化."""

from __future__ import annotations

import re

# 字母 / 数字 / 下划线 / 中文汉字；须以字母或汉字开头
_NAME_RE = re.compile(r"^[a-z\u4e00-\u9fff][a-z0-9_\u4e00-\u9fff]*$", re.UNICODE)

# Windows 保留设备名（不区分大小写）
_WIN_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


def normalize_project_name(raw: str, default: str = "project") -> str:
    """转为合法项目名：英文小写字母/数字/下划线/中文，以字母或汉字开头."""
    name = (raw or "").strip().replace(" ", "_")
    # 去掉路径分隔等非法字符，保留中文
    name = re.sub(r"[^0-9A-Za-z_\u4e00-\u9fff]", "_", name)
    name = re.sub(r"_+", "_", name).strip("_")
    name = name.lower()  # 中文不受影响
    if not name:
        return default
    if name[0].isdigit():
        name = f"p_{name}"
    # 避免 Windows 保留名
    if name.lower() in _WIN_RESERVED:
        name = f"p_{name}"
    if not is_valid_project_name(name):
        return default
    return name


def is_valid_project_name(name: str) -> bool:
    return bool(name and _NAME_RE.match(name))
