"""JsonPath 工具 — 支持 $.body.data 语法读写嵌套JSON."""


def json_get(obj: dict, path: str, default=None):
    """json_get(obj, '$.body.data') → 读取嵌套值."""
    parts = path.strip("$.").split(".")
    current = obj
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                current = current[int(part.strip("[]"))]
            except (ValueError, IndexError):
                return default
        else:
            return default
        if current is None:
            return default
    return current


def json_set(obj: dict, path: str, value):
    """json_set(obj, '$.body.data', 'xxx') → 写入嵌套值."""
    parts = path.strip("$.").split(".")
    current = obj
    for part in parts[:-1]:
        if part not in current:
            current[part] = {}
        current = current[part]
    current[parts[-1]] = value
