"""JSON解析器 — 解析/修改/回写JSON请求体."""

import json


def parse(data: str) -> dict:
    try:
        return json.loads(data)
    except (json.JSONDecodeError, ValueError):
        return {"_raw": data}


def write(obj: dict) -> str:
    if "_raw" in obj and len(obj) == 1:
        return obj["_raw"]
    return json.dumps(obj, ensure_ascii=False)


def json_get(obj: dict, path: str, default=None):
    """读取嵌套JSON值: json_get(obj, '$.body.data')."""
    parts = path.strip("$.").split(".")
    cur = obj
    for p in parts:
        if isinstance(cur, dict):
            cur = cur.get(p)
        elif isinstance(cur, list):
            try:
                cur = cur[int(p.strip("[]"))]
            except (ValueError, IndexError):
                return default
        else:
            return default
        if cur is None:
            return default
    return cur


def json_set(obj: dict, path: str, value):
    """写入嵌套JSON值: json_set(obj, '$.body.data', 'xxx')."""
    parts = path.strip("$.").split(".")
    cur = obj
    for p in parts[:-1]:
        if p not in cur or not isinstance(cur[p], dict):
            cur[p] = {}
        cur = cur[p]
    cur[parts[-1]] = value
