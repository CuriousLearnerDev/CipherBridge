"""自定义扩展注册表 — 供插件编辑器、可视化构建器、代码生成共用."""

from __future__ import annotations

import importlib.util
import os
import sys
import traceback
from typing import Any, Callable

from core.paths import get_app_root

EXTENSIONS_DIR = os.path.join(get_app_root(), "extensions")
_REGISTRY: dict[str, dict[str, Any]] = {}
_LOADED_FILES: dict[str, float] = {}


def register(
    name: str,
    category: str = "custom",
    params: list[dict] | None = None,
    description: str = "",
):
    """注册自定义函数/类方法为可视化构建器步骤.

    函数签名: fn(value: str, **params) -> str
    params 中 field/scope 由框架注入, 无需在函数参数里声明.
    """

    def decorator(fn: Callable) -> Callable:
        ext_id = f"{fn.__module__}.{fn.__name__}"
        _REGISTRY[ext_id] = {
            "id": ext_id,
            "name": name,
            "display_type": f"🔌 {name}",
            "category": category,
            "description": description,
            "params": params or [],
            "fn": fn,
            "module": fn.__module__,
            "func_name": fn.__name__,
        }
        fn.__extension_meta__ = _REGISTRY[ext_id]
        return fn

    return decorator


def _scope_options() -> list[str]:
    return ["📋 Body (JSON)", "📋 Body (Form)", "🔗 URL Query"]


def _default_field_params() -> list[dict]:
    return [
        {"label": "字段名", "key": "field", "type": "str"},
        {"label": "数据来源", "key": "scope", "type": "choice", "options": _scope_options()},
    ]


def _param_to_gui(param: dict) -> tuple:
    if param.get("type") == "choice":
        return (param["label"], param["key"], param["options"])
    return (param["label"], param["key"], str)


def get_extension_op_types() -> dict[str, list[tuple]]:
    """返回 {display_type: [(label, key, type), ...]} 供 GUI 使用."""
    ops: dict[str, list[tuple]] = {}
    for meta in _REGISTRY.values():
        fields = [_param_to_gui(p) for p in _default_field_params() + meta["params"]]
        ops[meta["display_type"]] = fields
    return ops


def get_extension_choices() -> list[str]:
    return [meta["display_type"] for meta in _REGISTRY.values()]


def is_extension_op(op_type: str) -> bool:
    return op_type.startswith("🔌 ") or bool(
        _REGISTRY.get(op_type) or _get_by_display(op_type)
    )


def _get_by_display(display_type: str) -> dict | None:
    for meta in _REGISTRY.values():
        if meta["display_type"] == display_type:
            return meta
    return None


def get_meta(op_type: str, params: dict | None = None) -> dict | None:
    if params and params.get("extension_id"):
        return _REGISTRY.get(params["extension_id"])
    return _get_by_display(op_type)


def reload_extensions(force: bool = False) -> tuple[int, list[str]]:
    """扫描 extensions/ 目录并加载所有 .py 文件."""
    errors: list[str] = []
    if not os.path.isdir(EXTENSIONS_DIR):
        os.makedirs(EXTENSIONS_DIR, exist_ok=True)

    root = os.path.dirname(os.path.dirname(__file__))
    if root not in sys.path:
        sys.path.insert(0, root)

    # 清除旧注册 (保留即将重新注册的)
    old_ids = set(_REGISTRY.keys())
    new_ids: set[str] = set()

    for fname in sorted(os.listdir(EXTENSIONS_DIR)):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        path = os.path.join(EXTENSIONS_DIR, fname)
        try:
            mtime = os.path.getmtime(path)
            mod_name = f"extensions.{fname[:-3]}"
            if not force and mod_name in sys.modules and _LOADED_FILES.get(path) == mtime:
                for meta in _REGISTRY.values():
                    if meta["module"] == mod_name:
                        new_ids.add(meta["id"])
                continue

            # 重新加载前清除该文件旧注册
            for ext_id in list(_REGISTRY.keys()):
                if _REGISTRY[ext_id]["module"] == mod_name:
                    del _REGISTRY[ext_id]

            spec = importlib.util.spec_from_file_location(mod_name, path)
            if not spec or not spec.loader:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[mod_name] = module
            spec.loader.exec_module(module)
            _LOADED_FILES[path] = mtime
            for meta in list(_REGISTRY.values()):
                if meta["module"] == mod_name:
                    new_ids.add(meta["id"])
        except Exception as e:
            errors.append(f"{fname}: {e}\n{traceback.format_exc(limit=2)}")

    # 移除已删除文件中的注册
    for ext_id in old_ids - new_ids:
        _REGISTRY.pop(ext_id, None)

    return len(_REGISTRY), errors


def list_extension_files() -> list[str]:
    if not os.path.isdir(EXTENSIONS_DIR):
        return []
    return sorted(
        f for f in os.listdir(EXTENSIONS_DIR)
        if f.endswith(".py") and not f.startswith("_")
    )


def get_file_registered_names(filename: str) -> list[str]:
    mod_name = f"extensions.{filename[:-3]}"
    return [meta["name"] for meta in _REGISTRY.values() if meta["module"] == mod_name]


def run_extension_test(ext_id: str, value: str, params: dict | None = None) -> str:
    meta = _REGISTRY.get(ext_id)
    if not meta:
        raise ValueError(f"未找到扩展: {ext_id}")
    fn = meta["fn"]
    call_params = {}
    if params:
        skip = {"field", "scope", "extension_id"}
        call_params = {k: v for k, v in params.items() if k not in skip and v}
    return str(fn(value, **call_params))


def new_extension_template(name: str = "my_extension") -> str:
    return f'''"""自定义扩展: {name}

在此编写函数或类, 用 @register 注册后可在请求解析器/可视化构建器中使用.
函数签名: fn(value: str, **kwargs) -> str
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from core.extension_registry import register


# ---- 示例: 类封装复杂逻辑 ----
class MyHelper:
    """可在此定义有状态的 helper 类."""

    def __init__(self, prefix: str = ""):
        self.prefix = prefix

    def process(self, value: str) -> str:
        return self.prefix + value


_helper = MyHelper(prefix="")


@register(
    name="我的自定义处理",
    category="transform",
    description="示例: 在字段值前追加前缀",
    params=[
        {{"label": "前缀文本", "key": "prefix", "type": "str"}},
    ],
)
def my_custom_process(value: str, prefix: str = "", **kwargs) -> str:
    helper = MyHelper(prefix=prefix)
    return helper.process(value)
'''


# 启动时加载一次
reload_extensions(force=True)
