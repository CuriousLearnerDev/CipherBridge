"""CipherBridge MCP Server 入口（stdio）。

启动:
  python -m mcp_server

Cursor / Claude Desktop 配置见 mcp_server/README.md
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from mcp_server import __version__
from mcp_server.crypto_ops import (
    analyze_ciphertext as _analyze_ciphertext,
    crypto_aes,
    crypto_hash,
    encode_convert as _encode_convert,
)
from mcp_server.paths import ALLOW_PROXY_CTRL, ROOT, ensure_sys_path
from mcp_server.projects import (
    get_plugin_code as _get_plugin_code,
    get_project as _get_project,
    list_projects as _list_projects,
)
from mcp_server.proxy_ctrl import (
    proxy_start as _proxy_start,
    proxy_status as _proxy_status,
    proxy_stop as _proxy_stop,
)

ensure_sys_path()

mcp = FastMCP(
    "CipherBridge",
    instructions=(
        "密桥 CipherBridge MCP：本地加解密代理框架的工具面。"
        "优先用 list_projects / get_plugin_code 了解方案；"
        "用 analyze_ciphertext / aes_crypto / hash_digest / encode_convert 做本地试算；"
        "proxy_* 默认只读状态，启停需主机设置 CB_MCP_ALLOW_PROXY=1。"
        "本工具用于授权安全测试，勿对未授权目标操作。"
    ),
)


def _dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2)


@mcp.tool()
def cb_status() -> str:
    """返回密桥 MCP 版本、仓库根目录、代理控制是否开启。"""
    return _dumps(
        {
            "app": "CipherBridge",
            "mcp_version": __version__,
            "root": str(ROOT),
            "allow_proxy_ctrl": ALLOW_PROXY_CTRL,
        }
    )


@mcp.tool()
def list_projects() -> str:
    """列出 profiles/ 下的加解密项目（含模板）。"""
    return _dumps({"projects": _list_projects()})


@mcp.tool()
def get_project(name: str) -> str:
    """读取指定项目的 profile YAML 与 plugin.py 源码摘要。"""
    return _dumps(_get_project(name))


@mcp.tool()
def get_plugin_code(name: str, max_chars: int = 40000) -> str:
    """读取 plugins/{name}/plugin.py 完整代码（可截断）。"""
    return _dumps(_get_plugin_code(name, max_chars=max_chars))


@mcp.tool()
def analyze_ciphertext(text: str) -> str:
    """本地识别密文/编码形态（Base64、Hex、JWT、熵等），不访问外网。"""
    return _dumps(_analyze_ciphertext(text))


@mcp.tool()
def aes_crypto(
    op: str,
    data: str,
    key: str,
    mode: str = "ECB",
    padding: str = "PKCS7",
    iv: str = "",
    fmt: str = "base64",
) -> str:
    """AES 加密或解密试算。op=encrypt|decrypt；fmt=base64|hex。"""
    return _dumps(
        crypto_aes(
            op=op,
            data=data,
            key=key,
            mode=mode,
            padding=padding,
            iv=iv,
            fmt=fmt,
        )
    )


@mcp.tool()
def hash_digest(algo: str, data: str, key: str = "") -> str:
    """计算摘要：MD5 / SHA1 / SHA256 / SHA512 / SM3 / HMAC-SHA256（HMAC 时传 key）。"""
    return _dumps(crypto_hash(algo, data, key=key))


@mcp.tool()
def encode_convert(op: str, data: str) -> str:
    """编码转换：b64_encode|b64_decode|hex_encode|hex_decode|url_encode|url_decode。"""
    return _dumps(_encode_convert(op=op, data=data))


@mcp.tool()
def proxy_status() -> str:
    """查看本 MCP 进程托管的解密/加密端是否在跑（以及是否允许启停）。"""
    return _dumps(_proxy_status())


@mcp.tool()
def proxy_start(
    project: str,
    role: str = "decrypt",
    port: int = 8083,
    burp_port: int = 8080,
) -> str:
    """启动 mitmdump 加载项目插件。需环境变量 CB_MCP_ALLOW_PROXY=1。"""
    return _dumps(
        _proxy_start(project, role=role, port=port, burp_port=burp_port)
    )


@mcp.tool()
def proxy_stop(role: str = "decrypt") -> str:
    """停止代理。role=decrypt|encrypt|all。需 CB_MCP_ALLOW_PROXY=1。"""
    return _dumps(_proxy_stop(role))


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
