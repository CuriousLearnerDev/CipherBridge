# 密桥 CipherBridge — MCP Server

让 Cursor / Claude Desktop / 其他 MCP 宿主调用密桥的**本地**能力（项目、试算、可选启停代理）。

## 架构

```
外部智能体 (Cursor / Claude …)
        │  MCP stdio
        ▼
 mcp_server (本目录)
   ├─ 项目只读  → profiles/ + plugins/
   ├─ 加解密试算 → sdk/ + analyzer/
   └─ 代理控制  → mitmdump（默认关闭，需环境变量）
```

与 GUI 内 Agent（`core/agent_tools.py`）的关系：

| | GUI Agent | MCP Server |
|--|-----------|------------|
| 流量 / Hook / JS | ✅ 会话内只读 | ❌ 暂不暴露（无常驻采集会话） |
| 项目 / 插件代码 | 间接 | ✅ |
| AES / Hash / 编码试算 | 弱 | ✅ |
| 启停 mitmdump | GUI 按钮 | ✅（需 `CB_MCP_ALLOW_PROXY=1`） |

## 工具一览

| Tool | 说明 |
|------|------|
| `cb_status` | 版本与根目录 |
| `list_projects` | 列出 profiles |
| `get_project` | profile + 插件摘要 |
| `get_plugin_code` | 读 `plugin.py` |
| `analyze_ciphertext` | Base64/Hex/JWT/熵 |
| `aes_crypto` | AES 加解密试算 |
| `hash_digest` | MD5/SHA*/SM3/HMAC |
| `encode_convert` | Base64/Hex/URL |
| `proxy_status` | 代理运行状态 |
| `proxy_start` / `proxy_stop` | 启停（需授权） |

## 安装

```bash
pip install "mcp>=1.26,<2" attrs
# 以及本仓库 requirements.txt（pycryptodome、PyYAML、mitmproxy 等）
```

## 启动（手动）

在仓库根目录：

```bash
python -m mcp_server
```

stdio 服务会阻塞等待宿主连接，属正常现象。

## Cursor 配置

设置 → MCP → 添加（或编辑 `mcp.json`）：

```json
{
  "mcpServers": {
    "cipherbridge": {
      "command": "python",
      "args": ["-m", "mcp_server"],
      "cwd": "/path/to/CipherBridge",
      "env": {
        "CB_MCP_ALLOW_PROXY": "0"
      }
    }
  }
}
```

需要智能体启停代理时，把 `CB_MCP_ALLOW_PROXY` 设为 `"1"`。

## 安全

- 默认**不能**启停代理，避免误开监听端口。
- 不读取、不返回 `config/ai.yaml` 中的 API Key。
- 仅本机 stdio；不要把未加固的 Streamable HTTP 暴露到公网。
- 仅用于**授权**安全测试。

## 后续可扩展（未做）

1. 与 GUI 共享会话：通过本机 socket / 文件桥接 AI 实验室的 flow/hook/js  
2. `codegen`：把步骤 JSON 生成 `plugin.py`  
3. DES/SM4/RSA 试算  
4. Streamable HTTP 传输（仅绑定 127.0.0.1）
