"""可视化构建：步骤 → 代码 / 代码 → 步骤（与 GUI VisualBuilderTab 对齐）。"""

from __future__ import annotations

from typing import Any

_SCOPE = ["📋 Body (JSON)", "📋 Body (Form)", "🔗 URL Query"]
_DATA_SCOPE = ["📋 Body", "🔗 URL Query"]
_CRYPTO_ALGO = ["AES", "DES", "3DES", "SM4", "RSA", "SM2", "XOR"]
_CRYPTO_MODE = [
    "ECB",
    "CBC",
    "CFB",
    "OFB",
    "CTR",
    "GCM",
    "OAEP",
    "PKCS1v15",
    "C1C3C2",
    "C1C2C3",
]
_PADDING = ["PKCS7", "ZeroPadding", "NoPadding", "OAEP", "PKCS1v15"]


# Web 构建器 / 解析器可用操作（参数名与 GUI / codegen 一致）
OP_CATALOG: list[dict[str, Any]] = [
    {
        "type": "🔓 解密字段",
        "group": "解密",
        "defaults": {
            "field": "data",
            "scope": "📋 Body (JSON)",
            "algo": "AES",
            "mode": "ECB",
            "key": "",
            "padding": "PKCS7",
            "iv": "",
            "input_fmt": "base64",
        },
    },
    {
        "type": "🔒 加密字段",
        "group": "加密",
        "defaults": {
            "field": "data",
            "scope": "📋 Body (JSON)",
            "algo": "AES",
            "mode": "ECB",
            "key": "",
            "padding": "PKCS7",
            "iv": "",
        },
    },
    {
        "type": "🔓 解密响应字段",
        "group": "解密",
        "defaults": {
            "field": "data",
            "algo": "AES",
            "mode": "ECB",
            "key": "",
            "padding": "PKCS7",
            "iv": "",
            "input_fmt": "base64",
        },
    },
    {
        "type": "🔒 加密响应字段",
        "group": "加密",
        "defaults": {
            "field": "data",
            "algo": "AES",
            "mode": "ECB",
            "key": "",
            "padding": "PKCS7",
            "iv": "",
        },
    },
    {
        "type": "📝 签名(Hash)",
        "group": "签名",
        "defaults": {
            "algo": "SHA256",
            "source": "data",
            "output": "hex",
            "target_type": "Header",
            "target": "X-Sign",
        },
    },
    {
        "type": "📝 签名(HMAC带密钥)",
        "group": "签名",
        "defaults": {
            "algo": "HMAC-SHA256",
            "hmac_key": "",
            "source": "data",
            "output": "hex",
            "target_type": "Header",
            "target": "X-Sign",
        },
    },
    {
        "type": "📝 签名(排序拼接)",
        "group": "签名",
        "defaults": {
            "algo": "MD5",
            "data_scope": "📋 Body",
            "separator": "|",
            "secret_suffix": "",
            "include_key": "否(仅value|)",
            "target_type": "Header",
            "target": "sign",
        },
    },
    {
        "type": "🔗 拼接字符串",
        "group": "编码",
        "defaults": {
            "join_type": "直接拼接",
            "src1": "📋 body字段(如data)",
            "val1": "data",
            "src2": "📝 固定文本",
            "val2": "",
            "target_field": "joined",
        },
    },
    {
        "type": "🔤 编码转换",
        "group": "编码",
        "defaults": {
            "field": "data",
            "scope": "📋 Body (JSON)",
            "encode_type": "Base64解码",
        },
    },
    {
        "type": "✂️ 正则清洗",
        "group": "编码",
        "defaults": {
            "field": "data",
            "scope": "📋 Body (JSON)",
            "clean_type": "清除\\r\\n",
        },
    },
    {
        "type": "🏷 设置Header",
        "group": "写入",
        "defaults": {
            "header_name": "X-Sign",
            "value_type": "📝 固定文本",
            "value": "",
        },
    },
    {
        "type": "📦 设置Body字段",
        "group": "写入",
        "defaults": {
            "field_path": "sign",
            "scope": "📋 Body (JSON)",
            "value_type": "📝 固定文本",
            "value": "",
        },
    },
    {
        "type": "⏰ 生成时间戳",
        "group": "生成",
        "defaults": {
            "ts_type": "毫秒时间戳",
            "target_field": "_t",
            "scope": "📋 Body (JSON)",
        },
    },
    {
        "type": "🎲 生成随机数",
        "group": "生成",
        "defaults": {
            "rand_type": "16位hex",
            "target_field": "nonce",
            "scope": "📋 Body (JSON)",
        },
    },
    {
        "type": "🔐 AuthToken生成",
        "group": "高级",
        "defaults": {
            "base_key": "",
            "jwt_src": "Header字段",
            "jwt_value": "Authorization",
            "sign_source": "data",
            "origin": "https://example.com",
            "strip_prefix": "/api",
            "algo": "AES",
        },
    },
    {
        "type": "✂️ 字符串切片",
        "group": "编码",
        "defaults": {
            "field": "data",
            "slice_type": "取后20位 [-20:]",
            "custom_slice": "",
        },
    },
    {
        "type": "🔀 字符串反转",
        "group": "编码",
        "defaults": {"field": "data", "target_field": "data"},
    },
    {
        "type": "🔑 定义密钥(固定值)",
        "group": "密钥",
        "defaults": {"key_name": "encKey", "key_value": "", "_note": ""},
    },
    {
        "type": "🔑 提取密钥(从响应)",
        "group": "密钥",
        "defaults": {
            "key_name": "encKey",
            "source_type": "响应body字段",
            "source_path": "result.secretKey",
        },
    },
    {
        "type": "🔑 派生密钥(计算)",
        "group": "密钥",
        "defaults": {
            "key_name": "encKey",
            "derive_type": "MD5(body字段)",
            "derive_param": "data",
        },
    },
]


OP_FIELDS: dict[str, list[tuple[str, str, list[str] | None]]] = {
    "🔓 解密字段": [
        ("字段名", "field", None),
        ("数据来源", "scope", _SCOPE),
        ("算法", "algo", _CRYPTO_ALGO),
        ("模式", "mode", _CRYPTO_MODE),
        ("密钥", "key", None),
        ("填充", "padding", _PADDING),
        ("IV", "iv", None),
        ("密文格式", "input_fmt", ["base64", "hex"]),
    ],
    "🔒 加密字段": [
        ("字段名", "field", None),
        ("数据来源", "scope", _SCOPE),
        ("算法", "algo", _CRYPTO_ALGO),
        ("模式", "mode", _CRYPTO_MODE),
        ("密钥", "key", None),
        ("填充", "padding", _PADDING),
        ("IV", "iv", None),
    ],
    "🔓 解密响应字段": [
        ("字段路径", "field", None),
        ("算法", "algo", _CRYPTO_ALGO),
        ("模式", "mode", _CRYPTO_MODE),
        ("密钥", "key", None),
        ("填充", "padding", _PADDING),
        ("IV", "iv", None),
        ("密文格式", "input_fmt", ["base64", "hex"]),
    ],
    "🔒 加密响应字段": [
        ("字段路径", "field", None),
        ("算法", "algo", _CRYPTO_ALGO),
        ("模式", "mode", _CRYPTO_MODE),
        ("密钥", "key", None),
        ("填充", "padding", _PADDING),
        ("IV", "iv", None),
    ],
    "📝 签名(Hash)": [
        ("签名算法", "algo", ["SHA256", "MD5", "SHA1", "SHA512", "SM3"]),
        ("源字段", "source", None),
        ("输出格式", "output", ["hex", "base64"]),
        ("写入方式", "target_type", ["Header", "Body字段"]),
        ("目标名", "target", None),
    ],
    "📝 签名(HMAC带密钥)": [
        ("HMAC算法", "algo", ["HMAC-SHA256", "HMAC-SHA1", "HMAC-MD5", "HMAC-SHA512", "HMAC-SM3"]),
        ("HMAC密钥", "hmac_key", None),
        ("源字段", "source", None),
        ("输出格式", "output", ["hex", "base64"]),
        ("写入方式", "target_type", ["Header", "Body字段"]),
        ("目标名", "target", None),
    ],
    "📝 签名(排序拼接)": [
        ("签名算法", "algo", ["MD5", "SHA256", "SHA1", "SM3"]),
        ("签名数据范围", "data_scope", _DATA_SCOPE),
        ("拼接分隔符", "separator", ["|", "&", ""]),
        ("密钥后缀", "secret_suffix", None),
        ("是否包含字段名", "include_key", ["是(key=value|)", "否(仅value|)"]),
        ("写入方式", "target_type", ["Header", "Body字段", "URL参数字段"]),
        ("目标名", "target", None),
    ],
    "🔗 拼接字符串": [
        ("拼接方式", "join_type", ["直接拼接", "用&拼接", "用|拼接", "用@@拼接", "用逗号拼接", "用空格拼接"]),
        ("左边来源", "src1", ["📋 body字段(如data)", "📝 固定文本"]),
        ("左边值", "val1", None),
        ("右边来源", "src2", ["📋 body字段(如data)", "📝 固定文本"]),
        ("右边值", "val2", None),
        ("结果写入字段", "target_field", None),
    ],
    "🔤 编码转换": [
        ("字段名", "field", None),
        ("数据来源", "scope", _SCOPE),
        (
            "编码方式",
            "encode_type",
            ["Base64编码", "Base64解码", "Hex编码", "Hex解码", "URL编码", "URL解码"],
        ),
    ],
    "✂️ 正则清洗": [
        ("字段名", "field", None),
        ("数据来源", "scope", _SCOPE),
        (
            "清洗方式",
            "clean_type",
            ["清除\\r\\n", "清除空白字符", "清除引号", "仅保留字母数字", "大写", "小写", "反转"],
        ),
    ],
    "🏷 设置Header": [
        ("Header名", "header_name", None),
        (
            "值的来源",
            "value_type",
            ["📋 body字段(如data)", "🔗 URL Query字段", "📝 固定文本", "⏰ 时间戳(毫秒)", "🎲 随机hex(16)"],
        ),
        ("字段名或文本值", "value", None),
    ],
    "📦 设置Body字段": [
        ("目标字段路径", "field_path", None),
        ("数据来源", "scope", _SCOPE),
        (
            "值的来源",
            "value_type",
            [
                "📋 body字段(如data)",
                "🔗 URL Query字段",
                "📝 固定文本",
                "⏰ 时间戳(毫秒)",
                "🎲 随机hex(16)",
                "🔗 拼接结果",
            ],
        ),
        ("字段名或文本值", "value", None),
    ],
    "⏰ 生成时间戳": [
        ("时间格式", "ts_type", ["毫秒时间戳", "秒时间戳", "年-月-日 时:分:秒"]),
        ("写入目标字段", "target_field", None),
        ("数据来源", "scope", _SCOPE),
    ],
    "🎲 生成随机数": [
        ("随机类型", "rand_type", ["32位hex", "16位hex", "8位hex", "UUID", "6位数字"]),
        ("写入目标字段", "target_field", None),
        ("数据来源", "scope", _SCOPE),
    ],
    "🔐 AuthToken生成": [
        ("基础密钥", "base_key", None),
        ("JWT来源", "jwt_src", ["Header字段", "固定值"]),
        ("JWT Header名/固定值", "jwt_value", None),
        ("签名来自哪个字段", "sign_source", None),
        ("Origin URL", "origin", None),
        ("URL前缀剥离", "strip_prefix", None),
        ("加密算法", "algo", ["AES", "SM4"]),
    ],
    "✂️ 字符串切片": [
        ("字段名", "field", None),
        (
            "切片方式",
            "slice_type",
            ["取后20位 [-20:]", "取后10位 [-10:]", "取前10位 [:10]", "取8位之后 [8:]", "取后5位 [-5:]", "自定义"],
        ),
        ("自定义切片", "custom_slice", None),
    ],
    "🔀 字符串反转": [
        ("字段名", "field", None),
        ("写入目标字段", "target_field", None),
    ],
    "🔑 定义密钥(固定值)": [
        ("密钥变量名", "key_name", None),
        ("密钥值", "key_value", None),
        ("说明", "_note", None),
    ],
    "🔑 提取密钥(从响应)": [
        ("密钥变量名", "key_name", None),
        ("提取来源", "source_type", ["响应body字段", "响应Header", "请求Cookie"]),
        ("字段路径/Header名/Cookie名", "source_path", None),
    ],
    "🔑 派生密钥(计算)": [
        ("密钥变量名", "key_name", None),
        (
            "派生方式",
            "derive_type",
            ["MD5(body字段)", "SHA256(body字段)", "SHA256(时间戳+字段)", "字段值反转", "拼接: 字段+时间戳"],
        ),
        ("公式参数", "derive_param", None),
    ],
}


# 与 GUI VisualBuilderTab._TEMPLATE_DEFS 对齐
TEMPLATE_DEFS: list[dict[str, Any]] = [
    {
        "name": "简单AES解密",
        "group": "解密",
        "desc": "请求体 data 字段 AES-ECB 解密 — 解密端最常用",
        "steps": [
            {
                "type": "🔓 解密字段",
                "params": {
                    "field": "data",
                    "algo": "AES",
                    "mode": "ECB",
                    "key": "your-16-byte-key!",
                    "padding": "PKCS7",
                },
            },
        ],
    },
    {
        "name": "简单AES加密",
        "group": "加密",
        "desc": "请求体 data 字段 AES-ECB 加密 — 加密端回包前",
        "steps": [
            {
                "type": "🔒 加密字段",
                "params": {
                    "field": "data",
                    "algo": "AES",
                    "mode": "ECB",
                    "key": "your-16-byte-key!",
                    "padding": "PKCS7",
                },
            },
        ],
    },
    {
        "name": "简单RSA加密",
        "group": "加密",
        "desc": "字段 RSA-OAEP 公钥加密（登录密码等短字段常见）",
        "steps": [
            {
                "type": "🔒 加密字段",
                "params": {
                    "field": "password",
                    "algo": "RSA",
                    "mode": "OAEP",
                    "key": "-----BEGIN PUBLIC KEY-----\n...(粘贴 PEM)...\n-----END PUBLIC KEY-----",
                    "padding": "OAEP",
                },
            },
        ],
    },
    {
        "name": "AES+签名+时间戳",
        "group": "加密",
        "desc": "加密 data + SHA256/HMAC 头签名 + 时间戳与 nonce",
        "steps": [
            {
                "type": "🔒 加密字段",
                "params": {
                    "field": "data",
                    "algo": "AES",
                    "mode": "ECB",
                    "key": "your-16-byte-key!",
                    "padding": "PKCS7",
                },
            },
            {
                "type": "📝 签名(Hash)",
                "params": {
                    "algo": "SHA256",
                    "source": "data",
                    "output": "hex",
                    "target_type": "Header",
                    "target": "X-Sign",
                },
            },
            {
                "type": "📝 签名(HMAC带密钥)",
                "params": {
                    "algo": "HMAC-SHA256",
                    "hmac_key": "your-hmac-key",
                    "source": "data",
                    "output": "base64",
                    "target_type": "Header",
                    "target": "X-HMAC",
                },
            },
            {
                "type": "🏷 设置Header",
                "params": {
                    "header_name": "X-Timestamp",
                    "value_type": "⏰ 时间戳(毫秒)",
                    "value": "",
                },
            },
            {
                "type": "🎲 生成随机数",
                "params": {"rand_type": "16位hex", "target_field": "nonce"},
            },
        ],
    },
    {
        "name": "3DES+AuthToken",
        "group": "加密",
        "desc": "3DES 加密 + Hash 签名 + AuthToken 头",
        "steps": [
            {
                "type": "🔒 加密字段",
                "params": {
                    "field": "data",
                    "algo": "3DES",
                    "mode": "ECB",
                    "key": "your-24-byte-3des-key!!",
                    "padding": "PKCS7",
                },
            },
            {
                "type": "📝 签名(Hash)",
                "params": {
                    "algo": "SHA256",
                    "source": "data",
                    "output": "hex",
                    "target_type": "Header",
                    "target": "signature",
                },
            },
            {
                "type": "🔐 AuthToken生成",
                "params": {
                    "base_key": "your-24-byte-3des-key!!",
                    "jwt_src": "Header字段",
                    "jwt_value": "Authorization",
                    "sign_source": "data",
                    "origin": "https://example.com",
                    "strip_prefix": "/api",
                    "algo": "AES",
                },
            },
            {
                "type": "🏷 设置Header",
                "params": {
                    "header_name": "Content-Type",
                    "value_type": "📝 固定文本",
                    "value": "application/json",
                },
            },
        ],
    },
    {
        "name": "动态密钥(响应提取)",
        "group": "高级",
        "desc": "从响应提取密钥变量，再加密并签名",
        "steps": [
            {
                "type": "🔑 提取密钥(从响应)",
                "params": {
                    "key_name": "encKey",
                    "source_type": "响应body字段",
                    "source_path": "result.secretKey",
                },
            },
            {
                "type": "🔒 加密字段",
                "params": {
                    "field": "data",
                    "algo": "AES",
                    "mode": "ECB",
                    "key": "$encKey",
                    "padding": "PKCS7",
                },
            },
            {
                "type": "📝 签名(Hash)",
                "params": {
                    "algo": "SHA256",
                    "source": "data",
                    "output": "hex",
                    "target_type": "Header",
                    "target": "X-Sign",
                },
            },
        ],
    },
    {
        "name": "时间戳+MD5签名",
        "group": "高级",
        "desc": "生成 _t 与 nonce，对 _t 做 MD5 写入 Header",
        "steps": [
            {
                "type": "⏰ 生成时间戳",
                "params": {
                    "ts_type": "毫秒时间戳",
                    "target_field": "_t",
                    "scope": "📋 Body (JSON)",
                },
            },
            {
                "type": "🎲 生成随机数",
                "params": {
                    "rand_type": "16位hex",
                    "target_field": "nonce",
                    "scope": "📋 Body (JSON)",
                },
            },
            {
                "type": "📝 签名(Hash)",
                "params": {
                    "algo": "MD5",
                    "source": "_t",
                    "output": "hex",
                    "target_type": "Header",
                    "target": "signData",
                },
            },
        ],
    },
    {
        "name": "排序拼接签名",
        "group": "高级",
        "desc": "URL Query 排序拼接 + secret 后缀 MD5 → sign",
        "steps": [
            {
                "type": "🎲 生成随机数",
                "params": {
                    "rand_type": "16位hex",
                    "target_field": "nonce",
                    "scope": "🔗 URL Query",
                },
            },
            {
                "type": "📝 签名(排序拼接)",
                "params": {
                    "algo": "MD5",
                    "data_scope": "🔗 URL Query",
                    "separator": "|",
                    "secret_suffix": "your-secret-key",
                    "include_key": "否(仅value|)",
                    "target_type": "URL参数字段",
                    "target": "sign",
                },
            },
        ],
    },
]


def list_ops() -> list[dict[str, Any]]:
    out = []
    for op in OP_CATALOG:
        item = dict(op)
        item["fields"] = OP_FIELDS.get(op["type"], [])
        out.append(item)
    return out


def list_templates() -> list[dict[str, Any]]:
    return [
        {
            "name": t["name"],
            "group": t["group"],
            "desc": t.get("desc") or "",
            "steps": t["steps"],
            "step_count": len(t["steps"]),
        }
        for t in TEMPLATE_DEFS
    ]


def merge_template_steps(name: str) -> dict[str, Any]:
    """加载模板：默认参数 + 模板差异参数。"""
    tpl = next((t for t in TEMPLATE_DEFS if t["name"] == name), None)
    if not tpl:
        return {"ok": False, "error": f"未知模板: {name}", "steps": []}
    by_type = {o["type"]: o for o in OP_CATALOG}
    built: list[dict[str, Any]] = []
    for step in tpl["steps"]:
        op_type = step.get("type") or ""
        base = dict((by_type.get(op_type) or {}).get("defaults") or {})
        base.update(dict(step.get("params") or {}))
        built.append({"type": op_type, "params": base})
    return {
        "ok": True,
        "name": tpl["name"],
        "desc": tpl.get("desc") or "",
        "steps": built,
    }


def preview_code(
    steps: list[dict[str, Any]],
    *,
    body_format: str = "json",
    profile_name: str = "",
) -> dict[str, Any]:
    from codegen import codegen_for_pipeline

    steps = list(steps or [])
    if not steps:
        return {"ok": True, "code": "", "steps": 0}
    try:
        code = codegen_for_pipeline(steps, body_format or "json", profile_name=profile_name)
        return {"ok": True, "code": code, "steps": len(steps)}
    except Exception as e:
        return {"ok": False, "error": str(e), "code": "", "steps": len(steps)}


def reverse_steps(code: str) -> dict[str, Any]:
    from codegen import parse_code_to_steps

    try:
        steps = parse_code_to_steps(code or "")
        return {"ok": True, "steps": steps or []}
    except Exception as e:
        return {"ok": False, "error": str(e), "steps": []}
