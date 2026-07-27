"""插件代码生成与逆向解析 — 生成含 requests 转发的独立 mitmdump 插件."""

import os
import re

import yaml

from core.paths import get_app_root

_ROOT = get_app_root()
_PROFILES_DIR = os.path.join(_ROOT, "profiles")

from core.brand import APP_TITLE
from core.extension_registry import get_meta
from core.match_rules import generate_match_guard_code

# 算法名 → (sdk模块, 函数前缀)
ALGO_SDK = {
    "AES": ("aes", "aes"),
    "DES": ("des", "des"),
    "3DES": ("tripledes", "tripledes"),
    "SM4": ("sm4", "sm4"),
    "RSA": ("rsa", "rsa"),
    "XOR": ("xor", "xor"),
}

_ALGO_REVERSE = {v[1]: k for k, v in ALGO_SDK.items()}

_ENCODE_TYPES = {
    "Base64编码", "Base64解码", "Hex编码", "Hex解码", "URL编码", "URL解码",
}
_ENCODE_ALIASES = {
    "base64_encode": "Base64编码", "base64_decode": "Base64解码",
    "base64编码": "Base64编码", "base64解码": "Base64解码",
    "hex_encode": "Hex编码", "hex_decode": "Hex解码",
    "url_encode": "URL编码", "url_decode": "URL解码",
    "urlencode": "URL编码", "urldecode": "URL解码",
    "encode": "Base64编码", "decode": "Base64解码",
    "encodeURIComponent": "URL编码", "decodeURIComponent": "URL解码",
}


def _resolve_encode_type(params: dict) -> str:
    raw = (
        params.get("encode_type")
        or params.get("encoding")
        or params.get("encode")
        or params.get("codec")
        or params.get("operation")
        or params.get("type")
        or ""
    )
    s = str(raw).strip()
    if s in _ENCODE_TYPES:
        return s
    mapped = _ENCODE_ALIASES.get(s.lower().replace(" ", "_"))
    if mapped:
        return mapped
    if "url" in s.lower():
        return "URL解码" if "解" in s or "dec" in s.lower() else "URL编码"
    if "hex" in s.lower():
        return "Hex解码" if "解" in s or "dec" in s.lower() else "Hex编码"
    if "base64" in s.lower() or "b64" in s.lower():
        return "Base64解码" if "解" in s or "dec" in s.lower() else "Base64编码"
    return "Base64解码"


def _normalize_scope_label(scope: str) -> str:
    if not scope:
        return "📋 Body (JSON)"
    if "Query" in scope or scope == "query" or "query" in scope.lower():
        return "🔗 URL Query"
    if "Form" in scope or "form" in scope.lower() or "表单" in scope or "urlencoded" in scope.lower():
        return "📋 Body (Form)"
    return "📋 Body (JSON)"


def normalize_step_params(step: dict) -> dict:
    """补全 AI 生成步骤中缺失或别名参数，避免代码生成 KeyError."""
    op = step.get("type", "")
    p = dict(step.get("params") or {})

    if "scope" in p or op in ("🔓 解密字段", "🔒 加密字段", "🔤 编码转换"):
        p["scope"] = _normalize_scope_label(p.get("scope", ""))

    if op == "🔤 编码转换":
        p["encode_type"] = _resolve_encode_type(p)
        p.setdefault("field", "data")
    elif op in ("🔓 解密字段", "🔒 加密字段"):
        p.setdefault("field", "data")
        p.setdefault("algo", "AES")
        p.setdefault("mode", "ECB")
        p.setdefault("padding", "PKCS7")
        p.setdefault("key", "")
    elif op in ("🔓 解密响应字段", "🔒 加密响应字段"):
        p.setdefault("field", "data")
        p.setdefault("algo", "AES")
        p.setdefault("mode", "ECB")
        p.setdefault("padding", "PKCS7")
        p.setdefault("key", "")
    elif op == "📝 签名(Hash)":
        p.setdefault("algo", "SHA256")
        p.setdefault("output", "hex")
        p.setdefault("target_type", "Header")
    return {"type": op, "params": p}


_CRYPTO_DECRYPT_OPS = frozenset({"🔓 解密字段", "🔓 解密响应字段"})
_CRYPTO_ENCRYPT_OPS = frozenset({"🔒 加密字段", "🔒 加密响应字段"})
_PRE_CRYPTO_DECODES = frozenset({"Base64解码", "Hex解码"})
_POST_CRYPTO_ENCODES = frozenset({"Base64编码", "Hex编码"})


def _step_field(params: dict) -> str:
    return (params.get("field") or "").strip() or "data"


def _fields_same_step(a: dict, b: dict) -> bool:
    """同字段或任一步未指定 field 时视为同一字段（AI 常漏填 field）."""
    fa, fb = _step_field(a), _step_field(b)
    if not (a.get("field") or "").strip() or not (b.get("field") or "").strip():
        return True
    return fa == fb


def optimize_pipeline_steps(steps: list[dict]) -> list[dict]:
    """移除加解密前后多余的 Base64/Hex 编解码（SDK 已内置 input_fmt/output）."""
    if not steps:
        return steps
    steps = [normalize_step_params(s) for s in steps]

    trimmed: list[dict] = []
    i = 0
    while i < len(steps):
        cur, nxt = steps[i], steps[i + 1] if i + 1 < len(steps) else None
        if (
            cur["type"] == "🔤 编码转换"
            and nxt is not None
            and _resolve_encode_type(cur["params"]) in _PRE_CRYPTO_DECODES
            and nxt["type"] in _CRYPTO_DECRYPT_OPS
            and _fields_same_step(cur["params"], nxt["params"])
        ):
            enc = _resolve_encode_type(cur["params"])
            fmt = "hex" if enc == "Hex解码" else "base64"
            merged = dict(nxt)
            merged["params"] = dict(nxt["params"])
            merged["params"]["input_fmt"] = fmt
            trimmed.append(merged)
            i += 2
            continue
        trimmed.append(cur)
        i += 1

    out: list[dict] = []
    i = 0
    while i < len(trimmed):
        cur, nxt = trimmed[i], trimmed[i + 1] if i + 1 < len(trimmed) else None
        if (
            cur["type"] in _CRYPTO_ENCRYPT_OPS
            and nxt is not None
            and nxt["type"] == "🔤 编码转换"
            and _resolve_encode_type(nxt["params"]) in _POST_CRYPTO_ENCODES
            and _fields_same_step(cur["params"], nxt["params"])
        ):
            out.append(cur)
            i += 2
            continue
        out.append(cur)
        i += 1
    return out


def _normalize_scope(scope: str) -> str:
    """body | form | query"""
    if not scope:
        return "body"
    if "Query" in scope or scope == "query":
        return "query"
    if "Form" in scope or scope == "form":
        return "form"
    return "body"


_BODY_FIELD_OPS = {
    "🔒 加密字段", "🔓 解密字段", "🔤 编码转换", "✂️ 正则清洗", "🔗 拼接字符串",
    "📦 设置Body字段", "⏰ 生成时间戳", "🎲 生成随机数", "✂️ 字符串切片", "🔀 字符串反转",
    "📝 签名(Hash)", "📝 生成签名", "📝 签名(HMAC带密钥)", "📝 签名(排序拼接)", "🔐 AuthToken生成",
}
_RESPONSE_FIELD_OPS = {"🔓 解密响应字段", "🔒 加密响应字段"}


def _scope_val(params: dict, key: str) -> str | None:
    raw = params.get(key, "")
    return _normalize_scope(raw) if raw else None


def _analyze_steps(steps: list, body_format: str = "json"):
    uses_query = False
    uses_body = False
    fmt = body_format or "json"
    for step in steps:
        p = step.get("params", {})
        scope = _scope_val(p, "scope")
        data_scope = _scope_val(p, "data_scope")
        target_type = p.get("target_type", "")
        op = step["type"]
        if op.startswith("🔌 "):
            if scope == "query":
                uses_query = True
            else:
                uses_body = True
            continue
        if scope == "query" or data_scope == "query" or target_type == "URL参数字段":
            uses_query = True
        if scope == "form" or data_scope == "form":
            uses_body = True
            fmt = "form"
        elif scope == "body" or data_scope == "body":
            uses_body = True
        elif op in _BODY_FIELD_OPS:
            if scope is None and data_scope is None:
                uses_body = True
            elif scope != "query" and data_scope != "query":
                uses_body = True
    if not uses_body and not uses_query:
        uses_body = True
    return uses_query, uses_body, fmt


def _field_get_scoped(field: str, scope: str) -> str:
    if scope == "query":
        return f'query.get("{field}", "")'
    return _field_get(field)


def _field_set_scoped(field: str, expr: str, scope: str) -> str:
    if scope == "query":
        return f'query["{field}"] = {expr}'
    return _field_set(field, expr)


def _iv_expr(iv: str, scope: str) -> str:
    """IV: 留空 | 固定值 | $session | @body字段 | #prefix(密文前缀)."""
    if not iv:
        return '""'
    if iv == "#prefix":
        return "#prefix"
    if iv.startswith("$"):
        return _key_expr(iv)
    if iv.startswith("@"):
        return f"str({_field_get_scoped(iv[1:], scope)})"
    return f'"{iv}"'


def _crypto_op_scoped(
    fn: str, field: str, key: str, mode: str, padding: str, scope: str, iv: str = "",
    input_fmt: str = "base64", output: str = "base64",
) -> str:
    iv_val = _iv_expr(iv, scope)
    if iv_val == "#prefix" and fn == "aes_decrypt":
        inner = (
            f"aes_decrypt_iv_prefix({_field_get_scoped(field, scope)}, {_key_expr(key)}, "
            f'mode="{mode}", padding="{padding}", input_fmt="{input_fmt}")'
        )
        return _field_set_scoped(field, inner, scope)
    iv_kw = f', iv={iv_val}' if iv_val != '""' else ""
    fmt_kw = ""
    if fn.endswith("_decrypt") and input_fmt != "base64":
        fmt_kw = f', input_fmt="{input_fmt}"'
    elif fn.endswith("_encrypt") and output != "base64":
        fmt_kw = f', output="{output}"'
    inner = (
        f'{fn}({_field_get_scoped(field, scope)}, {_key_expr(key)}, '
        f'mode="{mode}", padding="{padding}"{iv_kw}{fmt_kw})'
    )
    return _field_set_scoped(field, inner, scope)


def _sorted_sign_block(algo: str, sep: str, suffix: str, include_key: bool,
                       data_scope: str, target_type: str, target: str, comment: str) -> list:
    lines = []
    algo_lower = algo.lower()
    if algo == "SM3":
        lines.append("from sdk.sign.sm3 import sm3")
        fn_call_tpl = "sm3(sign_str.encode())"
    else:
        lines.append(f"from sdk.sign.sha import {algo_lower}")
        fn_call_tpl = f"{algo_lower}(sign_str)"
    lines.append("import json")
    var = "query" if data_scope == "query" else "data"
    lines.append(f"    # 排序拼接签名{comment}")
    lines.append("    parts = []")
    lines.append(f"    for k in sorted({var}.keys()):")
    lines.append(f"        v = {var}[k]")
    lines.append('        if v is None or v == "": continue')
    lines.append('        if isinstance(v, (dict, list)): v = json.dumps(v, separators=(",", ":"))')
    if include_key:
        lines.append(f'        parts.append(f"{{k}}={{{{v}}}}" + "{sep}")')
    else:
        lines.append(f'        parts.append(str(v) + "{sep}")')
    lines.append(f'    sign_str = "".join(parts) + "{suffix}"')
    fn_call = fn_call_tpl
    if target_type == "Header":
        lines.append(f'    ctx.set_header("{target}", {fn_call}){comment}')
    elif target_type == "URL参数字段":
        lines.append(f'    query["{target}"] = {fn_call}{comment}')
    else:
        lines.append(f"    {_field_set_scoped(target, fn_call, data_scope)}{comment}")
    return lines


def _sdk_import(algo: str, op: str) -> str:
    """op: 'encrypt' | 'decrypt'"""
    mod, prefix = ALGO_SDK.get(algo.upper(), (algo.lower(), algo.lower()))
    return f"from sdk.crypto.{mod} import {prefix}_{op}"


def _sdk_fn(algo: str, op: str) -> str:
    _, prefix = ALGO_SDK.get(algo.upper(), (algo.lower(), algo.lower()))
    return f"{prefix}_{op}"


def _field_path(path: str) -> str:
    """jsonpath 风格路径."""
    if path.startswith("$."):
        return path
    return f"$.{path}" if ("." in path or "[" in path) else path


def _field_get(field: str) -> str:
    if "." in field or "[" in field:
        return f'json_get(data, "{_field_path(field)}", "")'
    return f'data.get("{field}", "")'


def _field_set(field: str, expr: str) -> str:
    if "." in field or "[" in field:
        return f'json_set(data, "{_field_path(field)}", {expr})'
    return f'data["{field}"] = {expr}'


def _resp_field_get(field: str) -> str:
    if "." in field or "[" in field:
        return f'json_get(resp_data, "{_field_path(field)}", "")'
    return f'resp_data.get("{field}", "")'


def _resp_field_set(field: str, expr: str) -> str:
    if "." in field or "[" in field:
        return f'json_set(resp_data, "{_field_path(field)}", {expr})'
    return f'resp_data["{field}"] = {expr}'


def _iv_expr_resp(iv: str) -> str:
    if not iv:
        return '""'
    if iv == "#prefix":
        return "#prefix"
    if iv.startswith("$"):
        return _key_expr_flow(iv)
    if iv.startswith("@"):
        return f"str({_resp_field_get(iv[1:])})"
    return f'"{iv}"'


def _crypto_op_response(
    fn: str, field: str, key: str, mode: str, padding: str, iv: str = "",
    input_fmt: str = "base64", output: str = "base64",
) -> str:
    iv_val = _iv_expr_resp(iv)
    if iv_val == "#prefix" and "decrypt" in fn:
        inner = (
            f"aes_decrypt_iv_prefix({_resp_field_get(field)}, {_key_expr_flow(key)}, "
            f'mode="{mode}", padding="{padding}", input_fmt="{input_fmt}")'
        )
        return _resp_field_set(field, inner)
    fmt_kw = ""
    if "decrypt" in fn and input_fmt != "base64":
        fmt_kw = f', input_fmt="{input_fmt}"'
    elif "encrypt" in fn and output != "base64":
        fmt_kw = f', output="{output}"'
    inner = (
        f'{fn}({_resp_field_get(field)}, {_key_expr_flow(key)}, '
        f'mode="{mode}", padding="{padding}"{fmt_kw})'
    )
    return _resp_field_set(field, inner)


def _key_expr(key_val: str) -> str:
    if key_val.startswith("$"):
        return f'ctx.get_key("{key_val[1:]}", "")'
    return f'"{key_val}"'


def _key_expr_flow(key_val: str) -> str:
    if key_val.startswith("$"):
        return f'_SESSION.get("{key_val[1:]}", "")'
    return f'"{key_val}"'


def _adapt_lines_for_flow(lines: list[str]) -> list[str]:
    """将 ctx 风格步骤行转换为 flow + _SESSION 风格."""
    out = []
    for line in lines:
        line = re.sub(r'ctx\.set_header\("([^"]+)",\s*', r'flow.request.headers["\1"] = ', line)
        line = re.sub(r'ctx\.save_key\("([^"]+)",\s*', r'_SESSION["\1"] = ', line)
        line = line.replace("ctx.get_key(", "_SESSION.get(")
        line = line.replace("ctx.url", "flow.request.url")
        line = re.sub(
            r'ctx\.get_header\("([^"]+)",\s*"([^"]*)"\)',
            r'flow.request.headers.get("\1", "\2")',
            line,
        )
        line = line.replace("ctx.set_key_from_cookie(", "# flow-cookie: ")
        out.append(line)
    return out


def _adapt_response_lines_for_flow(lines: list[str]) -> list[str]:
    out = []
    for line in lines:
        m = re.search(r'ctx\.set_key_from_response\("([^"]+)",\s*"([^"]+)"\)', line)
        if m:
            kn, path = m.groups()
            expr = "resp_data"
            for part in path.split("."):
                expr += f'["{part}"]'
            out.append(f'    _SESSION["{kn}"] = str({expr})')
            continue
        m = re.search(r'ctx\.set_key_from_header\("([^"]+)",\s*"([^"]+)"\)', line)
        if m:
            out.append(f'    _SESSION["{m.group(1)}"] = flow.response.headers.get("{m.group(2)}", "")')
            continue
        out.append(line)
    return out


_FLOW_HELPERS = '''\
_SESSION = {}

def _write_json_body(flow, data):
    body = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    flow.request.content = body
    flow.request.headers["Content-Length"] = str(len(body))

def _write_form_body(flow, data):
    body = urllib.parse.urlencode(data, doseq=True).encode("utf-8")
    flow.request.content = body
    flow.request.headers["Content-Length"] = str(len(body))

def _write_json_response(flow, data):
    body = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    flow.response.content = body
    flow.response.headers["Content-Length"] = str(len(body))

def _forward_headers(flow):
    headers = dict(flow.request.headers)
    for h in ("Connection", "Transfer-Encoding", "Proxy-Connection", "Keep-Alive", "Content-Length"):
        headers.pop(h, None)
    content = flow.request.content or b""
    if content:
        headers["Content-Length"] = str(len(content))
    host, port = flow.request.host, flow.request.port
    if (flow.request.scheme == "https" and port != 443) or (flow.request.scheme == "http" and port != 80):
        headers["Host"] = f"{host}:{port}"
    else:
        headers["Host"] = host
    return headers
'''


def _burp_forward_block() -> str:
    return '''\
    proxies = {
        "http": f"http://{BURP_PROXY[0]}:{BURP_PROXY[1]}",
        "https": f"http://{BURP_PROXY[0]}:{BURP_PROXY[1]}",
    }
    try:
        burp_resp = requests.request(
            method=flow.request.method,
            url=flow.request.url,
            headers=_forward_headers(flow),
            data=flow.request.content,
            allow_redirects=False,
            proxies=proxies,
            timeout=30,
            verify=False,
        )
        flow.response = http.Response.make(
            burp_resp.status_code,
            burp_resp.content,
            dict(burp_resp.headers),
        )
    except Exception as e:
        print(f"转发到Burp失败: {e}")
        import traceback; traceback.print_exc()
'''


def _server_forward_block() -> str:
    return '''\
    try:
        server_resp = requests.request(
            method=flow.request.method,
            url=flow.request.url,
            headers=_forward_headers(flow),
            data=flow.request.content,
            allow_redirects=False,
            timeout=30,
            verify=False,
        )
        flow.response = http.Response.make(
            server_resp.status_code,
            server_resp.content,
            dict(server_resp.headers),
        )
    except Exception as e:
        print(f"转发到服务器失败: {e}")
        import traceback; traceback.print_exc()
'''


def _crypto_op(fn: str, field: str, key: str, mode: str, padding: str) -> str:
    inner = (
        f'{fn}({_field_get(field)}, {_key_expr(key)}, '
        f'mode="{mode}", padding="{padding}")'
    )
    return _field_set(field, inner)


def get_codegen_role(profile_name: str = "") -> str:
    """根据 profile roles 决定生成解密端(→Burp)还是加密端(→服务器)代码."""
    if not profile_name:
        return "decrypt"
    path = os.path.join(_PROFILES_DIR, f"{profile_name}.yaml")
    if not os.path.exists(path):
        return "decrypt"
    try:
        with open(path, encoding="utf-8") as f:
            roles = (yaml.safe_load(f) or {}).get("roles") or ["decrypt"]
        if "encrypt" in roles and "decrypt" not in roles:
            return "encrypt"
        return "decrypt"
    except Exception:
        return "decrypt"


def _load_profile_match(profile_name: str) -> dict:
    if not profile_name:
        return {}
    path = os.path.join(_PROFILES_DIR, f"{profile_name}.yaml")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return (yaml.safe_load(f) or {}).get("match", {})
    except Exception:
        return {}


def blank_plugin_template(name: str = "plugin") -> str:
    """新建项目时的空白 mitmdump 插件（合法 HTTPFlow 签名，可直接启动）."""
    return (
        f'"""插件: {name} — 由 {APP_TITLE} 生成.\n'
        "在「请求解析器」粘贴报文，左键字段添加加解密步骤后保存，即可覆盖本文件。\n"
        '"""\n'
        "import sys, os\n"
        'sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))\n'
        "from mitmproxy import http\n"
        "\n"
        "\n"
        "def request(flow: http.HTTPFlow) -> None:\n"
        "    # 添加步骤并保存项目后，此处会生成解密/加密逻辑\n"
        "    return\n"
        "\n"
        "\n"
        "def response(flow: http.HTTPFlow) -> None:\n"
        "    return\n"
    )


def default_profile_match_yaml() -> str:
    """新建项目默认匹配：放宽 path/methods，避免启动后「完全没流量」."""
    return (
        "match:\n"
        "  host:\n"
        "    - '*'\n"
        "  path:\n"
        "    - '*'\n"
        "  methods:\n"
        "    - POST\n"
        "    - PUT\n"
        "    - PATCH\n"
        "    - GET\n"
    )


def codegen_for_pipeline(steps: list, body_format: str = "json", profile_name: str = "") -> str:
    """按项目角色生成含 requests 转发的完整插件代码."""
    return generate_code_from_steps(
        steps,
        body_format,
        role=get_codegen_role(profile_name),
        profile_name=profile_name,
    )


def generate_code_from_steps(
    steps: list,
    body_format: str = "json",
    role: str = "decrypt",
    profile_name: str = "",
    match_rules: dict | None = None,
) -> str:
    """从步骤列表生成独立 mitmdump 插件 (含 requests 转发 Burp/服务器)."""
    if not steps:
        return "# 请添加操作步骤"

    steps = optimize_pipeline_steps([normalize_step_params(s) for s in steps])
    uses_query, uses_body, body_fmt = _analyze_steps(steps, body_format)
    imports = set()
    request_lines = []
    response_lines = []
    response_writes_body = False

    for i, step in enumerate(steps):
        op = step["type"]
        p = step["params"]
        comment = f"  # 步骤{i + 1}: {op}"
        scope = _normalize_scope(p.get("scope", ""))

        if op.startswith("🔌 "):
            meta = get_meta(op, p)
            if not meta:
                request_lines.append(f"    # 未找到扩展: {op}{comment}")
                continue
            func_name = meta["func_name"]
            imports.add(f"from {meta['module']} import {func_name}")
            field = p.get("field", "data")
            step_scope = _normalize_scope(p.get("scope", scope or "body"))
            if step_scope != "query":
                imports.add("from sdk.helpers.jsonpath import json_get, json_set")
            value_expr = _field_get_scoped(field, step_scope)
            kw_parts = []
            for param_def in meta["params"]:
                pk = param_def["key"]
                pv = p.get(pk, param_def.get("default", ""))
                if isinstance(pv, str) and pv.startswith("$"):
                    kw_parts.append(f"{pk}={_key_expr(pv)}")
                elif isinstance(pv, str):
                    kw_parts.append(f'{pk}="{pv}"')
                else:
                    kw_parts.append(f"{pk}={repr(pv)}")
            call = f"{func_name}({value_expr}"
            if kw_parts:
                call += ", " + ", ".join(kw_parts)
            call += ")"
            request_lines.append("    " + _field_set_scoped(field, call, step_scope) + comment)
            continue

        if op == "🔒 加密字段":
            imports.add(_sdk_import(p["algo"], "encrypt"))
            if scope != "query":
                imports.add("from sdk.helpers.jsonpath import json_get, json_set")
            fn = _sdk_fn(p["algo"], "encrypt")
            request_lines.append(
                "    " + _crypto_op_scoped(
                    fn, p["field"], p["key"], p["mode"], p["padding"], scope, p.get("iv", ""),
                    output=p.get("output", "base64"),
                ) + comment
            )

        elif op == "🔓 解密字段":
            imports.add(_sdk_import(p["algo"], "decrypt"))
            if scope != "query":
                imports.add("from sdk.helpers.jsonpath import json_get, json_set")
            fn = _sdk_fn(p["algo"], "decrypt")
            if p.get("iv") == "#prefix" and p.get("algo") == "AES":
                imports.add("from sdk.crypto.aes import aes_decrypt_iv_prefix")
            request_lines.append(
                "    " + _crypto_op_scoped(
                    fn, p["field"], p["key"], p["mode"], p["padding"], scope, p.get("iv", ""),
                    input_fmt=p.get("input_fmt", "base64"),
                ) + comment
            )

        elif op == "🔓 解密响应字段":
            imports.add(_sdk_import(p["algo"], "decrypt"))
            imports.add("from sdk.helpers.jsonpath import json_get, json_set")
            fn = _sdk_fn(p["algo"], "decrypt")
            if p.get("iv") == "#prefix" and p.get("algo") == "AES":
                imports.add("from sdk.crypto.aes import aes_decrypt_iv_prefix")
            response_lines.append(
                "    " + _crypto_op_response(
                    fn, p["field"], p["key"], p["mode"], p["padding"], p.get("iv", ""),
                    input_fmt=p.get("input_fmt", "base64"),
                ) + comment
            )
            response_writes_body = True

        elif op == "🔒 加密响应字段":
            imports.add(_sdk_import(p["algo"], "encrypt"))
            imports.add("from sdk.helpers.jsonpath import json_get, json_set")
            fn = _sdk_fn(p["algo"], "encrypt")
            response_lines.append(
                "    " + _crypto_op_response(
                    fn, p["field"], p["key"], p["mode"], p["padding"], p.get("iv", ""),
                    output=p.get("output", "base64"),
                ) + comment
            )
            response_writes_body = True

        elif op in ("📝 签名(Hash)", "📝 生成签名"):
            if p["algo"] == "SM3":
                imports.add("from sdk.sign.sm3 import sm3")
                fn = "sm3"
            else:
                imports.add(f"from sdk.sign.sha import {p['algo'].lower()}")
                fn = p["algo"].lower()
            src_scope = _normalize_scope(p.get("source_scope", p.get("scope", "body")))
            src = _field_get_scoped(p["source"], src_scope) if p.get("source") else "json.dumps(data, ensure_ascii=False)"
            sig_call = f"{fn}({src})"
            if p.get("output") == "base64":
                imports.add("import base64")
                sig_call = f"base64.b64encode(bytes.fromhex({fn}({src}))).decode()"
            if p["target_type"] == "Header":
                request_lines.append(f'    ctx.set_header("{p["target"]}", {sig_call}){comment}')
            elif p["target_type"] == "URL参数字段":
                request_lines.append(f'    query["{p["target"]}"] = {sig_call}{comment}')
            else:
                tgt_scope = _normalize_scope(p.get("target_scope", src_scope))
                request_lines.append("    " + _field_set_scoped(p["target"], sig_call, tgt_scope) + comment)

        elif op == "📝 签名(HMAC带密钥)":
            algo_map = {"HMAC-SHA256": "sha256", "HMAC-SHA1": "sha1", "HMAC-MD5": "md5", "HMAC-SHA512": "sha512"}
            hash_name = algo_map.get(p["algo"], "sha256")
            imports.add("import hmac")
            imports.add("import hashlib")
            src = _field_get(p["source"]) if p.get("source") else 'data.get("data", "")'
            hm_key_expr = _key_expr(p["hmac_key"])
            sig_call = f'hmac.new({hm_key_expr}.encode(), str({src}).encode(), hashlib.{hash_name}).hexdigest()'
            if p.get("output") == "base64":
                imports.add("import base64")
                sig_call = f"base64.b64encode(hmac.new({hm_key_expr}.encode(), str({src}).encode(), hashlib.{hash_name}).digest()).decode()"
            if p["target_type"] == "Header":
                request_lines.append(f'    ctx.set_header("{p["target"]}", {sig_call}){comment}')
            else:
                request_lines.append(f'    {_field_set(p["target"], sig_call)}{comment}')

        elif op == "📝 签名(排序拼接)":
            sep = p.get("separator", "|")
            suffix = p.get("secret_suffix", "")
            include_key = "是" in str(p.get("include_key", ""))
            data_scope = _normalize_scope(p.get("data_scope", p.get("scope", "body")))
            for line in _sorted_sign_block(
                p["algo"], sep, suffix, include_key, data_scope,
                p.get("target_type", "Body字段"), p.get("target", "sign"), comment,
            ):
                if line.startswith("from ") or line == "import json":
                    imports.add(line)
                else:
                    request_lines.append(line)

        elif op == "🔗 拼接字符串":
            imports.add("from sdk.helpers.jsonpath import json_get, json_set")
            sep = {"直接拼接": "", "用&拼接": "&", "用|拼接": "|", "用@@拼接": "@@", "用逗号拼接": ",", "用空格拼接": " "}.get(p["join_type"], "")
            v1 = _field_get(p.get("val1", "")) if "body字段" in str(p.get("src1", "")) else f'"{p.get("val1", "")}"'
            v2 = _field_get(p.get("val2", "")) if "body字段" in str(p.get("src2", "")) else f'"{p.get("val2", "")}"'
            target = p.get("target_field", "result")
            if sep:
                expr = "str(" + v1 + ') + "' + sep + '" + str(' + v2 + ")"
            else:
                expr = "str(" + v1 + ") + str(" + v2 + ")"
            request_lines.append("    " + _field_set(target, expr) + comment)

        elif op == "🔤 编码转换":
            if scope != "query":
                imports.add("from sdk.helpers.jsonpath import json_get, json_set")
            enc_map = {
                "Base64编码": "base64_encode", "Base64解码": "base64_decode",
                "Hex编码": "hex_encode", "Hex解码": "hex_decode",
                "URL编码": "url_encode", "URL解码": "url_decode",
            }
            enc_type = _resolve_encode_type(p)
            fn = enc_map.get(enc_type, "base64_decode")
            imports.add(f"from sdk.encoding.{fn.split('_')[0]} import {fn}")
            field = p.get("field", "data")
            fg = _field_get_scoped(field, scope)
            request_lines.append("    " + _field_set_scoped(field, fn + "(" + fg + ")", scope) + comment)

        elif op == "✂️ 正则清洗":
            if scope != "query":
                imports.add("from sdk.helpers.jsonpath import json_get, json_set")
            field = p["field"]
            fg = _field_get_scoped(field, scope)
            clean = p.get("clean_type", "")
            if clean == "清除\\r\\n":
                expr = "str(" + fg + ').replace(chr(13), "").replace(chr(10), "")'
            elif clean == "清除空白字符":
                imports.add("import re")
                expr = 're.sub(r"\\s+", "", str(' + fg + "))"
            elif clean == "清除引号":
                expr = "str(" + fg + ').replace(chr(34), "").replace(chr(39), "")'
            elif clean == "仅保留字母数字":
                imports.add("import re")
                expr = 're.sub(r"[^a-zA-Z0-9]", "", str(' + fg + "))"
            elif clean == "大写":
                expr = "str(" + fg + ").upper()"
            elif clean == "小写":
                expr = "str(" + fg + ").lower()"
            elif clean == "反转":
                expr = "str(" + fg + ")[::-1]"
            else:
                expr = ""
            if expr:
                request_lines.append("    " + _field_set_scoped(field, expr, scope) + comment)

        elif op == "🏷 设置Header":
            val_type = p.get("value_type", "")
            if "Query" in str(val_type) or "URL" in str(val_type):
                val = _field_get_scoped(p["value"], "query")
            elif "body字段" in str(val_type):
                val = _field_get(p["value"])
            elif "时间戳" in str(val_type):
                imports.add("from sdk.helpers.timestamp import timestamp_ms")
                val = "str(timestamp_ms())"
            elif "随机hex" in str(val_type):
                imports.add("from sdk.helpers.randoms import random_hex")
                val = "random_hex(16)"
            else:
                val = f'"{p["value"]}"'
            request_lines.append(f'    ctx.set_header("{p["header_name"]}", {val}){comment}')

        elif op in ("📦 设置Body字段", "📦 设置URL参数"):
            if scope != "query":
                imports.add("from sdk.helpers.jsonpath import json_get, json_set")
            val_type = p.get("value_type", "")
            if "Query" in str(val_type) or "URL" in str(val_type):
                val = _field_get_scoped(p["value"], "query")
            elif "body字段" in str(val_type):
                val = _field_get(p["value"])
            elif "时间戳" in str(val_type):
                imports.add("from sdk.helpers.timestamp import timestamp_ms")
                val = "str(timestamp_ms())"
            elif "随机hex" in str(val_type):
                imports.add("from sdk.helpers.randoms import random_hex")
                val = "random_hex(16)"
            else:
                val = f'"{p["value"]}"'
            field = p.get("field_path", p.get("target_field", ""))
            request_lines.append("    " + _field_set_scoped(field, val, scope) + comment)

        elif op == "⏰ 生成时间戳":
            if scope != "query":
                imports.add("from sdk.helpers.jsonpath import json_get, json_set")
            if p["ts_type"] == "毫秒时间戳":
                imports.add("from sdk.helpers.timestamp import timestamp_ms")
                val = "str(timestamp_ms())"
            elif p["ts_type"] == "秒时间戳":
                imports.add("from sdk.helpers.timestamp import timestamp_s")
                val = "str(timestamp_s())"
            else:
                imports.add("from datetime import datetime")
                val = 'datetime.now().strftime("%Y-%m-%d %H:%M:%S")'
            request_lines.append("    " + _field_set_scoped(p["target_field"], val, scope) + comment)

        elif op == "🎲 生成随机数":
            if scope != "query":
                imports.add("from sdk.helpers.jsonpath import json_get, json_set")
            rand_map = {
                "32位hex": "random_hex(32)", "16位hex": "random_hex(16)", "8位hex": "random_hex(8)",
                "UUID": "uuid4()", "6位数字": "random_digits(6)",
            }
            rt = p.get("rand_type", "16位hex")
            if "uuid4" in rand_map.get(rt, ""):
                imports.add("from sdk.helpers.randoms import uuid4")
            elif "random_digits" in rand_map.get(rt, ""):
                imports.add("from sdk.helpers.randoms import random_digits")
            else:
                imports.add("from sdk.helpers.randoms import random_hex")
            request_lines.append("    " + _field_set_scoped(p["target_field"], rand_map.get(rt, "random_hex(16)"), scope) + comment)

        elif op == "🔐 AuthToken生成":
            bk = p["base_key"]
            if bk.startswith("$"):
                bk_expr = _key_expr(bk)
                rev_expr = f"{bk_expr}[::-1]"
            else:
                bk_expr = f'"{bk}"'
                rev_expr = f'"{bk}"[::-1]'
            imports.add(_sdk_import(p["algo"], "encrypt"))
            imports.add("from sdk.sign.sha import sha256")
            imports.add("import urllib.parse")
            enc_fn = _sdk_fn(p["algo"], "encrypt")
            request_lines.append(f"    # AuthToken生成{comment}")
            request_lines.append(f"    _bk = {bk_expr}")
            request_lines.append(f'    encrypted_data = {enc_fn}({_field_get(p["sign_source"])}, _bk, mode="ECB", padding="PKCS7")')
            request_lines.append("    signature = sha256(encrypted_data)")
            request_lines.append("    url_path = urllib.parse.urlparse(ctx.url).path")
            if p.get("strip_prefix"):
                request_lines.append(f'    url_path = url_path.replace("{p["strip_prefix"]}", "", 1)')
            jwt_val = p["jwt_value"]
            jwt_src = f'ctx.get_header("{jwt_val}", "{jwt_val}")' if p.get("jwt_src") == "Header字段" else f'"{jwt_val}"'
            request_lines.append(f"    jwt_token = {jwt_src}")
            request_lines.append(f'    auth_parts = [url_path, jwt_token[-20:], signature[-20:], _bk[8:], "{p["origin"]}"]')
            request_lines.append('    auth_str = "@@".join(auth_parts)')
            request_lines.append(f"    reversed_key = {rev_expr}")
            request_lines.append(f'    encrypted_auth = {enc_fn}(auth_str, reversed_key, mode="ECB", padding="PKCS7")')
            request_lines.append('    ctx.set_header("AuthToken", encrypted_auth)')
            request_lines.append('    ctx.set_header("signature", signature)')

        elif op == "✂️ 字符串切片":
            imports.add("from sdk.helpers.jsonpath import json_get, json_set")
            slice_map = {
                "取后20位 [-20:]": "[-20:]", "取后10位 [-10:]": "[-10:]", "取前10位 [:10]": "[:10]",
                "取8位之后 [8:]": "[8:]", "取后5位 [-5:]": "[-5:]",
            }
            sl = p.get("custom_slice") if p.get("slice_type") == "自定义" else slice_map.get(p.get("slice_type", ""), "")
            fg = _field_get(p["field"])
            request_lines.append("    " + _field_set(p["field"], "str(" + fg + ")" + sl) + comment)

        elif op == "🔀 字符串反转":
            imports.add("from sdk.helpers.jsonpath import json_get, json_set")
            target = p.get("target_field", p["field"])
            fg = _field_get(p["field"])
            request_lines.append("    " + _field_set(target, "str(" + fg + ")[::-1]") + comment)

        elif op == "🔑 定义密钥(固定值)":
            request_lines.append(f'    ctx.save_key("{p["key_name"]}", "{p["key_value"]}"){comment}')

        elif op in ("🔑 提取密钥(响应)", "🔑 提取密钥(从响应)"):
            st = p["source_type"]
            if "body" in st:
                response_lines.append(f'    ctx.set_key_from_response("{p["key_name"]}", "{p["source_path"]}"){comment}')
            elif "Header" in st:
                response_lines.append(f'    ctx.set_key_from_header("{p["key_name"]}", "{p["source_path"]}"){comment}')
            elif "Cookie" in st:
                request_lines.append(f'    ctx.set_key_from_cookie("{p["key_name"]}", "{p["source_path"]}"){comment}')

        elif op in ("🔑 派生密钥(公式)", "🔑 派生密钥(计算)"):
            dt = p["derive_type"]
            param = p.get("derive_param", "")
            kn = p["key_name"]
            imports.add("import hashlib")
            imports.add("from sdk.helpers.timestamp import timestamp_ms")
            src = _field_get(param) if param else 'data.get("data", "")'
            if "MD5" in dt:
                request_lines.append(f'    ctx.save_key("{kn}", hashlib.md5(str({src}).encode()).hexdigest()){comment}')
            elif "SHA256" in dt and "时间戳" in dt:
                request_lines.append(f'    ctx.save_key("{kn}", hashlib.sha256((str(timestamp_ms()) + str({src})).encode()).hexdigest()){comment}')
            elif "SHA256" in dt:
                request_lines.append(f'    ctx.save_key("{kn}", hashlib.sha256(str({src}).encode()).hexdigest()){comment}')
            elif "反转" in dt:
                request_lines.append(f'    ctx.save_key("{kn}", str({src})[::-1]){comment}')
            elif "拼接" in dt:
                request_lines.append(f'    ctx.save_key("{kn}", str({src}) + str(timestamp_ms())){comment}')

    flow_request_lines = _adapt_lines_for_flow(request_lines)
    flow_response_lines = _adapt_response_lines_for_flow(response_lines)

    code = f'"""Auto-generated plugin — 由 {APP_TITLE} 生成."""\n'
    code += "import sys, os, json, requests, urllib.parse\n"
    code += 'sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))\n'
    code += "from mitmproxy import http\n"
    if role == "decrypt":
        code += '\nBURP_PORT = os.environ.get("BURP_PORT", "8080")\n'
        code += "BURP_PROXY = (\"127.0.0.1\", int(BURP_PORT))\n"
    for imp in sorted(imports):
        code += imp + "\n"
    code += "\n"
    code += _FLOW_HELPERS
    code += "\n"

    rules = match_rules if match_rules is not None else _load_profile_match(profile_name)
    match_guard = generate_match_guard_code(rules)
    if match_guard:
        code += match_guard

    if request_lines:
        methods = []
        if uses_query:
            methods.append("GET")
        if uses_body:
            methods.extend(["POST", "PUT", "PATCH"])
        if not methods:
            methods = ["POST", "PUT", "PATCH", "GET"]
        code += "def request(flow: http.HTTPFlow) -> None:\n"
        if match_guard:
            code += "    if not _should_process(flow):\n"
            code += "        return\n"
        code += f"    if flow.request.method not in {tuple(methods)}:\n"
        code += "        return\n"
        code += "    try:\n"
        if uses_body:
            if body_fmt == "form":
                code += "        data = dict(urllib.parse.parse_qsl(flow.request.text or \"\"))\n"
            else:
                code += "        data = json.loads(flow.request.content or b\"{}\")\n"
        if uses_query:
            code += "        _parsed = urllib.parse.urlparse(flow.request.url)\n"
            code += "        query = dict(urllib.parse.parse_qsl(_parsed.query, keep_blank_values=True))\n"
        for line in flow_request_lines:
            code += "    " + line + "\n"
        if uses_body:
            if body_fmt == "form":
                code += "        _write_form_body(flow, data)\n"
            else:
                code += "        _write_json_body(flow, data)\n"
        if uses_query:
            code += "        _parsed = urllib.parse.urlparse(flow.request.url)\n"
            code += "        new_q = urllib.parse.urlencode(query, doseq=True)\n"
            code += "        flow.request.url = urllib.parse.urlunparse((_parsed.scheme, _parsed.netloc, _parsed.path, _parsed.params, new_q, _parsed.fragment))\n"
        code += "    except Exception as e:\n"
        code += '        print(f"请求处理错误: {e}")\n'
        code += "        import traceback; traceback.print_exc()\n"
        code += "\n"
        if role == "encrypt":
            code += _server_forward_block()
        else:
            code += _burp_forward_block()
        code += "\n"
    else:
        code += "def request(flow: http.HTTPFlow) -> None:\n"
        code += "    # 暂无请求步骤：在解析器/构建器添加后保存即可\n"
        code += "    return\n\n"

    if response_lines:
        code += "def response(flow: http.HTTPFlow) -> None:\n"
        code += "    if not flow.response or not flow.response.content:\n"
        code += "        return\n"
        if match_guard:
            code += "    if not _should_process(flow):\n"
            code += "        return\n"
        code += "    try:\n"
        code += "        resp_data = json.loads(flow.response.content)\n"
        for line in flow_response_lines:
            code += "    " + line + "\n"
        if response_writes_body:
            code += "        _write_json_response(flow, resp_data)\n"
        code += "    except Exception as e:\n"
        code += '        print(f"响应处理错误: {e}")\n'
        code += "        import traceback; traceback.print_exc()\n"
        code += "\n"

    return code


def parse_code_to_steps(code: str) -> list:
    """从插件代码逆向生成操作步骤（支持 ctx 和旧 flow 风格）."""
    steps = []
    for line in code.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if "resp_data" in line and re.search(r"(\w+)_(decrypt|encrypt)\(", line):
            m = re.search(
                r"(\w+)_(decrypt|encrypt)\(.+,\s*(_SESSION\.get\(\"[^\"]+\"[^)]*\)|\"([^\"]+)\")\s*,\s*mode=\"(\w+)\"(?:\s*,\s*padding=\"(\w+)\")?\s*\)",
                line,
            )
            if m:
                prefix, op_kind = m.group(1), m.group(2)
                algo = _ALGO_REVERSE.get(prefix, prefix.upper())
                field_m = re.search(
                    r'resp_data\["(\w+)"\]|resp_data\.get\("(\w+)"|json_get\(resp_data,\s*"\$\.([^"]+)"',
                    line,
                )
                field = "data"
                if field_m:
                    field = field_m.group(1) or field_m.group(2) or field_m.group(3) or "data"
                key_raw = m.group(4)
                if key_raw:
                    key = key_raw
                else:
                    km = re.search(r'_SESSION\.get\("(\w+)"', m.group(3) or "")
                    key = f"${km.group(1)}" if km else ""
                mode = m.group(5) or "ECB"
                pad = m.group(6) or "PKCS7"
                op_type = "🔓 解密响应字段" if op_kind == "decrypt" else "🔒 加密响应字段"
                steps.append({"type": op_type, "params": {
                    "field": field, "algo": algo, "mode": mode, "key": key, "padding": pad,
                }})
                continue

        # aes_decrypt(..., "key", mode=..., padding=...)
        m = re.search(
            r"(\w+)_(decrypt|encrypt)\(.+,\s*(ctx\.get_key\(\"[^\"]+\"[^)]*\)|\"([^\"]+)\")\s*,\s*mode=\"(\w+)\"(?:\s*,\s*padding=\"(\w+)\")?\s*\)",
            line,
        )
        if m:
            prefix, op_kind = m.group(1), m.group(2)
            algo = _ALGO_REVERSE.get(prefix, prefix.upper())
            field_m = re.search(
                r'data\["(\w+)"\]|data\.get\("(\w+)"|json_get\(data,\s*"\$\.([^"]+)"',
                line,
            )
            field = "data"
            if field_m:
                field = field_m.group(1) or field_m.group(2) or field_m.group(3) or "data"
            key_raw = m.group(4)
            if key_raw:
                key = key_raw
            else:
                km = re.search(r'ctx\.get_key\("(\w+)"', m.group(3) or "")
                key = f"${km.group(1)}" if km else ""
            mode = m.group(5) or "ECB"
            pad = m.group(6) or "PKCS7"
            op_type = "🔓 解密字段" if op_kind == "decrypt" else "🔒 加密字段"
            steps.append({"type": op_type, "params": {"field": field, "algo": algo, "mode": mode, "key": key, "padding": pad}})
            continue

        m = re.search(r'ctx\.set_header\("([^"]+)"\s*,\s*(\w+)\(', line)
        if m:
            target, algo = m.groups()
            src_m = re.search(r'data\.get\("(\w+)"|json_get\(data,\s*"\$\.([^"]+)"', line)
            source = (src_m.group(1) or src_m.group(2)) if src_m else "data"
            steps.append({"type": "📝 签名(Hash)", "params": {
                "algo": algo.upper() if algo.upper() in ("SHA256", "MD5", "SHA1", "SHA512", "SM3") else "SHA256",
                "source": source, "output": "hex", "target_type": "Header", "target": target,
            }})
            continue

        m = re.search(r'ctx\.save_key\("(\w+)"\s*,\s*"([^"]+)"\)', line)
        if m:
            steps.append({"type": "🔑 定义密钥(固定值)", "params": {"key_name": m.group(1), "key_value": m.group(2), "_note": ""}})
            continue

        m = re.search(r'ctx\.set_key_from_response\("(\w+)"\s*,\s*"([^"]+)"\)', line)
        if m:
            steps.append({"type": "🔑 提取密钥(从响应)", "params": {
                "key_name": m.group(1), "source_type": "响应body字段", "source_path": m.group(2),
            }})
            continue

        m = re.search(r'query\["(\w+)"\]\s*=\s*random_hex\(', line)
        if m:
            steps.append({"type": "🎲 生成随机数", "params": {
                "rand_type": "16位hex", "target_field": m.group(1), "scope": "🔗 URL Query",
            }})
            continue

        m = re.search(r'query\["(\w+)"\]\s*=\s*(\w+)\(sign_str\)', line)
        if m:
            steps.append({"type": "📝 签名(排序拼接)", "params": {
                "algo": m.group(2).upper(), "data_scope": "🔗 URL Query",
                "separator": "|", "secret_suffix": "", "include_key": "否(仅value|)",
                "target_type": "URL参数字段", "target": m.group(1),
            }})
            continue

        m = re.search(r'query\["(\w+)"\]\s*=\s*(\w+)\(', line)
        if m and m.group(2) in ("md5", "sha256", "sha1", "sha512", "sm3"):
            src_m = re.search(r'data\.get\("(\w+)"|json_get\(data,\s*"\$\.([^"]+)"', line)
            source = (src_m.group(1) or src_m.group(2)) if src_m else ""
            steps.append({"type": "📝 签名(Hash)", "params": {
                "algo": m.group(2).upper(), "source": source, "output": "hex",
                "target_type": "URL参数字段", "target": m.group(1), "scope": "🔗 URL Query",
            }})
            continue

    return steps
