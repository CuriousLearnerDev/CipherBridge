"""AI 分析 — 结合 Hook 日志与 HTTP 流量，生成 CryptoProxy 步骤 JSON."""

from __future__ import annotations

import json
import re
import requests
from PyQt6.QtCore import QThread, pyqtSignal

from core.extension_registry import get_extension_choices
from codegen import normalize_step_params, optimize_pipeline_steps

BUILTIN_STEP_TYPES = [
    "🔓 解密字段", "🔒 加密字段", "🔓 解密响应字段", "🔒 加密响应字段",
    "📝 签名(Hash)", "📝 签名(HMAC带密钥)",
    "📝 签名(排序拼接)", "🔤 编码转换", "🔗 拼接字符串", "✂️ 正则清洗",
    "🏷 设置Header", "📦 设置Body字段", "⏰ 生成时间戳", "🎲 生成随机数",
    "🔐 AuthToken生成", "✂️ 字符串切片", "🔀 字符串反转",
    "🔑 定义密钥(固定值)", "🔑 提取密钥(从响应)", "🔑 派生密钥(计算)",
]

SYSTEM_PROMPT_DECRYPT = """你是 JavaScript 逆向与 HTTP 加解密分析专家。
根据 Hook 日志、HTTP 请求/响应，推断**解密端**代理流程：浏览器密文 → 解密 → 转发 Burp 明文。

必须只输出一个 JSON 对象，不要 markdown 代码块，格式:
{
  "summary": "简短中文分析",
  "confidence": "high|medium|low",
  "steps": [
    {"type": "🔓 解密字段", "params": {"field": "data", "algo": "AES", "mode": "ECB", "key": "...", "padding": "PKCS7", "scope": "📋 Body (JSON)"}},
    {"type": "🔓 解密响应字段", "params": {"field": "result.data", "algo": "AES", "mode": "ECB", "key": "...", "padding": "PKCS7"}}
  ]
}

规则:
1. type 必须从提供的步骤类型列表中选择
2. params 字段名与 CryptoProxy 构建器一致
3. 密钥优先从 Hook 日志提取，不要编造
4. 不确定时 confidence 设为 low，并在 summary 说明需人工确认
5. **解密端请求用 🔓 解密字段**；**响应体加密时用 🔓 解密响应字段**（field 支持嵌套路径如 result.data）
6. 用户追问时输出**完整更新后**的 JSON
7. **禁止** key/mode/padding/algo 为 "unknown"；未确认则不要生成该步骤
8. Hook 含 `Key (String):` 时必须写入 steps 的 key
9. 编码转换含 encode_type: Base64编码/Base64解码/Hex编码/Hex解码/URL编码/URL解码
10. scope: 📋 Body (JSON) / 📋 Body (Form) / 🔗 URL Query（仅用于请求步骤）
11. 流量含 Request/Response Headers，签名/Token 常在 Header 中，可用 🏷 设置Header 或 📝 签名(Hash) 写入 Header
12. **禁止**在 🔓 解密字段 / 🔒 加密字段 前后添加 Base64/Hex 编解码：AES/DES/SM4/RSA 等 SDK 已内置 input_fmt/output（默认 Base64），密文字段直接写加解密步骤即可
13. 🔤 编码转换仅用于明文层编码（如 Base64 包 JSON 字符串），不用于 AES 密文
14. JS 若带 miniprogram:// 前缀，为微信小程序反编译源码；常见 CryptoJS / encrypt / wx.request，优先从中找密钥与字段
"""

SYSTEM_PROMPT_ENCRYPT = """你是 JavaScript 逆向与 HTTP 加解密分析专家。
根据 Hook 日志、HTTP 请求/响应，推断**加密端**代理流程：Burp 明文 → 加密/签名 → 转发真实服务器。

浏览器抓到的是**已加密**请求，你需要逆向出「Burp 里改明文后，如何再加密成同样格式」的步骤。

必须只输出一个 JSON 对象，不要 markdown 代码块，格式:
{
  "summary": "简短中文分析",
  "confidence": "high|medium|low",
  "steps": [
    {"type": "🔒 加密字段", "params": {"field": "password", "algo": "AES", "mode": "ECB", "key": "...", "padding": "PKCS7", "scope": "📋 Body (Form)"}},
    {"type": "🔒 加密响应字段", "params": {"field": "result.data", "algo": "AES", "mode": "ECB", "key": "...", "padding": "PKCS7"}},
    {"type": "📝 签名(Hash)", "params": {"algo": "SHA256", "source": "data", "output": "hex", "target_type": "Header", "target": "sign"}}
  ]
}

规则:
1. type 必须从提供的步骤类型列表中选择
2. **加密端请求用 🔒 加密字段**；**需加密响应体时用 🔒 加密响应字段**
3. 需要签名时添加 📝 签名(Hash) / 📝 签名(HMAC带密钥) / 📝 签名(排序拼接)
4. 密钥优先从 Hook 日志提取，不要编造
5. **禁止** key/mode/padding/algo 为 "unknown"
6. Hook 含 `Key (String):` 时必须写入 key
7. 编码转换含 encode_type；scope 用标准 Body/Form/Query 标签
8. 用户追问时输出完整 JSON
9. **禁止**在 🔒 加密字段 / 🔓 解密字段 前后添加 Base64/Hex 编解码：加解密 SDK 已内置 Base64/Hex 处理，密文字段只需一步加解密
10. 🔤 编码转换仅用于明文层，不用于 AES 等密文
11. JS 若带 miniprogram:// 前缀，为微信小程序反编译源码；常见 CryptoJS / encrypt / wx.request，优先从中找密钥与字段
"""


def system_prompt_for_role(role: str) -> str:
    return SYSTEM_PROMPT_ENCRYPT if role == "encrypt" else SYSTEM_PROMPT_DECRYPT

_CRYPTO_KW = re.compile(
    r"encrypt|decrypt|CryptoJS|AES|DES|SM4|password|username|cipher|"
    r"(?<![A-Za-z0-9_])iv(?![A-Za-z0-9_])|padding|ecb|cbc|wx\.request|sessionKey",
    re.I,
)


def _extract_json(text: str) -> dict:
    text = text.strip()
    m = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if m:
        text = m.group(1).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        text = text[start : end + 1]
    return json.loads(text)


def _bad_value(val) -> bool:
    return str(val or "").strip().lower() in ("unknown", "?", "null", "none", "n/a", "")


def _clean_steps(result: dict, role: str = "decrypt") -> dict:
    valid_types = set(BUILTIN_STEP_TYPES) | set(get_extension_choices())
    steps = result.get("steps") or []
    cleaned = []
    for s in steps:
        stype = s.get("type")
        if stype not in valid_types or not isinstance(s.get("params"), dict):
            continue
        params = dict(s["params"])
        if role == "encrypt":
            if stype == "🔓 解密字段":
                if _bad_value(params.get("key")):
                    continue
                stype = "🔒 加密字段"
            elif stype == "🔒 加密字段" and _bad_value(params.get("key")):
                continue
            elif stype == "🔓 解密响应字段":
                if _bad_value(params.get("key")):
                    continue
                stype = "🔒 加密响应字段"
            elif stype == "🔒 加密响应字段" and _bad_value(params.get("key")):
                continue
        else:
            if stype == "🔒 加密字段":
                if _bad_value(params.get("key")):
                    continue
                stype = "🔓 解密字段"
            elif stype == "🔓 解密字段" and _bad_value(params.get("key")):
                continue
            elif stype == "🔒 加密响应字段":
                if _bad_value(params.get("key")):
                    continue
                stype = "🔓 解密响应字段"
            elif stype == "🔓 解密响应字段" and _bad_value(params.get("key")):
                continue
        if stype in ("🔓 解密字段", "🔒 加密字段", "🔓 解密响应字段", "🔒 加密响应字段"):
            for k in ("mode", "padding", "algo"):
                if _bad_value(params.get(k)):
                    params.pop(k, None)
        cleaned.append(normalize_step_params({"type": stype, "params": params}))
    before = len(cleaned)
    cleaned = optimize_pipeline_steps(cleaned)
    if len(cleaned) < before:
        note = "（已自动合并多余的 Base64/Hex 编解码步骤）"
        result["summary"] = f"{result.get('summary', '')}{note}".strip()
    result["steps"] = cleaned
    if not cleaned and result.get("confidence") != "low":
        result["confidence"] = "low"
    return result


def _select_scripts_text(
    scripts: dict[str, str],
    max_files: int = 10,
    max_chars: int = 24000,
    *,
    user_selected: bool = False,
) -> str:
    if not scripts:
        return "(无页面 JS)"
    # 用户勾选：尽量全量送入，按文件均分额度
    if user_selected:
        urls = list(scripts.items())
        per = max(2500, max_chars // max(len(urls), 1))
        parts: list[str] = []
        total = 0
        for url, content in urls[: max(max_files, 30)]:
            chunk = content[:per]
            if total + len(chunk) > max_chars:
                chunk = chunk[: max(0, max_chars - total)]
            if not chunk:
                break
            parts.append(f"\n--- JS(已选): {url} ---\n{chunk}")
            total += len(chunk)
            if total >= max_chars:
                break
        return "\n".join(parts) if parts else "(无相关 JS)"

    ranked: list[tuple[int, str, str]] = []
    for url, content in scripts.items():
        score = 0
        low_url = url.lower()
        # 小程序反编译源码优先
        if low_url.startswith("miniprogram://"):
            score += 20
        for kw in ("encrypt", "decrypt", "crypto", "request", "login", "auth",
                   "sign", "util", "api", "aes", "http"):
            if kw in low_url:
                score += 5
        # 降权噪声
        if "weui" in low_url or "app-wxss" in low_url or "/icon/" in low_url:
            score -= 50
        hits = _CRYPTO_KW.findall(content[:12000])
        score += min(len(hits), 40)
        ranked.append((score, url, content))
    ranked = [x for x in ranked if x[0] > 0] or [
        (1, u, c) for u, c in list(scripts.items())[:5]
    ]
    ranked.sort(key=lambda x: x[0], reverse=True)
    parts = []
    total = 0
    for score, url, content in ranked[:max_files]:
        chunk = content[:4000]
        if total + len(chunk) > max_chars:
            chunk = chunk[: max(0, max_chars - total)]
        if not chunk:
            break
        parts.append(f"\n--- JS: {url} (相关度={score}) ---\n{chunk}")
        total += len(chunk)
        if total >= max_chars:
            break
    return "\n".join(parts) if parts else "(无相关 JS)"


def _format_headers(hdrs: dict | None, max_items: int = 25) -> str:
    if not hdrs or not isinstance(hdrs, dict):
        return "(无)"
    lines = [f"  {k}: {v}" for k, v in list(hdrs.items())[:max_items]]
    return "\n".join(lines) if lines else "(无)"


def build_analysis_prompt(
    flows: list[dict],
    hook_lines: list[str],
    role: str = "decrypt",
    scripts: dict[str, str] | None = None,
    focus_hook: bool = False,
    focus_miniprogram: bool = False,
    *,
    user_selected_flows: bool = False,
    user_selected_scripts: bool = False,
) -> str:
    ext = get_extension_choices()
    types = BUILTIN_STEP_TYPES + ext
    types_text = "\n".join(f"- {t}" for t in types)

    # 调用方已筛选时尽量全送；自动模式仍做上限保护
    flow_cap = 30 if user_selected_flows else 12
    n_flow = min(len(flows), flow_cap)
    if n_flow <= 3:
        body_lim = 6000
    elif n_flow <= 8:
        body_lim = 3500
    else:
        body_lim = 2000

    flows_text = ""
    for i, f in enumerate(flows[:flow_cap]):
        flows_text += f"\n--- Flow #{i+1} ---\n"
        flows_text += f"{f.get('method')} {f.get('url')}\n"
        flows_text += f"Request Headers:\n{_format_headers(f.get('request_headers'))}\n"
        flows_text += f"Request Body: {f.get('request_body', '')[:body_lim]}\n"
        flows_text += f"Response Headers:\n{_format_headers(f.get('response_headers'))}\n"
        flows_text += f"Response Body ({f.get('status')}): {f.get('response_body', '')[:body_lim]}\n"
    if len(flows) > flow_cap:
        flows_text += f"\n(另有 {len(flows) - flow_cap} 条流量未送入，请缩小勾选)\n"

    sel_note = ""
    if user_selected_flows or user_selected_scripts:
        parts = []
        if user_selected_flows:
            parts.append(f"流量 {n_flow} 条（用户勾选）")
        if user_selected_scripts:
            parts.append(f"JS {len(scripts or {})} 个（用户勾选）")
        sel_note = f"\n**素材范围**: {', '.join(parts)}。请主要依据这些材料分析，勿臆造未出现的字段。\n"

    hooks_text = "\n".join(hook_lines[-120:]) if hook_lines else "(无 Hook 日志)"
    script_budget = 48000 if user_selected_scripts else 24000
    script_files = max(len(scripts or {}), 10) if user_selected_scripts else 10
    scripts_text = _select_scripts_text(
        scripts or {},
        max_files=script_files,
        max_chars=script_budget,
        user_selected=user_selected_scripts,
    )

    focus_note = ""
    if focus_miniprogram:
        if flows:
            focus_note = (
                "\n**本次重点（微信小程序：流量 + 反编译 JS）**:\n"
                "- 结合下方 HTTP 流量（密文字段形态）与 miniprogram:// 反编译源码，"
                "还原加解密/签名步骤。\n"
                "- 优先对照 wx.request / 封装请求里的 data、header 字段与流量中的 body。\n"
                "- 从 JS 找 AES/DES/SM4/RSA、CryptoJS、MD5/SHA、sign、密钥常量或派生；"
                "流量用于确认字段名与密文编码（Base64/Hex）。\n"
                "- 忽略 weui / 组件库噪声文件。\n"
            )
        else:
            focus_note = (
                "\n**本次重点（微信小程序静态分析）**:\n"
                "- 主要依据下方 miniprogram:// 反编译 JS，推断请求体/Header 的加解密与签名步骤。\n"
                "- Hook / HTTP 流量可能为空，**不要**因此输出空 steps；应从 JS 中找 AES/DES/SM4/RSA、CryptoJS、"
                "MD5/SHA、sign、wx.request 封装、密钥常量或派生逻辑。\n"
                "- 若只找到算法与字段名但密钥不在源码中，仍输出可编辑的步骤骨架，key 用明显占位如 "
                "`请填写密钥`，confidence=medium/low，并在 summary 说明。\n"
                "- 忽略 weui / 组件库噪声文件。\n"
            )
    elif focus_hook:
        focus_note = (
            "\n**本次重点**: 优先从 Hook 日志提取密钥/算法；其次分析页面 JS 源码；"
            "HTTP 流量仅作字段名参考。Hook 有 Key 时必须写入 steps。\n"
        )

    role_note = ""
    if role == "encrypt":
        role_note = (
            "\n**加密端任务**: 生成 Burp→服务器 的加密/签名步骤。"
            "浏览器流量是密文，请推断如何把 Burp 明文再加密成同样格式。"
            "步骤用 🔒 加密字段，可含签名 Header 步骤。\n"
        )
    else:
        role_note = (
            "\n**解密端任务**: 生成 浏览器→Burp 的解密步骤。"
            "请求用 🔓 解密字段；若响应 JSON 某字段也是密文，追加 🔓 解密响应字段（field 如 result.data）。\n"
        )

    return f"""目标角色: {role} 端代理
{sel_note}{focus_note}{role_note}
可用步骤类型:
{types_text}

Hook 日志 (CryptoJS / RSA / HMAC，含 Key/IV/模式):
{hooks_text}

页面/小程序 JS 源码 (浏览器 Network 或 miniprogram:// 反编译):
{scripts_text}

捕获的 HTTP 流量:
{flows_text or '(无)'}

请分析并输出 JSON。"""


def _normalize_base_url(base_url: str) -> str:
    base = (base_url or "https://api.openai.com/v1").rstrip("/")
    if base.endswith("/v1"):
        return base
    # DeepSeek 等常见兼容端点需要 /v1
    if "deepseek.com" in base or "openai.com" in base:
        return base + "/v1"
    return base


def _api_proxies(cfg: dict) -> dict | None:
    if cfg.get("use_http_proxy") and cfg.get("http_proxy"):
        p = cfg["http_proxy"].strip()
        if not p.startswith("http"):
            p = f"http://{p}"
        return {"http": p, "https": p}
    return None


def _build_request(
    cfg: dict,
    messages: list[dict],
    *,
    stream: bool = True,
) -> tuple[str, dict, dict | None, dict]:
    api_key = (cfg.get("api_key") or "").strip()
    if not api_key:
        raise ValueError("请先在 AI 实验室配置 API Key")

    base_url = _normalize_base_url(cfg.get("base_url") or "https://api.openai.com/v1")
    model = cfg.get("model") or "deepseek-chat"
    url = f"{base_url}/chat/completions"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    body = {
        "model": model,
        "messages": messages,
        "temperature": 0.2,
        "stream": stream,
    }
    return url, headers, _api_proxies(cfg), body


def test_ai_config(cfg: dict) -> tuple[bool, str]:
    """发送最小 chat 请求，验证 API Key / Base URL / 模型 / 代理."""
    api_key = (cfg.get("api_key") or "").strip()
    if not api_key:
        return False, "请填写 API Key"

    messages = [{"role": "user", "content": "回复 OK"}]
    try:
        url, headers, proxies, body = _build_request(cfg, messages, stream=False)
        body["max_tokens"] = 8
        model = body.get("model", "")
        resp = requests.post(
            url, headers=headers, json=body, proxies=proxies, timeout=(10, 45),
        )
        resp.raise_for_status()
        data = resp.json()
        reply = (data.get("choices", [{}])[0].get("message", {}).get("content") or "").strip()
        preview = reply[:120] + ("…" if len(reply) > 120 else "")
        return True, f"连接成功\n\n端点: {url}\n模型: {model}\n回复: {preview or '(空)'}"
    except requests.HTTPError as e:
        detail = ""
        if e.response is not None:
            try:
                detail = e.response.json().get("error", {}).get("message", "")
            except Exception:
                detail = (e.response.text or "")[:200]
        msg = str(e)
        if detail:
            msg = f"{msg}\n{detail}"
        return False, f"HTTP 错误: {msg}"
    except requests.RequestException as e:
        return False, f"网络错误: {e}"
    except Exception as e:
        return False, str(e)


def build_initial_messages(
    flows: list[dict],
    hook_lines: list[str],
    role: str = "decrypt",
    scripts: dict[str, str] | None = None,
    focus_hook: bool = False,
    focus_miniprogram: bool = False,
    *,
    user_selected_flows: bool = False,
    user_selected_scripts: bool = False,
) -> list[dict]:
    return [
        {"role": "system", "content": system_prompt_for_role(role)},
        {
            "role": "user",
            "content": build_analysis_prompt(
                flows, hook_lines, role, scripts=scripts,
                focus_hook=focus_hook, focus_miniprogram=focus_miniprogram,
                user_selected_flows=user_selected_flows,
                user_selected_scripts=user_selected_scripts,
            ),
        },
    ]


def analyze_crypto(
    flows: list[dict],
    hook_lines: list[str],
    cfg: dict,
    role: str = "decrypt",
) -> dict:
    """同步分析（兼容旧调用）."""
    result = {"text": ""}

    def _collect(chunk: str):
        result["text"] += chunk

    _stream_analyze(flows, hook_lines, cfg, role, on_chunk=_collect)
    parsed = _extract_json(result["text"])
    return _clean_steps(parsed, role)


def _stream_analyze(
    flows: list[dict],
    hook_lines: list[str],
    cfg: dict,
    role: str,
    on_log=None,
    on_chunk=None,
    scripts: dict[str, str] | None = None,
    focus_hook: bool = False,
    focus_miniprogram: bool = False,
    *,
    user_selected_flows: bool = False,
    user_selected_scripts: bool = False,
) -> str:
    def log(msg: str):
        if on_log:
            on_log(msg)

    sel = []
    if user_selected_flows:
        sel.append(f"勾选流量 {len(flows)}")
    if user_selected_scripts:
        sel.append(f"勾选 JS {len(scripts or {})}")
    scope = f"（{' · '.join(sel)}）" if sel else "（自动挑选）"
    log(
        f"数据: {len(flows)} 条流量, {len(hook_lines)} 条 Hook, "
        f"{len(scripts or {})} 个 JS 文件 {scope}"
    )
    log("正在组装 Prompt…")
    messages = build_initial_messages(
        flows, hook_lines, role, scripts=scripts,
        focus_hook=focus_hook, focus_miniprogram=focus_miniprogram,
        user_selected_flows=user_selected_flows,
        user_selected_scripts=user_selected_scripts,
    )

    url, headers, proxies, body = _build_request(cfg, messages)
    model = body["model"]
    log(f"连接 API: {url}")
    log(f"模型: {model}（流式输出，请稍候）…")

    try:
        return _read_stream(url, headers, body, proxies, on_log=on_log, on_chunk=on_chunk)
    except requests.RequestException as e:
        log(f"流式请求失败 ({e})，尝试非流式…")
        return _blocking_analyze(messages, cfg, on_log=on_log, on_chunk=on_chunk)


def _stream_chat(
    messages: list[dict],
    cfg: dict,
    on_log=None,
    on_chunk=None,
) -> str:
    def log(msg: str):
        if on_log:
            on_log(msg)

    url, headers, proxies, body = _build_request(cfg, messages)
    model = body["model"]
    log(f"继续对话 — 模型: {model}（{len(messages)} 条消息）…")
    try:
        return _read_stream(url, headers, body, proxies, on_log=on_log, on_chunk=on_chunk)
    except requests.RequestException as e:
        log(f"流式请求失败 ({e})，尝试非流式…")
        return _blocking_analyze(messages, cfg, on_log=on_log, on_chunk=on_chunk)


def _read_stream(
    url: str,
    headers: dict,
    body: dict,
    proxies: dict | None,
    on_log=None,
    on_chunk=None,
) -> str:
    def log(msg: str):
        if on_log:
            on_log(msg)

    full = ""
    got_first = False
    with requests.post(
        url,
        headers=headers,
        json=body,
        proxies=proxies,
        timeout=(15, 180),
        stream=True,
    ) as resp:
        resp.raise_for_status()
        for raw in resp.iter_lines(decode_unicode=True):
            if not raw or not raw.startswith("data: "):
                continue
            data = raw[6:].strip()
            if data == "[DONE]":
                break
            try:
                obj = json.loads(data)
                delta = obj.get("choices", [{}])[0].get("delta", {})
                piece = delta.get("content") or ""
                if piece:
                    if not got_first:
                        got_first = True
                        log("已收到首包，流式输出中…")
                    full += piece
                    if on_chunk:
                        on_chunk(piece)
            except json.JSONDecodeError:
                continue

    if not full:
        raise ValueError("流式响应无内容")
    log(f"接收完成，共 {len(full)} 字符，正在解析 JSON…")
    return full


def _blocking_analyze(
    messages: list[dict],
    cfg: dict,
    on_log=None,
    on_chunk=None,
) -> str:
    def log(msg: str):
        if on_log:
            on_log(msg)

    url, headers, proxies, body = _build_request(cfg, messages, stream=False)
    log(f"非流式请求: {url}")
    resp = requests.post(
        url, headers=headers, json=body, proxies=proxies, timeout=(15, 180)
    )
    resp.raise_for_status()
    data = resp.json()
    full = data.get("choices", [{}])[0].get("message", {}).get("content") or ""
    if on_chunk and full:
        on_chunk(full)
    return full


class AIAnalysisWorker(QThread):
    """后台线程调用 AI，流式输出不阻塞 GUI."""

    log = pyqtSignal(str)
    chunk = pyqtSignal(str)
    finished_ok = pyqtSignal(dict, str)
    failed = pyqtSignal(str)

    def __init__(
        self,
        flows: list[dict] | None = None,
        hook_lines: list[str] | None = None,
        cfg: dict | None = None,
        role: str = "decrypt",
        messages: list[dict] | None = None,
        scripts: dict[str, str] | None = None,
        focus_hook: bool = False,
        focus_miniprogram: bool = False,
        *,
        user_selected_flows: bool = False,
        user_selected_scripts: bool = False,
        parent=None,
    ):
        super().__init__(parent)
        self.flows = flows or []
        self.hook_lines = hook_lines or []
        self.cfg = cfg or {}
        self.role = role
        self.messages = messages
        self.scripts = scripts or {}
        self.focus_hook = focus_hook
        self.focus_miniprogram = focus_miniprogram
        self.user_selected_flows = user_selected_flows
        self.user_selected_scripts = user_selected_scripts

    def run(self):
        try:
            if self.messages:
                full = _stream_chat(
                    self.messages,
                    self.cfg,
                    on_log=lambda m: self.log.emit(m),
                    on_chunk=lambda c: self.chunk.emit(c),
                )
            else:
                full = _stream_analyze(
                    self.flows,
                    self.hook_lines,
                    self.cfg,
                    self.role,
                    on_log=lambda m: self.log.emit(m),
                    on_chunk=lambda c: self.chunk.emit(c),
                    scripts=self.scripts,
                    focus_hook=self.focus_hook,
                    focus_miniprogram=self.focus_miniprogram,
                    user_selected_flows=self.user_selected_flows,
                    user_selected_scripts=self.user_selected_scripts,
                )
            result = _clean_steps(_extract_json(full), self.role)
            self.log.emit(
                f"分析完成 — confidence: {result.get('confidence', '?')}，"
                f"步骤: {len(result.get('steps', []))}"
            )
            self.finished_ok.emit(result, full)
        except Exception as e:
            self.failed.emit(str(e))
