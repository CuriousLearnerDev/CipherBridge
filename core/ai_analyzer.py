"""AI 分析 — 结合 Hook 日志与 HTTP 流量，生成密桥 CipherBridge 步骤 JSON."""

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

# 哈希 / HMAC / 排序签名 — 不可从结果还原明文
_IRREVERSIBLE_STEP_TYPES = {
    "📝 签名(Hash)",
    "📝 生成签名",
    "📝 签名(HMAC带密钥)",
    "📝 签名(排序拼接)",
}
_REVERSIBLE_CRYPTO_TYPES = {
    "🔓 解密字段",
    "🔓 解密响应字段",
    "🔒 加密字段",
    "🔒 加密响应字段",
    "🔐 AuthToken生成",
}
_HASH_ALGO_MARKERS = (
    "MD5", "SHA1", "SHA256", "SHA512", "SHA3", "SM3", "HMAC", "HASH",
)


def classify_steps_reversibility(steps: list | None) -> dict:
    """区分可逆加解密 vs 哈希/签名等不可逆步骤。"""
    irreversible: list[str] = []
    reversible: list[str] = []
    other: list[str] = []
    for step in steps or []:
        if not isinstance(step, dict):
            continue
        stype = str(step.get("type") or "").strip()
        params = step.get("params") if isinstance(step.get("params"), dict) else {}
        algo = str(params.get("algo") or params.get("algorithm") or "").upper()
        label = stype
        if algo:
            label = f"{stype} ({algo})"

        if stype in _IRREVERSIBLE_STEP_TYPES or "签名" in stype:
            irreversible.append(label)
            continue
        if stype in _REVERSIBLE_CRYPTO_TYPES:
            # 误把哈希写进「解密/加密字段」
            if any(m in algo for m in _HASH_ALGO_MARKERS) and not any(
                x in algo for x in ("AES", "DES", "SM4", "RSA", "XOR", "RC4")
            ):
                irreversible.append(label + " · 哈希不可逆")
            else:
                reversible.append(label)
            continue
        other.append(label)

    return {
        "irreversible": irreversible,
        "reversible": reversible,
        "other": other,
        "hash_only": bool(irreversible) and not reversible,
        "has_irreversible": bool(irreversible),
        "has_reversible": bool(reversible),
    }


def format_irreversible_decrypt_warning(info: dict) -> str | None:
    """生成解密场景下的不可逆提示文案；无需提示时返回 None。"""
    if not info.get("has_irreversible"):
        return None
    names = "、".join(info["irreversible"][:6])
    if len(info["irreversible"]) > 6:
        names += "…"
    if info.get("hash_only"):
        return (
            "当前识别到的主要是哈希 / 签名类步骤（不可逆），例如：\n"
            f"  {names}\n\n"
            "MD5、SHA、HMAC 等无法「解密」还原。\n\n"
            "推荐：写油猴 Hook「绕过加密」，让选定字段以明文发给 Burp；"
            "你在 Burp 改完后，再用「生成加密」在加密端重算哈希/签名出站。\n\n"
            "仍要按当前步骤写入解密项目吗？"
        )
    return (
        "步骤中包含哈希 / 签名（不可逆），例如：\n"
        f"  {names}\n\n"
        "也可 Hook 绕过，让字段明文进 Burp，再「生成加密」重算出站。\n\n"
        "仍要写入当前选中的步骤吗？"
    )


SYSTEM_PROMPT_DECRYPT = """你是 JavaScript 逆向与 HTTP 加解密分析专家。
根据 Hook 日志、HTTP 请求/响应，推断**解密端**代理流程：浏览器密文 → 解密 → 转发 Burp 明文。

必须只输出一个 JSON 对象，不要 markdown 代码块，格式:
{
  "summary": "简短中文分析",
  "confidence": "high|medium|low",
  "crypto_pattern": "fixed_symmetric|hybrid_session_key|asymmetric_only|sign_only",
  "code_locations": [
    {"url": "https://example.com/app.js", "approx_line": 1284, "offset": 45678, "what": "CryptoJS.AES.encrypt", "snippet": "CryptoJS.AES.encrypt(...)"}
  ],
  "steps": [
    {"type": "🔓 解密字段", "params": {"field": "data", "algo": "AES", "mode": "ECB", "key": "...", "padding": "PKCS7", "scope": "📋 Body (JSON)"}},
    {"type": "🔓 解密响应字段", "params": {"field": "result.data", "algo": "AES", "mode": "ECB", "key": "...", "padding": "PKCS7"}}
  ]
}

规则:
1. type 必须从提供的步骤类型列表中选择
2. params 字段名与密桥 CipherBridge 可视化构建器一致
3. 先判定模式：fixed_symmetric / hybrid_session_key / asymmetric_only / sign_only（写入 crypto_pattern）
4. 密钥：固定密钥才从 Hook 写入 params.key；随机会话密钥禁止把单次 Hook Key 固化为长期解密 key
5. hybrid：应先非对称解密钥字段，再对称解数据字段；无私钥则 confidence=low 并在 summary 说明
6. 不确定时 confidence 设为 low，并在 summary 说明需人工确认
7. **解密端请求用 🔓 解密字段**；**响应体加密时用 🔓 解密响应字段**（field 支持嵌套路径如 result.data）
8. 用户追问时输出**完整更新后**的 JSON
9. **禁止** key/mode/padding/algo 为 "unknown"；未确认则不要生成该步骤
10. Hook 含 `Key (String):` 且为固定密钥模式时必须写入 steps 的 key
11. 编码转换含 encode_type: Base64编码/Base64解码/Hex编码/Hex解码/URL编码/URL解码
12. scope: 📋 Body (JSON) / 📋 Body (Form) / 🔗 URL Query（仅用于请求步骤）
13. 流量含 Request/Response Headers，签名/Token 常在 Header 中，可用 🏷 设置Header 或 📝 签名(Hash) 写入 Header
14. **禁止**在 🔓 解密字段 / 🔒 加密字段 前后添加 Base64/Hex 编解码：AES/DES/SM4/RSA 等 SDK 已内置 input_fmt/output（默认 Base64），密文字段直接写加解密步骤即可
15. 🔤 编码转换仅用于明文层编码（如 Base64 包 JSON 字符串），不用于 AES 密文
16. JS 若带 miniprogram:// 前缀，为微信小程序反编译源码；常见 CryptoJS / encrypt / wx.request，优先从中找密钥与字段
17. **code_locations** 记录加解密相关源码位置（url / approx_line / what / snippet），仅供人工找代码；与 steps 无关，不参与 plugin 生成；有 JS 依据时尽量填写
"""

SYSTEM_PROMPT_ENCRYPT = """你是 JavaScript 逆向与 HTTP 加解密分析专家。
根据 Hook 日志、HTTP 请求/响应，推断**加密端**代理流程：Burp 明文 → 加密/签名 → 转发真实服务器。

浏览器抓到的是**已加密**请求，你需要逆向出「Burp 里改明文后，如何再加密成同样格式」的步骤。

必须只输出一个 JSON 对象，不要 markdown 代码块，格式:
{
  "summary": "简短中文分析",
  "confidence": "high|medium|low",
  "crypto_pattern": "fixed_symmetric|hybrid_session_key|asymmetric_only|sign_only",
  "code_locations": [
    {"url": "https://example.com/app.js", "approx_line": 200, "offset": 8000, "what": "encrypt / sign", "snippet": "..."}
  ],
  "steps": [
    {"type": "🔒 加密字段", "params": {"field": "password", "algo": "AES", "mode": "ECB", "key": "...", "padding": "PKCS7", "scope": "📋 Body (Form)"}},
    {"type": "🔒 加密响应字段", "params": {"field": "result.data", "algo": "AES", "mode": "ECB", "key": "...", "padding": "PKCS7"}},
    {"type": "📝 签名(Hash)", "params": {"algo": "SHA256", "source": "data", "output": "hex", "target_type": "Header", "target": "sign"}}
  ]
}

规则:
1. type 必须从提供的步骤类型列表中选择
2. **加密端请求用 🔒 加密字段**；**需加密响应体时用 🔒 加密响应字段**
3. 先判定 crypto_pattern；hybrid_session_key 时：公钥可固定，AES Key/IV 每请求随机，禁止固化 Hook 单次 Key
4. 需要签名时添加 📝 签名(Hash) / 📝 签名(HMAC带密钥) / 📝 签名(排序拼接)
5. 固定密钥优先从 Hook 提取；不要编造；动态会话密钥不要抄采样 Hook Key
6. **禁止** key/mode/padding/algo 为 "unknown"
7. Hook 含 `Key (String):` 且为固定密钥模式时必须写入 key
8. 编码转换含 encode_type；scope 用标准 Body/Form/Query 标签
9. 用户追问时输出完整 JSON
10. **禁止**在 🔒 加密字段 / 🔓 解密字段 前后添加 Base64/Hex 编解码：加解密 SDK 已内置 Base64/Hex 处理，密文字段只需一步加解密
11. 🔤 编码转换仅用于明文层，不用于 AES 等密文
12. JS 若带 miniprogram:// 前缀，为微信小程序反编译源码；常见 CryptoJS / encrypt / wx.request，优先从中找密钥与字段
13. **code_locations** 记录加解密相关源码位置，仅供人工找代码；与 steps/plugin 无关
"""


def system_prompt_for_role(role: str) -> str:
    return SYSTEM_PROMPT_ENCRYPT if role == "encrypt" else SYSTEM_PROMPT_DECRYPT

_CRYPTO_KW = re.compile(
    r"encrypt|decrypt|CryptoJS|AES|DES|SM4|password|username|cipher|"
    r"(?<![A-Za-z0-9_])iv(?![A-Za-z0-9_])|padding|ecb|cbc|wx\.request|sessionKey",
    re.I,
)


def _extract_json(text: str) -> dict:
    """从模型回复中提取 JSON；优先含 steps 的对象。"""
    raw = (text or "").strip()
    if not raw:
        raise ValueError("empty response")

    candidates: list[str] = []
    for m in re.finditer(r"```(?:json)?\s*([\s\S]*?)```", raw, flags=re.I):
        candidates.append(m.group(1).strip())

    # 扫描所有 {...} 平衡片段（从每个 { 起做括号匹配）
    def _balanced_objects(s: str) -> list[str]:
        out = []
        i = 0
        while i < len(s):
            if s[i] != "{":
                i += 1
                continue
            depth = 0
            in_str = False
            esc = False
            for j in range(i, len(s)):
                ch = s[j]
                if in_str:
                    if esc:
                        esc = False
                    elif ch == "\\":
                        esc = True
                    elif ch == '"':
                        in_str = False
                    continue
                if ch == '"':
                    in_str = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        out.append(s[i : j + 1])
                        i = j + 1
                        break
            else:
                break
            continue
        return out

    candidates.extend(_balanced_objects(raw))
    # 兼容旧逻辑：首尾大括号
    start, end = raw.find("{"), raw.rfind("}")
    if start >= 0 and end > start:
        candidates.append(raw[start : end + 1])

    parsed_list: list[dict] = []
    for cand in candidates:
        cleaned = re.sub(r",\s*([}\]])", r"\1", cand.strip())
        for blob in (cleaned, cand.strip()):
            try:
                obj = json.loads(blob)
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(obj, dict):
                parsed_list.append(obj)
                break

    if not parsed_list:
        raise ValueError("no json object found")

    # 优先带非空 steps 的
    for obj in parsed_list:
        steps = obj.get("steps")
        if isinstance(steps, list) and steps:
            return obj
    for obj in parsed_list:
        if "steps" in obj or "summary" in obj or "confidence" in obj:
            return obj
    return parsed_list[0]


def _bad_value(val) -> bool:
    return str(val or "").strip().lower() in ("unknown", "?", "null", "none", "n/a", "")


_STEP_TYPE_ALIASES = {
    "decrypt": "🔓 解密字段",
    "decrypt_field": "🔓 解密字段",
    "解密": "🔓 解密字段",
    "解密字段": "🔓 解密字段",
    "aes_decrypt": "🔓 解密字段",
    "encrypt": "🔒 加密字段",
    "encrypt_field": "🔒 加密字段",
    "加密": "🔒 加密字段",
    "加密字段": "🔒 加密字段",
    "decrypt_response": "🔓 解密响应字段",
    "解密响应": "🔓 解密响应字段",
    "解密响应字段": "🔓 解密响应字段",
    "encrypt_response": "🔒 加密响应字段",
    "加密响应": "🔒 加密响应字段",
    "加密响应字段": "🔒 加密响应字段",
    "hash": "📝 签名(Hash)",
    "md5": "📝 签名(Hash)",
    "hmac": "📝 签名(HMAC带密钥)",
    "encode": "🔤 编码转换",
    "encoding": "🔤 编码转换",
    "编码转换": "🔤 编码转换",
}


def _normalize_step_type(stype) -> str:
    if not stype:
        return ""
    s = str(stype).strip()
    if s in BUILTIN_STEP_TYPES:
        return s
    # 去掉可能的全角空格
    s2 = s.replace("\u3000", " ")
    if s2 in BUILTIN_STEP_TYPES:
        return s2
    key = s2.casefold().replace(" ", "").replace("_", "")
    for alias, canon in _STEP_TYPE_ALIASES.items():
        if alias.replace(" ", "").casefold() == key or alias == s2:
            return canon
    # 模糊：包含关键词
    low = s2.casefold()
    if "解密响应" in s2:
        return "🔓 解密响应字段"
    if "加密响应" in s2:
        return "🔒 加密响应字段"
    if "解密" in s2:
        return "🔓 解密字段"
    if "加密" in s2 and "响应" not in s2:
        return "🔒 加密字段"
    if "hmac" in low:
        return "📝 签名(HMAC带密钥)"
    if "hash" in low or "md5" in low or "sha" in low:
        return "📝 签名(Hash)"
    return s


def _sanitize_key(val) -> str:
    """从 Hook 风格字符串里抠出密钥。"""
    s = str(val or "").strip()
    if not s:
        return ""
    m = re.search(
        r"(?:Key\s*\((?:String|WordArray|Hex)\)|Key)\s*[:：]\s*([^\s,;]+)",
        s,
        flags=re.I,
    )
    if m:
        return m.group(1).strip().strip("'\"")
    return s


def _normalize_code_locations(result: dict) -> dict:
    """规范化 code_locations；与 steps 无关，不参与 plugin 生成。"""
    raw = result.get("code_locations")
    if raw is None:
        # 兼容个别模型写成 locations / source_locations
        raw = result.get("locations") or result.get("source_locations")
    if not isinstance(raw, list):
        result.pop("code_locations", None)
        return result
    cleaned: list[dict] = []
    for item in raw[:20]:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or item.get("script") or item.get("file") or "").strip()
        if not url:
            continue
        entry: dict = {"url": url}
        what = str(item.get("what") or item.get("note") or item.get("desc") or "").strip()
        if what:
            entry["what"] = what[:200]
        snippet = str(item.get("snippet") or item.get("context") or "").strip()
        if snippet:
            entry["snippet"] = snippet[:400]
        for key, out in (("approx_line", "approx_line"), ("line", "approx_line"), ("lineno", "approx_line")):
            if key in item and item[key] is not None:
                try:
                    line = int(item[key])
                    if line > 0:
                        entry["approx_line"] = line
                        break
                except (TypeError, ValueError):
                    pass
        for key in ("offset", "match_offset", "pos"):
            if key in item and item[key] is not None:
                try:
                    entry["offset"] = max(0, int(item[key]))
                    break
                except (TypeError, ValueError):
                    pass
        cleaned.append(entry)
    if cleaned:
        result["code_locations"] = cleaned
    else:
        result.pop("code_locations", None)
    result.pop("locations", None)
    result.pop("source_locations", None)
    return result


def _clean_steps(result: dict, role: str = "decrypt") -> dict:
    _normalize_code_locations(result)
    valid_types = set(BUILTIN_STEP_TYPES) | set(get_extension_choices())
    steps = result.get("steps") or []
    cleaned = []
    dropped: list[str] = []
    for s in steps:
        if not isinstance(s, dict):
            dropped.append("非对象步骤已跳过")
            continue
        stype = _normalize_step_type(s.get("type"))
        if stype not in valid_types:
            dropped.append(f"未知类型: {s.get('type') or '(空)'}")
            continue
        params_raw = s.get("params")
        if params_raw is None:
            params_raw = {}
        if not isinstance(params_raw, dict):
            dropped.append(f"{stype}: params 无效")
            continue
        params = dict(params_raw)
        if "key" in params:
            params["key"] = _sanitize_key(params.get("key"))
        if role == "encrypt":
            if stype == "🔓 解密字段":
                if _bad_value(params.get("key")):
                    dropped.append(f"{stype}: key 无效/unknown")
                    continue
                stype = "🔒 加密字段"
            elif stype == "🔒 加密字段" and _bad_value(params.get("key")):
                dropped.append(f"{stype}: key 无效/unknown")
                continue
            elif stype == "🔓 解密响应字段":
                if _bad_value(params.get("key")):
                    dropped.append(f"{stype}: key 无效/unknown")
                    continue
                stype = "🔒 加密响应字段"
            elif stype == "🔒 加密响应字段" and _bad_value(params.get("key")):
                dropped.append(f"{stype}: key 无效/unknown")
                continue
        else:
            if stype == "🔒 加密字段":
                if _bad_value(params.get("key")):
                    dropped.append(f"{stype}: key 无效/unknown")
                    continue
                stype = "🔓 解密字段"
            elif stype == "🔓 解密字段" and _bad_value(params.get("key")):
                dropped.append(f"{stype}: key 无效/unknown")
                continue
            elif stype == "🔒 加密响应字段":
                if _bad_value(params.get("key")):
                    dropped.append(f"{stype}: key 无效/unknown")
                    continue
                stype = "🔓 解密响应字段"
            elif stype == "🔓 解密响应字段" and _bad_value(params.get("key")):
                dropped.append(f"{stype}: key 无效/unknown")
                continue
        if stype in ("🔓 解密字段", "🔒 加密字段", "🔓 解密响应字段", "🔒 加密响应字段"):
            for k in ("mode", "padding", "algo"):
                if _bad_value(params.get(k)):
                    params.pop(k, None)
            # 缺 field 时尽量给默认，避免整步丢掉
            if _bad_value(params.get("field")):
                params["field"] = "data"
        cleaned.append(normalize_step_params({"type": stype, "params": params}))
    before = len(cleaned)
    cleaned = optimize_pipeline_steps(cleaned)
    if len(cleaned) < before:
        note = "（已自动合并多余的 Base64/Hex 编解码步骤）"
        result["summary"] = f"{result.get('summary', '')}{note}".strip()
    result["steps"] = cleaned
    if dropped:
        result["_dropped"] = dropped
    if not cleaned and result.get("confidence") != "low":
        result["confidence"] = "low"
    return result


def format_code_locations_text(locations: list | None) -> str:
    """人类可读的源码位置列表（不参与 codegen）。"""
    if not locations:
        return "（本次未识别到源码位置；可再追问 Agent 补充 code_locations）"
    lines: list[str] = [
        "加解密相关源码位置（仅供人工查找，与生成的 plugin 步骤无关）",
        "",
    ]
    for i, loc in enumerate(locations, 1):
        if not isinstance(loc, dict):
            continue
        url = loc.get("url") or ""
        what = loc.get("what") or ""
        line = loc.get("approx_line")
        offset = loc.get("offset")
        snippet = (loc.get("snippet") or "").replace("\n", " ").strip()
        head = f"{i}. {what}" if what else f"{i}."
        lines.append(head.strip() or f"{i}.")
        lines.append(f"   URL: {url}")
        meta_parts = []
        if line is not None:
            meta_parts.append(f"约第 {line} 行")
        if offset is not None:
            meta_parts.append(f"offset={offset}")
        if meta_parts:
            lines.append(f"   {' · '.join(meta_parts)}")
        if snippet:
            if len(snippet) > 180:
                snippet = snippet[:180] + "…"
            lines.append(f"   片段: {snippet}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"

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
            "\n**本次重点**: 优先从 Hook 日志提取算法/模式/公钥；其次分析页面 JS；"
            "HTTP 流量确认字段名。先判 fixed_symmetric vs hybrid_session_key："
            "Hook 同时有对称 Key 与 RSA/公钥、或流量多字段(数据+key+iv 密文)→混合；"
            "仅固定对称才把 Hook Key 写入 steps；混合禁止固化单次会话 Key。\n"
        )

    role_note = ""
    if role == "encrypt":
        role_note = (
            "\n**加密端任务**: 生成 Burp→服务器 的加密/签名步骤。"
            "浏览器流量是密文，请推断如何把 Burp 明文再加密成同样格式。"
            "步骤用 🔒 加密字段，可含签名 Header。"
            "hybrid_session_key：公钥固定 + 每请求随机对称 Key/IV + 非对称封装，"
            "勿把 Hook 采样 Key 写死。\n"
        )
    else:
        role_note = (
            "\n**解密端任务**: 生成 浏览器→Burp 的解密步骤。"
            "请求用 🔓 解密字段；若响应 JSON 某字段也是密文，追加 🔓 解密响应字段（field 如 result.data）。"
            "hybrid 无私钥时 confidence=low，勿假装固定 AES 可长期解密。\n"
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
    """OpenAI 兼容网关统一落到 …/v1（New API / One API 等常只填主机）。"""
    base = (base_url or "https://api.openai.com/v1").rstrip("/")
    low = base.lower()
    if low.endswith("/v1") or low.endswith("/v1/") or "/anthropic" in low:
        return base.rstrip("/")
    # 主机根地址 → 自动补 /v1，避免打到前端 HTML
    return base + "/v1"


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
    from core.ai_config import enrich_ai_headers

    headers = enrich_ai_headers(headers, url=url, cfg=cfg)
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
        from core.ai_http import AIHttpError, post_json

        url, headers, proxies, body = _build_request(cfg, messages, stream=False)
        body["max_tokens"] = 8
        model = body.get("model", "")
        data = post_json(
            url, headers=headers, body=body, proxies=proxies, timeout=(10, 45)
        )
        reply = (data.get("choices", [{}])[0].get("message", {}).get("content") or "").strip()
        preview = reply[:120] + ("…" if len(reply) > 120 else "")
        return True, f"连接成功\n\n端点: {url}\n模型: {model}\n回复: {preview or '(空)'}"
    except AIHttpError as e:
        return False, str(e)
    except requests.HTTPError as e:
        from core.ai_http import cloudflare_hint, looks_like_cloudflare

        detail = ""
        if e.response is not None:
            try:
                detail = e.response.json().get("error", {}).get("message", "")
            except Exception:
                detail = (e.response.text or "")[:200]
            if looks_like_cloudflare(e.response.text, e.response.status_code):
                url = getattr(e.response, "url", "") or ""
                return False, cloudflare_hint(str(url))
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


def revise_steps_after_verify_failure(
    *,
    cfg: dict,
    role: str,
    previous_result: dict,
    verify_feedback: str,
    attempt: int,
    max_attempts: int = 5,
    hook_lines: list[str] | None = None,
    sample_flow: dict | None = None,
) -> dict:
    """根据自动验证失败的请求/响应，让 AI 修正 steps（同步一次调用）。"""
    role = "encrypt" if (role or "").lower() == "encrypt" else "decrypt"
    prev = previous_result if isinstance(previous_result, dict) else {}
    hooks = "\n".join((hook_lines or [])[-40:])
    if len(hooks) > 6000:
        hooks = hooks[-6000:]
    flow_snip = ""
    if isinstance(sample_flow, dict):
        try:
            flow_snip = json.dumps(
                {
                    "method": sample_flow.get("method"),
                    "url": sample_flow.get("url"),
                    "request_body": (sample_flow.get("request_body")
                                     or sample_flow.get("body")
                                     or "")[:1200],
                    "response_body": (sample_flow.get("response_body")
                                      or sample_flow.get("response")
                                      or "")[:800],
                },
                ensure_ascii=False,
            )
        except Exception:
            flow_snip = str(sample_flow)[:1200]

    try:
        prev_json = json.dumps(prev, ensure_ascii=False)[:8000]
    except Exception:
        prev_json = str(prev)[:8000]

    sys_p = system_prompt_for_role(role)
    user = (
        f"这是第 {attempt}/{max_attempts} 次自动验证失败后的修正请求。\n"
        "上一次 steps 在采样流量上验证未通过。请根据「验证反馈」中的字段错误与"
        "处理前/后 Body，输出**完整更新后**的 JSON（含 steps），不要 markdown。\n"
        "要求:\n"
        "1. 修正错误的 algo/mode/padding/key/iv/field/scope；\n"
        "2. 若像 hybrid_session_key（数据密文+密钥密文），不要把 Hook 单次 AES Key "
        "固化为长期方案，应体现混合链路或在 summary 说明限制；\n"
        "3. 禁止编造密钥；仍不确定则 confidence=low；\n"
        "4. type 必须带 emoji 完整步骤名。\n\n"
        f"【验证反馈】\n{verify_feedback}\n\n"
        f"【上一版 JSON】\n{prev_json}\n\n"
        f"【Hook 摘录】\n{hooks or '(无)'}\n\n"
        f"【采样流量摘要】\n{flow_snip or '(无)'}\n"
    )
    messages = [
        {"role": "system", "content": sys_p},
        {"role": "user", "content": user},
    ]
    from core.ai_http import post_json

    url, headers, proxies, body = _build_request(cfg, messages, stream=False)
    body["max_tokens"] = int(cfg.get("max_tokens") or 4096)
    data = post_json(url, headers=headers, body=body, proxies=proxies, timeout=(20, 120))
    text = (data.get("choices", [{}])[0].get("message", {}).get("content") or "").strip()
    if not text:
        raise ValueError("AI 修正返回为空")
    parsed = _extract_json(text)
    cleaned = _clean_steps(parsed, role)
    cleaned["_revise_raw"] = text
    return cleaned


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
    except Exception as e:
        from core.ai_http import AIHttpError

        if isinstance(e, AIHttpError) and e.status == 403:
            raise
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
    except Exception as e:
        from core.ai_http import AIHttpError

        if isinstance(e, AIHttpError) and e.status == 403:
            raise
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

    from core.ai_http import AIHttpError, iter_sse_lines

    full = ""
    got_first = False
    try:
        for data in iter_sse_lines(
            url, headers=headers, body=body, proxies=proxies, timeout=(15, 180)
        ):
            try:
                obj = json.loads(data)
            except Exception:
                continue
            delta = (
                (obj.get("choices") or [{}])[0].get("delta") or {}
            ).get("content") or ""
            if not delta:
                continue
            if not got_first:
                got_first = True
                log("已收到首包，流式输出中…")
            full += delta
            if on_chunk:
                on_chunk(delta)
    except AIHttpError:
        raise
    if not full:
        raise requests.RequestException("流式响应为空")
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

    from core.ai_http import post_json

    url, headers, proxies, body = _build_request(cfg, messages, stream=False)
    log(f"非流式请求: {url}")
    data = post_json(
        url, headers=headers, body=body, proxies=proxies, timeout=(15, 180)
    )
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
