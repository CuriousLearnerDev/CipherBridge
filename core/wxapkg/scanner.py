"""反编译结果中筛选疑似加解密相关 JS，供 AI 分析."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

# 长词可子串匹配；短词必须整词，避免 iv/sign 误伤 privacy/design
_WORD_KW = ("iv", "key", "sign", "aes", "des", "rsa", "md5", "hmac", "sm4", "sm3")
_PHRASE_KW = (
    "encrypt", "decrypt", "CryptoJS", "SHA256", "SHA1", "createCipher",
    "createDecipher", "sessionKey", "secretKey", "signature", "base64",
    "wx.request", "Authorization", "token", "密钥", "加密", "解密", "签名",
    "CBC", "ECB", "PKCS", "password", "passwd", "cipher",
)

_WORD_RE = re.compile(
    r"(?<![A-Za-z0-9_])(" + "|".join(re.escape(k) for k in _WORD_KW) + r")(?![A-Za-z0-9_])",
    re.IGNORECASE,
)
_PHRASE_RE = re.compile("|".join(re.escape(k) for k in _PHRASE_KW), re.IGNORECASE)

# 路径噪声：UI 组件库 / 样式包，几乎不含业务加解密
_NOISE_PATH = re.compile(
    r"(weui|miniprogram_npm[/\\][^/\\]+[/\\]icon|app-wxss|/wxss\.|page-frame|"
    r"webview\.app|appservice\.app\.js$)",
    re.IGNORECASE,
)

_PRIORITY_NAME = re.compile(
    r"(encrypt|decrypt|crypto|cipher|sign|request|http|api|login|auth|util)",
    re.IGNORECASE,
)


@dataclass
class ScriptHit:
    path: str
    relpath: str
    score: int
    size: int


def score_text(text: str) -> int:
    if not text:
        return 0
    return len(_PHRASE_RE.findall(text)) + len(_WORD_RE.findall(text))


def _path_bonus(relpath: str, name: str) -> int:
    bonus = 0
    low = relpath.replace("\\", "/").lower()
    if _NOISE_PATH.search(low):
        return -1000
    if name.lower() in ("app-service.js", "appservice.js"):
        bonus += 40
    if _PRIORITY_NAME.search(name) or _PRIORITY_NAME.search(low):
        bonus += 25
    if "/_modules/" in low or low.startswith("_modules/"):
        bonus += 10
    if low.endswith(".json") and "config" in low:
        bonus += 5
    return bonus


def collect_crypto_scripts(
    root: str,
    *,
    max_files: int = 20,
    max_bytes_per_file: int = 80_000,
) -> list[ScriptHit]:
    hits: list[ScriptHit] = []
    root = os.path.abspath(root)
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if not name.lower().endswith((".js", ".wxs")):
                continue
            path = os.path.join(dirpath, name)
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if size <= 0 or size > 2_500_000:
                continue
            rel = os.path.relpath(path, root).replace("\\", "/")
            bonus = _path_bonus(rel, name)
            if bonus <= -500:
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read(max_bytes_per_file)
            except OSError:
                continue
            score = score_text(text) + bonus
            # 业务请求封装即使关键字少也保留
            if score < 5 and bonus < 20:
                continue
            hits.append(ScriptHit(path=path, relpath=rel, score=score, size=size))

    hits.sort(key=lambda h: (-h.score, h.size))
    # 保证至少带上 app-service（若存在）
    if not any(h.relpath.endswith("app-service.js") for h in hits):
        for dirpath, _dirs, files in os.walk(root):
            if "app-service.js" in files:
                path = os.path.join(dirpath, "app-service.js")
                rel = os.path.relpath(path, root).replace("\\", "/")
                hits.insert(0, ScriptHit(path=path, relpath=rel, score=50, size=os.path.getsize(path)))
                break
    return hits[:max_files]


def scripts_as_dict(
    hits: list[ScriptHit],
    max_chars: int = 100_000,
    max_per_file: int = 28_000,
    max_lib_file: int = 2_000,
) -> dict[str, str]:
    """转为 AILab._scripts：业务文件优先、大额度；库文件（crypto-js/NIM）仅留短桩。"""
    _LIB = re.compile(
        r"(crypto-js\.js$|nim_web_|miniprogram_npm|/libs/|/vendor/|node_modules)",
        re.IGNORECASE,
    )

    def is_lib(rel: str) -> bool:
        return bool(_LIB.search(rel.replace("\\", "/")))

    business = [h for h in hits if not is_lib(h.relpath)]
    libs = [h for h in hits if is_lib(h.relpath)]
    ordered = business + libs

    out: dict[str, str] = {}
    budget = max_chars
    for h in ordered:
        if budget <= 200:
            break
        lib = is_lib(h.relpath)
        cap = max_lib_file if lib else max_per_file
        take = min(h.size, cap, budget)
        try:
            with open(h.path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read(take)
        except OSError:
            continue
        if not text.strip():
            continue
        if lib and len(text) >= take:
            text = (
                text
                + "\n\n/* [library stub] 已截断；加密密钥/业务调用请查非 libs 的业务 JS */\n"
            )
        elif not lib and h.size > take:
            text = text + f"\n\n/* …truncated, file_size={h.size}, loaded={take} */\n"
        label = f"miniprogram://{h.relpath}"
        out[label] = text
        budget -= len(text)
    return out
