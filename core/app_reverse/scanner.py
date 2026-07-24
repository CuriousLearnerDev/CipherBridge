"""从 apktool 反编译结果中筛选疑似加解密 smali/java/js."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

_PHRASE_KW = (
    "javax/crypto", "javax.crypto", "SecretKeySpec", "IvParameterSpec",
    "Cipher.getInstance", "MessageDigest", "Mac.getInstance",
    "AES/CBC", "AES/ECB", "AES/GCM", "DESede", "RSA/ECB",
    "encrypt", "decrypt", "doFinal", "CipherOutputStream",
    "PBKDF2", "KeyGenerator", "SecureRandom",
    "Base64.encode", "Base64.decode", "android.util.Base64",
    "HMAC", "SHA-256", "SHA256", "MD5", "SM4", "SM2", "SM3",
    "CryptoJS", "AESUtil", "RSAUtil", "EncryptUtil", "SignUtil",
    "加密", "解密", "签名", "密钥",
)

_PHRASE_RE = re.compile("|".join(re.escape(k) for k in _PHRASE_KW), re.IGNORECASE)

_PRIORITY_NAME = re.compile(
    r"(encrypt|decrypt|crypto|cipher|sign|aes|rsa|des|sm4|security|secret|auth|login|util)",
    re.IGNORECASE,
)

_NOISE_PATH = re.compile(
    r"(androidx[/\\]|com[/\\]google[/\\]|com[/\\]android[/\\]|kotlin[/\\]|"
    r"okhttp3[/\\]|retrofit2[/\\]|io[/\\]reactivex|"
    r"butterknife|glide[/\\]|firebase[/\\])",
    re.IGNORECASE,
)

_SCAN_EXT = (".smali", ".java", ".kt", ".js", ".ts", ".lua", ".txt")


@dataclass
class CodeHit:
    path: str
    relpath: str
    score: int
    size: int


def score_text(text: str) -> int:
    if not text:
        return 0
    return len(_PHRASE_RE.findall(text))


def _path_bonus(relpath: str) -> int:
    low = relpath.replace("\\", "/").lower()
    if _NOISE_PATH.search(low):
        return -2000
    bonus = 0
    name = os.path.basename(low)
    if _PRIORITY_NAME.search(name) or _PRIORITY_NAME.search(low):
        bonus += 40
    if "/smali" in low or low.endswith(".smali"):
        bonus += 5
    if "_dex_strings" in low:
        bonus += 20
    return bonus


def collect_crypto_code(
    root: str,
    *,
    max_files: int = 24,
    max_bytes_per_file: int = 100_000,
) -> list[CodeHit]:
    hits: list[CodeHit] = []
    root = os.path.abspath(root)
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            low_name = name.lower()
            if not low_name.endswith(_SCAN_EXT):
                continue
            if low_name.endswith(".txt") and "_dex_strings" not in dirpath.replace("\\", "/").lower():
                continue
            path = os.path.join(dirpath, name)
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if size <= 0 or size > 2_000_000:
                continue
            rel = os.path.relpath(path, root)
            bonus = _path_bonus(rel)
            if bonus <= -1000:
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read(max_bytes_per_file)
            except OSError:
                continue
            score = score_text(text) + bonus
            if score < 2:
                continue
            hits.append(CodeHit(path=path, relpath=rel.replace("\\", "/"), score=score, size=size))
    hits.sort(key=lambda h: (-h.score, h.relpath))
    return hits[:max_files]


def scripts_as_dict(hits: list[CodeHit], *, max_chars: int = 80_000) -> dict[str, str]:
    out: dict[str, str] = {}
    for h in hits:
        try:
            with open(h.path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read(max_chars)
        except OSError:
            continue
        out[f"app://{h.relpath}"] = text
    return out
