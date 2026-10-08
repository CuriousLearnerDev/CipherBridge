# -*- coding: utf-8 -*-
"""自测 crypto_verify：字段验证 + 插件干跑。"""
from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sdk.crypto.aes import aes_encrypt, aes_decrypt
from codegen import codegen_for_pipeline
from core.crypto_verify import verify_crypto, verify_fields_on_body, run_plugin_dry


def _ok(name: str, cond: bool, detail: str = "") -> None:
    mark = "PASS" if cond else "FAIL"
    print(f"[{mark}] {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        raise AssertionError(name + ": " + detail)


def test_decrypt_json_field() -> None:
    key = "1234567890abcdef"
    plain_obj = {"user": "alice", "pwd": "secret"}
    cipher = aes_encrypt(json.dumps(plain_obj, ensure_ascii=False), key)
    body = json.dumps({"data": cipher}, ensure_ascii=False)
    steps = [
        {
            "type": "🔓 解密字段",
            "params": {
                "field": "data",
                "algo": "AES",
                "mode": "ECB",
                "key": key,
                "padding": "PKCS7",
                "scope": "📋 Body (JSON)",
            },
        }
    ]
    side, after = verify_fields_on_body(steps, body, side="request", role="decrypt")
    _ok("decrypt field ok", side.ok is True, side.message)
    _ok("decrypt field count", len(side.fields) == 1)
    _ok("decrypt field message has plaintext", "明文" in side.fields[0].message or side.fields[0].ok)
    parsed = json.loads(after)
    _ok("decrypt nested json object", parsed.get("data") == plain_obj, repr(parsed))


def test_decrypt_wrong_key_fails() -> None:
    key = "1234567890abcdef"
    cipher = aes_encrypt("hello-world", key)
    body = json.dumps({"data": cipher})
    steps = [
        {
            "type": "🔓 解密字段",
            "params": {
                "field": "data",
                "algo": "AES",
                "mode": "ECB",
                "key": "0000000000000000",
                "padding": "PKCS7",
            },
        }
    ]
    side, _ = verify_fields_on_body(steps, body, side="request", role="decrypt")
    # wrong key usually raises padding error -> ok False
    _ok("wrong key not ok", side.ok is False, side.message + " | " + (side.fields[0].message if side.fields else ""))


def test_encrypt_role_reverse_check() -> None:
    """加密端：采样仍是密文，用同参数反解验证。"""
    key = "1234567890abcdef"
    plain = "plain-text-value"
    cipher = aes_encrypt(plain, key)
    body = json.dumps({"token": cipher})
    steps = [
        {
            "type": "🔒 加密字段",
            "params": {
                "field": "token",
                "algo": "AES",
                "mode": "ECB",
                "key": key,
                "padding": "PKCS7",
            },
        }
    ]
    side, after = verify_fields_on_body(steps, body, side="request", role="encrypt")
    _ok("encrypt-role verify ok", side.ok is True, side.message)
    _ok(
        "encrypt-role recovered plain",
        plain in (side.fields[0].after or ""),
        side.fields[0].after,
    )


def test_response_decrypt() -> None:
    key = "1234567890abcdef"
    cipher = aes_encrypt('{"code":0,"msg":"ok"}', key)
    body = json.dumps({"payload": cipher})
    steps = [
        {
            "type": "🔓 解密响应字段",
            "params": {
                "field": "payload",
                "algo": "AES",
                "mode": "ECB",
                "key": key,
                "padding": "PKCS7",
            },
        }
    ]
    side, after = verify_fields_on_body(steps, body, side="response", role="decrypt")
    _ok("response decrypt ok", side.ok is True, side.message)
    req_side, _ = verify_fields_on_body(steps, body, side="request", role="decrypt")
    _ok("response steps skipped on request", req_side.ok is None, req_side.message)


def test_missing_field() -> None:
    steps = [
        {
            "type": "🔓 解密字段",
            "params": {
                "field": "nope",
                "algo": "AES",
                "mode": "ECB",
                "key": "1234567890abcdef",
                "padding": "PKCS7",
            },
        }
    ]
    side, _ = verify_fields_on_body(steps, '{"data":"x"}', side="request", role="decrypt")
    _ok("missing field fails", side.ok is False)
    _ok("missing field msg", "找不到" in side.fields[0].message)


def test_full_report_and_plugin_dry() -> None:
    key = "1234567890abcdef"
    plain_obj = {"user": "bob"}
    cipher = aes_encrypt(json.dumps(plain_obj), key)
    body = json.dumps({"data": cipher})
    steps = [
        {
            "type": "🔓 解密字段",
            "params": {
                "field": "data",
                "algo": "AES",
                "mode": "ECB",
                "key": key,
                "padding": "PKCS7",
                "scope": "📋 Body (JSON)",
            },
        }
    ]
    flow = {
        "method": "POST",
        "url": "http://example.com/api/login",
        "request_headers": {
            "Host": "example.com",
            "Content-Type": "application/json",
        },
        "request_body": body,
        "status": 200,
        "response_headers": {"Content-Type": "application/json"},
        "response_body": json.dumps({"echo": "1"}),
    }
    code = codegen_for_pipeline(steps, "json", "verify_selftest")
    _ok("codegen has request", "def request(" in code)

    report = verify_crypto(steps, flow, role="decrypt", plugin_code=code)
    _ok("report overall", report.overall_ok is True, report.summary)
    _ok("report request ok", report.request.ok is True, report.request.message)
    _ok("report has before/after", bool(report.request.before) and bool(report.request.after))

    before, after, rb, ra, notice = run_plugin_dry(code, flow, role="decrypt")
    _ok("plugin dry changed request", before != after, notice or "changed")
    _ok("plugin dry after contains user", "bob" in after or "user" in after, after[:200])


def test_form_body() -> None:
    key = "1234567890abcdef"
    cipher = aes_encrypt("abc123", key)
    from urllib.parse import urlencode

    body = urlencode({"username": "u", "password": cipher})
    steps = [
        {
            "type": "🔓 解密字段",
            "params": {
                "field": "password",
                "algo": "AES",
                "mode": "ECB",
                "key": key,
                "padding": "PKCS7",
                "scope": "📋 Body (Form)",
            },
        }
    ]
    side, after = verify_fields_on_body(steps, body, side="request", role="decrypt")
    _ok("form decrypt ok", side.ok is True, side.message)
    _ok("form after has plain", "abc123" in after, after)


def main() -> int:
    tests = [
        test_decrypt_json_field,
        test_decrypt_wrong_key_fails,
        test_encrypt_role_reverse_check,
        test_response_decrypt,
        test_missing_field,
        test_form_body,
        test_full_report_and_plugin_dry,
    ]
    failed = 0
    for fn in tests:
        try:
            print(f"\n=== {fn.__name__} ===")
            fn()
        except Exception as e:
            failed += 1
            print(f"[FAIL] {fn.__name__}: {e}")
            traceback.print_exc()
    print(f"\n======== {len(tests) - failed}/{len(tests)} passed ========")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
