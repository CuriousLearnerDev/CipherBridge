"""加解密步骤自动验证 — 对采样流量做字段试算 + 可选插件干跑。"""

from __future__ import annotations

import json
import os
import re
import sys
import types
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse

from core.paths import get_app_root

ROOT = get_app_root()

_DECRYPT_TYPES = ("🔓 解密字段", "🔓 解密响应字段")
_ENCRYPT_TYPES = ("🔒 加密字段", "🔒 加密响应字段")
_RESP_TYPES = ("🔓 解密响应字段", "🔒 加密响应字段")


@dataclass
class FieldCheck:
    side: str  # request | response
    field: str
    op: str
    ok: bool
    message: str
    before: str = ""
    after: str = ""


@dataclass
class SideCheck:
    side: str
    ok: bool | None  # None = 无相关步骤可验
    changed: bool = False
    message: str = ""
    before: str = ""
    after: str = ""
    fields: list[FieldCheck] = field(default_factory=list)


@dataclass
class VerifyReport:
    role: str
    overall_ok: bool
    summary: str
    request: SideCheck
    response: SideCheck
    plugin_notice: str = ""
    error: str = ""


def _clip(s: str, n: int = 240) -> str:
    s = s or ""
    return s if len(s) <= n else s[:n] + "…"


def _looks_json(text: str) -> bool:
    t = (text or "").strip()
    if not t or t[0] not in "{[":
        return False
    try:
        json.loads(t)
        return True
    except Exception:
        return False


def _looks_form(text: str) -> bool:
    t = (text or "").strip()
    return bool(t) and "=" in t and not t.startswith("<") and "\n" not in t[:80]


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    ok = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return ok / max(1, len(text))


def _looks_plaintext(text: str) -> bool:
    if not text:
        return False
    if _looks_json(text) or _looks_form(text):
        return True
    return _printable_ratio(text) > 0.92 and len(text) < 50_000


def _looks_ciphertextish(text: str) -> bool:
    t = (text or "").strip()
    if len(t) < 8:
        return False
    if _looks_json(t) or _looks_form(t):
        # JSON 里嵌密文也算「有结构」，不算整段密文
        return False
    b64 = re.fullmatch(r"[A-Za-z0-9+/=\s]{16,}", t) is not None
    hexish = re.fullmatch(r"[0-9a-fA-F\s]{16,}", t) is not None
    return b64 or hexish or (_printable_ratio(t) < 0.75)


def _parse_body(body: str) -> tuple[str, Any]:
    """返回 (kind, data) kind=json|form|raw."""
    t = (body or "").strip()
    if not t:
        return "raw", t
    if t.startswith("{") or t.startswith("["):
        try:
            return "json", json.loads(t)
        except Exception:
            return "raw", t
    if "=" in t and "&" in t:
        return "form", dict(parse_qsl(t, keep_blank_values=True))
    if "=" in t and "\n" not in t:
        return "form", dict(parse_qsl(t, keep_blank_values=True))
    return "raw", t


def _dump_body(kind: str, data: Any, original: str) -> str:
    if kind == "json":
        # 尽量保持紧凑，贴近接口
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    if kind == "form" and isinstance(data, dict):
        return urlencode(data)
    return original if not isinstance(data, str) else data


def _get_path(obj: Any, path: str) -> Any:
    cur = obj
    for part in (path or "").split("."):
        if not part:
            continue
        if isinstance(cur, dict):
            if part not in cur:
                return None
            cur = cur[part]
        else:
            return None
    return cur


def _set_path(obj: Any, path: str, value: Any) -> bool:
    parts = [p for p in (path or "").split(".") if p]
    if not parts or not isinstance(obj, dict):
        return False
    cur = obj
    for p in parts[:-1]:
        if p not in cur or not isinstance(cur[p], dict):
            cur[p] = {}
        cur = cur[p]
    cur[parts[-1]] = value
    return True


def _sdk_crypt(op: str, algo: str, data: str, key: str, mode: str, padding: str, iv: str, fmt: str) -> str:
    algo_u = (algo or "AES").upper()
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    if algo_u == "AES":
        from sdk.crypto.aes import aes_decrypt, aes_encrypt

        if op == "decrypt":
            return aes_decrypt(data, key, mode=mode, padding=padding, iv=iv, input_fmt=fmt)
        return aes_encrypt(data, key, mode=mode, padding=padding, iv=iv, output=fmt)
    if algo_u == "DES":
        from sdk.crypto.des import des_decrypt, des_encrypt

        if op == "decrypt":
            return des_decrypt(data, key, mode=mode, padding=padding, iv=iv, input_fmt=fmt)
        return des_encrypt(data, key, mode=mode, padding=padding, iv=iv, output=fmt)
    if algo_u in ("3DES", "TRIPLEDES"):
        from sdk.crypto.tripledes import tripledes_decrypt, tripledes_encrypt

        if op == "decrypt":
            return tripledes_decrypt(data, key, mode=mode, padding=padding, iv=iv, input_fmt=fmt)
        return tripledes_encrypt(data, key, mode=mode, padding=padding, iv=iv, output=fmt)
    if algo_u == "SM4":
        from sdk.crypto.sm4 import sm4_decrypt, sm4_encrypt

        iv2 = iv or "0000000000000000"
        if op == "decrypt":
            return sm4_decrypt(data, key, mode=mode, padding=padding, iv=iv2)
        return sm4_encrypt(data, key, mode=mode, padding=padding, iv=iv2, output=fmt)
    if algo_u == "XOR":
        from sdk.crypto.xor import xor_decrypt, xor_encrypt

        if op == "decrypt":
            return xor_decrypt(data, key, input_fmt=fmt)
        return xor_encrypt(data, key, output=fmt)
    raise ValueError(f"暂不支持自动验证的算法: {algo}")


def _step_crypt_op(step_type: str) -> str | None:
    if step_type in _DECRYPT_TYPES:
        return "decrypt"
    if step_type in _ENCRYPT_TYPES:
        return "encrypt"
    return None


def _judge_field(op: str, before: str, after: str) -> tuple[bool, str]:
    if after == before:
        return False, "结果与输入相同，可能未真正加解密"
    if op == "decrypt":
        if _looks_plaintext(after):
            return True, "解密后像明文（JSON/表单/可读文本）"
        if _looks_ciphertextish(after):
            return False, "解密后仍像密文"
        if _printable_ratio(after) > 0.85:
            return True, "解密后可读性尚可"
        return False, "解密结果可读性差，可能密钥/模式错误"
    # encrypt
    if _looks_ciphertextish(after) or (not _looks_plaintext(after) and len(after) >= 8):
        return True, "加密后形态像密文"
    if _looks_plaintext(after):
        return False, "加密后仍像明文"
    return True, "加密已产生不同输出"


def _roundtrip_ok(algo: str, plain: str, key: str, mode: str, padding: str, iv: str, fmt: str, cipher: str) -> bool:
    """解密再加密是否回到原密文（ECB/固定 IV 的 CBC 等）。"""
    try:
        again = _sdk_crypt("encrypt", algo, plain, key, mode, padding, iv, fmt)
        # Base64 可能有 padding 差异
        a = (again or "").replace("\n", "").replace(" ", "")
        b = (cipher or "").replace("\n", "").replace(" ", "")
        return a == b
    except Exception:
        return False


def verify_fields_on_body(
    steps: list[dict],
    body: str,
    *,
    side: str,
    role: str,
) -> tuple[SideCheck, str]:
    """对单侧 body 做字段级验证，返回 (SideCheck, 变换后 body)。"""
    kind, data = _parse_body(body)
    checks: list[FieldCheck] = []
    relevant = []
    for st in steps or []:
        t = str(st.get("type") or "")
        op = _step_crypt_op(t)
        if not op:
            continue
        is_resp = t in _RESP_TYPES
        if side == "request" and is_resp:
            continue
        if side == "response" and not is_resp:
            continue
        # 加密端：采样流量仍是密文，用同参数做解密试算以验证密钥/模式
        verify_op = op
        if (role or "").lower() == "encrypt" and op == "encrypt":
            verify_op = "decrypt"
        relevant.append((st, verify_op, t, op))

    if not relevant:
        return (
            SideCheck(side=side, ok=None, message="无对应加解密字段步骤", before=body, after=body),
            body,
        )

    working = data
    any_fail = False
    for st, verify_op, t, orig_op in relevant:
        p = st.get("params") or {}
        field = str(p.get("field") or p.get("path") or "").strip()
        algo = str(p.get("algo") or "AES")
        key = str(p.get("key") or "")
        mode = str(p.get("mode") or "ECB")
        padding = str(p.get("padding") or "PKCS7")
        iv = str(p.get("iv") or "")
        fmt = str(p.get("input_fmt") or p.get("output") or p.get("fmt") or "base64")
        if fmt.lower() in ("hex", "base64"):
            fmt = fmt.lower()
        else:
            fmt = "base64"

        if not field:
            checks.append(
                FieldCheck(side, "?", t, False, "步骤缺少 field", "", "")
            )
            any_fail = True
            continue
        if not key or key.startswith("$") or key.lower() in ("unknown", "xxx", "..."):
            checks.append(
                FieldCheck(side, field, t, False, f"密钥无效: {key or '(空)'}", "", "")
            )
            any_fail = True
            continue

        if kind == "raw":
            before_val = body
        else:
            before_val = _get_path(working, field) if isinstance(working, dict) else None
            if before_val is None:
                checks.append(
                    FieldCheck(side, field, t, False, "采样流量中找不到该字段", "", "")
                )
                any_fail = True
                continue
            before_val = str(before_val)

        try:
            after_val = _sdk_crypt(verify_op, algo, before_val, key, mode, padding, iv, fmt)
        except Exception as e:
            checks.append(
                FieldCheck(side, field, t, False, f"运算失败: {e}", _clip(before_val), "")
            )
            any_fail = True
            continue

        ok, msg = _judge_field(verify_op, before_val, after_val)
        if orig_op == "encrypt" and verify_op == "decrypt" and ok:
            msg = "用加密参数反解密文成功（密钥/模式可用）— " + msg
        if ok and verify_op == "decrypt" and mode.upper() in ("ECB", "CBC"):
            if _roundtrip_ok(algo, after_val, key, mode, padding, iv, fmt, before_val):
                msg += "；回环加密与原密文一致"

        if kind != "raw" and isinstance(working, dict):
            to_set: Any = after_val
            if verify_op == "decrypt" and _looks_json(after_val):
                try:
                    to_set = json.loads(after_val)
                except Exception:
                    to_set = after_val
            _set_path(working, field, to_set)
        elif kind == "raw":
            working = after_val

        checks.append(
            FieldCheck(side, field, t, ok, msg, _clip(before_val), _clip(after_val))
        )
        if not ok:
            any_fail = True

    after_body = _dump_body(kind, working, body) if kind != "raw" else (
        working if isinstance(working, str) else body
    )
    changed = after_body != body
    ok = (not any_fail) and changed
    if not changed and not any_fail:
        ok = False
        message = "字段运算未改变 Body"
    elif any_fail:
        message = "存在失败或可疑字段"
    else:
        message = "字段验证通过"
    return (
        SideCheck(
            side=side,
            ok=ok,
            changed=changed,
            message=message,
            before=body,
            after=after_body,
            fields=checks,
        ),
        after_body,
    )


def _flow_bodies(flow: dict | None) -> tuple[str, str]:
    if not flow:
        return "", ""
    req = flow.get("request_body") or ""
    if isinstance(req, bytes):
        req = req.decode("utf-8", errors="replace")
    resp = flow.get("response_body") or ""
    if isinstance(resp, bytes):
        resp = resp.decode("utf-8", errors="replace")
    return str(req), str(resp)


def _build_mock_response(resp_block: str):
    from mitmproxy import http

    lines = resp_block.replace("\r\n", "\n").split("\n")
    m = re.match(r"HTTP/\d\.\d\s+(\d+)", lines[0].strip())
    status = int(m.group(1)) if m else 200
    headers: dict[str, str] = {}
    body_start = len(lines)
    for i, line in enumerate(lines[1:], start=1):
        line = line.strip()
        if not line:
            body_start = i + 1
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    body = "\n".join(lines[body_start:]).strip().encode("utf-8")
    return http.Response.make(status, body, headers)


def run_plugin_dry(
    code: str,
    flow: dict | None,
    *,
    role: str = "decrypt",
) -> tuple[str, str, str, str, str]:
    """干跑 plugin request/response，返回 before/after 文本。encrypt 会 mock requests。"""
    from mitmproxy import http
    from mitmproxy.test.tflow import tflow
    from core.flow_format import flow_to_parser_raw, split_request_response_body
    from core.http_message import format_request, format_response

    if not code or "def request(" not in code:
        raise RuntimeError("无有效 request(flow) 插件代码")
    if not flow:
        raise RuntimeError("无采样流量")

    raw = flow_to_parser_raw(flow)
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")
    lines = raw.split("\n")
    first = lines[0].strip()
    parts = first.split(" ", 2)
    method = parts[0] if parts else "POST"
    path = parts[1] if len(parts) > 1 else "/"
    header_section, _, body_section = raw.partition("\n\n")
    req_body, resp_block = split_request_response_body(body_section.strip())

    headers: dict[str, str] = {}
    for line in header_section.split("\n")[1:]:
        line = line.strip()
        if line and ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    host = ""
    for k, v in headers.items():
        if k.lower() == "host":
            host = v.strip()
            break
    url = flow.get("url") or f"http://{host or 'localhost'}{path}"
    if not url.startswith("http"):
        url = "http://" + url

    req = http.Request.make(method, url, req_body.encode("utf-8"), headers)
    tf = tflow(req=req)
    if resp_block:
        tf.response = _build_mock_response(resp_block)
    elif flow.get("response_body"):
        status = int(flow.get("status") or 200)
        rh = flow.get("response_headers") or {}
        if not isinstance(rh, dict):
            rh = {}
        body = flow.get("response_body") or ""
        if isinstance(body, bytes):
            b = body
        else:
            b = str(body).encode("utf-8")
        tf.response = http.Response.make(status, b, {str(k): str(v) for k, v in rh.items()})

    before = format_request(tf)
    resp_before = format_response(tf) if tf.response else ""

    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)

    class _Resp:
        status_code = 200
        content = b'{"ok":true,"_cipherbridge_dry":true}'
        headers: dict = {"Content-Type": "application/json"}

    class _Sess:
        def request(self, *a, **k):
            return _Resp()

    mock_requests = types.ModuleType("requests")
    mock_requests.Session = lambda: _Sess()  # type: ignore
    mock_requests.request = lambda *a, **k: _Resp()  # type: ignore
    mock_requests.exceptions = types.SimpleNamespace(  # type: ignore
        Timeout=type("Timeout", (Exception,), {}),
        RequestException=type("RequestException", (Exception,), {}),
    )

    ns: dict[str, Any] = {
        "__name__": "_cipherbridge_verify_plugin",
        "__file__": os.path.join(ROOT, "plugins", "_verify_tmp.py"),
        "requests": mock_requests,
    }
    exec(compile(code, "<cipherbridge-verify>", "exec"), ns)
    old = sys.modules.get("requests")
    sys.modules["requests"] = mock_requests
    try:
        fn = ns.get("request")
        if not callable(fn):
            raise RuntimeError("插件无 request(flow)")
        fn(tf)
        if tf.response and callable(ns.get("response")):
            ns["response"](tf)
    finally:
        if old is not None:
            sys.modules["requests"] = old
        else:
            sys.modules.pop("requests", None)

    after = format_request(tf)
    resp_after = format_response(tf) if tf.response else ""
    notice = ""
    if after == before and resp_after == resp_before:
        notice = "插件未改写报文（可能 MATCH_RULES 未命中，或步骤对采样流量无效）"
    return before, after, resp_before, resp_after, notice


def verify_crypto(
    steps: list[dict],
    flow: dict | None,
    *,
    role: str = "decrypt",
    plugin_code: str | None = None,
) -> VerifyReport:
    """综合字段验证 +（可选）插件干跑。"""
    role = (role or "decrypt").lower()
    req_body, resp_body = _flow_bodies(flow)

    req_side, _ = verify_fields_on_body(steps, req_body, side="request", role=role)
    resp_side, _ = verify_fields_on_body(steps, resp_body, side="response", role=role)

    plugin_notice = ""
    if plugin_code and flow:
        try:
            b, a, rb, ra, notice = run_plugin_dry(plugin_code, flow, role=role)
            plugin_notice = notice or ""
            # 用干跑结果丰富展示（字段结论仍以 SDK 为准）
            if b:
                req_side.before = b
            if a:
                req_side.after = a
                req_side.changed = req_side.changed or (a != b)
            if rb:
                resp_side.before = rb
            if ra:
                resp_side.after = ra
                resp_side.changed = resp_side.changed or (ra != rb)
            if notice and req_side.ok is True and not req_side.changed:
                req_side.ok = False
                req_side.message = notice
        except Exception as e:
            plugin_notice = f"插件干跑失败: {e}"

    sides = [s for s in (req_side, resp_side) if s.ok is not None]
    if not sides:
        return VerifyReport(
            role=role,
            overall_ok=False,
            summary="没有可验证的加解密字段步骤（或采样 Body 为空）",
            request=req_side,
            response=resp_side,
            plugin_notice=plugin_notice,
        )

    overall = all(s.ok for s in sides)
    parts = []
    if req_side.ok is not None:
        parts.append("请求正确" if req_side.ok else "请求异常")
    else:
        parts.append("请求未验证")
    if resp_side.ok is not None:
        parts.append("响应正确" if resp_side.ok else "响应异常")
    else:
        parts.append("响应未验证")
    summary = " · ".join(parts)
    if overall:
        summary = "验证通过 — " + summary
    else:
        summary = "验证未完全通过 — " + summary

    return VerifyReport(
        role=role,
        overall_ok=overall,
        summary=summary,
        request=req_side,
        response=resp_side,
        plugin_notice=plugin_notice,
    )


def format_verify_feedback(report: VerifyReport, *, max_body: int = 1800) -> str:
    """把验证失败结果压成给 AI 的修正提示（含处理前后报文与字段错误）。"""
    lines: list[str] = [
        f"验证结果: {report.summary}",
        f"角色: {report.role}",
        f"overall_ok: {report.overall_ok}",
    ]
    if report.plugin_notice:
        lines.append(f"插件干跑提示: {report.plugin_notice}")
    if report.error:
        lines.append(f"错误: {report.error}")

    for side in (report.request, report.response):
        title = "请求" if side.side == "request" else "响应"
        if side.ok is None and not side.fields and not (side.before or side.after):
            continue
        lines.append(f"\n## {title}")
        lines.append(f"状态: {_clip(side.message, 200) or ('正确' if side.ok else ('异常' if side.ok is False else '未验证'))}")
        for f in side.fields or []:
            mark = "OK" if f.ok else "FAIL"
            lines.append(
                f"- 字段 {f.field} [{f.op}] {mark}: {f.message}"
                + (f"\n  before: {_clip(f.before, 160)}" if f.before else "")
                + (f"\n  after: {_clip(f.after, 160)}" if f.after else "")
            )
        if side.before:
            lines.append(f"处理前 Body:\n{_clip(side.before, max_body)}")
        if side.after and side.after != side.before:
            lines.append(f"处理后 Body:\n{_clip(side.after, max_body)}")
    return "\n".join(lines)
