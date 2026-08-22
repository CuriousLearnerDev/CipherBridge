"""AI 实验室 — 从分析步骤自动生成并保存 mitmdump 代理项目."""

from __future__ import annotations

import json
import os
from urllib.parse import parse_qsl, urlparse

import yaml

from codegen import generate_code_from_steps
from core.flow_format import flow_to_parser_raw
from core.project_name import normalize_project_name
from core.paths import get_app_root

ROOT = get_app_root()
PROFILES_DIR = os.path.join(ROOT, "profiles")
PLUGINS_DIR = os.path.join(ROOT, "plugins")


def guess_project_name(url: str, flows: list[dict] | None = None) -> str:
    host = ""
    if flows:
        host = urlparse(flows[0].get("url", "")).hostname or ""
    if not host and url:
        u = url.strip()
        if not u.startswith("http"):
            u = "https://" + u
        host = urlparse(u).hostname or ""
    if not host:
        return "ai_project"
    return normalize_project_name(host.lower().replace(".", "_"), default="ai_project")


def detect_body_format(flows: list[dict]) -> str:
    for f in flows:
        body = (f.get("request_body") or "").strip()
        if not body:
            continue
        if body.startswith("{") or body.startswith("["):
            return "json"
        if "=" in body and "&" in body and not body.startswith("<"):
            return "form"
    return "json"


def guess_match_rules(flows: list[dict], fallback_url: str = "") -> dict:
    hosts: set[str] = set()
    paths: set[str] = set()
    methods: set[str] = set()

    for f in flows:
        u = urlparse(f.get("url", ""))
        if u.hostname:
            hosts.add(u.hostname)
        if u.path:
            parts = [p for p in u.path.strip("/").split("/") if p]
            if parts:
                paths.add(f"/{parts[0]}/*")
            else:
                paths.add("/*")
        m = (f.get("method") or "").upper()
        if m:
            methods.add(m)

    if not hosts and fallback_url:
        u = fallback_url.strip()
        if not u.startswith("http"):
            u = "https://" + u
        if urlparse(u).hostname:
            hosts.add(urlparse(u).hostname)

    return {
        "host": sorted(hosts) or ["*"],
        "path": sorted(paths) or ["/api/*"],
        "methods": sorted(methods) or ["POST"],
    }


def _step_fields(steps: list[dict] | None) -> list[str]:
    out: list[str] = []
    for s in steps or []:
        p = s.get("params") if isinstance(s, dict) else None
        if not isinstance(p, dict):
            continue
        for key in ("field", "source_field", "target_field"):
            v = p.get(key)
            if v and str(v) not in out:
                out.append(str(v))
    return out


def pick_sample_flow(
    flows: list[dict] | None,
    steps: list[dict] | None = None,
    preferred: dict | None = None,
) -> dict | None:
    """选一条最适合放进请求解析器的流量（优先含步骤字段的 POST）。"""
    if preferred and isinstance(preferred, dict):
        if (preferred.get("url") or "").strip() or (preferred.get("request_body") or "").strip():
            return preferred
    if not flows:
        return None
    fields = _step_fields(steps)
    ranked: list[tuple[int, int, dict]] = []
    for i, fl in enumerate(flows):
        if not isinstance(fl, dict):
            continue
        body = (fl.get("request_body") or "").strip()
        url = (fl.get("url") or "").strip()
        if not body and not url:
            continue
        if body in ("(等待响应…)", "(等待响应...)"):
            body = ""
        score = 0
        if body:
            score += 10
        if (fl.get("method") or "").upper() in ("POST", "PUT", "PATCH"):
            score += 8
        resp = (fl.get("response_body") or "").strip()
        if resp and resp not in ("(等待响应…)", "(等待响应...)"):
            score += 3
        for name in fields:
            if name and name in body:
                score += 25
            if name and name in url:
                score += 5
        ranked.append((score, i, fl))
    if not ranked:
        return None
    ranked.sort(key=lambda x: (-x[0], -x[1]))
    return ranked[0][2]


def extract_parsed_fields(flow: dict | None, body_format: str = "json") -> tuple[dict, dict]:
    """从流量粗解析 body/query 字段，写入 state 供解析器恢复."""
    fields: dict = {}
    query: dict = {}
    if not flow:
        return fields, query
    url = flow.get("url") or ""
    if "?" in url:
        try:
            q = urlparse(url).query
            query = dict(parse_qsl(q, keep_blank_values=True))
        except Exception:
            pass
    body = (flow.get("request_body") or "").strip()
    if not body or body in ("(等待响应…)", "(等待响应...)"):
        return fields, query
    fmt = body_format
    if fmt not in ("json", "form"):
        if body.startswith("{") or body.startswith("["):
            fmt = "json"
        elif "=" in body:
            fmt = "form"
    try:
        if fmt == "json":
            obj = json.loads(body)
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, (dict, list)):
                        fields[str(k)] = json.dumps(v, ensure_ascii=False)
                    else:
                        fields[str(k)] = "" if v is None else str(v)
        elif fmt == "form":
            fields = dict(parse_qsl(body, keep_blank_values=True))
    except Exception:
        pass
    return fields, query


def _looks_like_hex_cipher(val: str) -> bool:
    s = (val or "").strip()
    if len(s) < 32 or len(s) % 2:
        return False
    if any(c not in "0123456789abcdefABCDEF" for c in s):
        return False
    # 排除短 MD5(32) 当作「可能明文哈希」；AES 块至少 32 hex，常见 >=64
    return len(s) >= 64


def enrich_decrypt_input_fmt(steps: list[dict], flows: list[dict] | None) -> list[dict]:
    """样例密文是长 Hex 且未指定 input_fmt 时，自动补 hex（避免按 base64 解失败）."""
    if not steps:
        return steps
    sample_vals: dict[str, str] = {}
    for fl in flows or []:
        body = (fl.get("request_body") or "").strip()
        if not body or body.startswith("(等待"):
            continue
        try:
            if body[:1] in "{[":
                obj = json.loads(body)
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if isinstance(v, (str, int, float)):
                            sample_vals[str(k)] = str(v)
            elif "=" in body:
                sample_vals.update(dict(parse_qsl(body, keep_blank_values=True)))
        except Exception:
            pass
    out = []
    for s in steps:
        step = dict(s)
        params = dict(step.get("params") or {})
        stype = step.get("type") or ""
        if stype in ("🔓 解密字段", "🔓 解密响应字段") and not params.get("input_fmt"):
            field = str(params.get("field") or "").strip()
            sample = sample_vals.get(field, "")
            if _looks_like_hex_cipher(sample):
                params["input_fmt"] = "hex"
                step["params"] = params
        out.append(step)
    return out


def save_ai_project(
    profile_name: str,
    steps: list[dict],
    *,
    roles: list[str],
    code_role: str | None = None,
    match: dict | None = None,
    body_format: str = "json",
    description: str = "",
    flows: list[dict] | None = None,
    fallback_url: str = "",
    overwrite: bool = False,
    sample_flow: dict | None = None,
) -> tuple[str, str, dict | None]:
    """写入 plugins/ + profiles/ + state.json，返回 (项目名, 插件代码, 样例流量)."""
    name = normalize_project_name(profile_name)
    if not name:
        raise ValueError("项目名称不能为空")

    profile_path = os.path.join(PROFILES_DIR, f"{name}.yaml")
    plugin_dir = os.path.join(PLUGINS_DIR, name)
    if os.path.exists(profile_path) or os.path.isdir(plugin_dir):
        if not overwrite:
            raise FileExistsError(f"项目 '{name}' 已存在")

    if not steps:
        raise ValueError("没有可用的加解密步骤，请先运行 AI 分析")

    steps = enrich_decrypt_input_fmt(steps, flows)
    rules = match or guess_match_rules(flows or [], fallback_url)
    if code_role in ("encrypt", "decrypt"):
        gen_role = code_role
    elif isinstance(roles, list) and "encrypt" in roles and "decrypt" not in roles:
        gen_role = "encrypt"
    else:
        gen_role = "decrypt"
    code = generate_code_from_steps(
        steps, body_format, role=gen_role, profile_name=name, match_rules=rules,
    )

    sample = pick_sample_flow(flows, steps, preferred=sample_flow)
    raw_input = flow_to_parser_raw(sample) if sample else ""
    parsed_fields, parsed_query = extract_parsed_fields(sample, body_format)

    os.makedirs(plugin_dir, exist_ok=True)
    with open(os.path.join(plugin_dir, "plugin.py"), "w", encoding="utf-8") as f:
        f.write(code)

    profile = {
        "name": name,
        "description": description or "AI 实验室自动生成",
        "plugin": name,
        "roles": roles or ["decrypt"],
        "match": {
            "host": rules.get("host", ["*"]),
            "path": rules.get("path", ["/api/*"]),
            "methods": rules.get("methods", ["POST"]),
        },
    }
    with open(profile_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(profile, f, allow_unicode=True, sort_keys=False)

    with open(os.path.join(plugin_dir, "state.json"), "w", encoding="utf-8") as f:
        json.dump(
            {
                "steps": steps,
                "parsed_fields": parsed_fields,
                "parsed_query": parsed_query,
                "body_format": body_format,
                "raw_input": raw_input,
                "ai_generated": True,
            },
            f,
            ensure_ascii=False,
            indent=2,
        )

    return name, code, sample
