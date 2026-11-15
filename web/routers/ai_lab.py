from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from web.services.ai_lab import (
    AI_MODES,
    FIELD_PICK_MODES,
    default_goal_for,
    extract_steps_from_result,
    get_config_public,
    get_runtime,
    update_config,
)
from web.services.project_ops import create_project, save_project_state

router = APIRouter(tags=["ai"])


@router.get("/api/ai/modes")
def api_modes():
    return {
        "ok": True,
        "modes": AI_MODES,
        "field_pick_modes": sorted(FIELD_PICK_MODES),
        "defaults": {m["id"]: default_goal_for(m["id"]) for m in AI_MODES},
    }


@router.get("/api/ai/field-options")
def api_field_options():
    """列出当前会话流量中的可选字段（分析加解密前弹窗用）。"""
    return get_runtime().field_options()


@router.get("/api/ai/config")
def api_get_config():
    return {"ok": True, "config": get_config_public()}


class ConfigBody(BaseModel):
    config: dict[str, Any] = Field(default_factory=dict)


@router.put("/api/ai/config")
def api_put_config(body: ConfigBody):
    return {"ok": True, "config": update_config(body.config or {})}


@router.get("/api/ai/session")
def api_session():
    return {"ok": True, **get_runtime().session_summary()}


class SessionBody(BaseModel):
    flows: list[dict[str, Any]] | None = None
    hooks: list[str] | None = None
    scripts: dict[str, str] | None = None
    replace: bool = True


@router.put("/api/ai/session")
def api_set_session(body: SessionBody):
    rt = get_runtime()
    summary = rt.set_session(
        flows=body.flows,
        hooks=body.hooks,
        scripts=body.scripts,
        replace=body.replace,
    )
    return {"ok": True, **summary}


@router.delete("/api/ai/session")
def api_clear_session():
    return {"ok": True, **get_runtime().clear_session()}


class SelectionBody(BaseModel):
    flow_indices: list[int] | None = None
    script_urls: list[str] | None = None


@router.put("/api/ai/session/selection")
def api_set_selection(body: SelectionBody):
    """勾选送入 Agent 的流量 / JS（对齐 GUI）。"""
    return {
        "ok": True,
        **get_runtime().set_material_selection(
            flow_indices=body.flow_indices,
            script_urls=body.script_urls,
        ),
    }


class HttpFlowBody(BaseModel):
    raw: str
    url: str = ""
    method: str = "POST"


@router.post("/api/ai/session/http")
def api_add_http(body: HttpFlowBody):
    out = get_runtime().add_flow_from_http(body.raw, url=body.url, method=body.method)
    if not out.get("ok"):
        raise HTTPException(status_code=400, detail=out.get("error") or "解析失败")
    return out


class ScriptBody(BaseModel):
    url: str = ""
    code: str = ""


@router.post("/api/ai/session/script")
def api_add_script(body: ScriptBody):
    if not (body.code or "").strip():
        raise HTTPException(status_code=400, detail="code 不能为空")
    return get_runtime().add_script(body.url, body.code)


class RunBody(BaseModel):
    mode: str = "recognize"
    goal: str = ""
    field_targets: dict[str, Any] | None = None


@router.post("/api/ai/run")
def api_run(body: RunBody):
    out = get_runtime().start(
        mode=body.mode,
        goal=body.goal,
        field_targets=body.field_targets,
    )
    if not out.get("ok"):
        raise HTTPException(status_code=400, detail=out.get("error") or "启动失败")
    return out


@router.post("/api/ai/stop")
def api_stop():
    return {"ok": True, **get_runtime().stop()}


@router.get("/api/ai/job")
def api_job():
    return {"ok": True, **get_runtime().job_snapshot()}


class ApplyBody(BaseModel):
    project: str = ""
    encrypt_project: str = ""
    create_if_missing: bool = True
    overwrite: bool = True
    roles: list[str] = Field(default_factory=lambda: ["decrypt"])
    result_text: str = ""
    match: dict[str, Any] | None = None
    code_role: str = "decrypt"
    both: bool = False


@router.get("/api/ai/generate-options")
def api_generate_options():
    """生成脚本弹窗默认项：项目名 / 角色 / 匹配规则 / steps 数。"""
    from core.ai_project_writer import guess_match_rules, guess_project_name
    from core.project_name import normalize_project_name

    rt = get_runtime()
    snap = rt.job_snapshot()
    role = "encrypt" if (snap.get("verify") or {}).get("role") == "encrypt" else "decrypt"
    if snap.get("mode") == "generate_encrypt":
        role = "encrypt"
    both = bool(snap.get("encrypt_verified")) and role == "decrypt"
    flows = list(rt.flows)
    name = normalize_project_name(guess_project_name("", flows))
    match = guess_match_rules(flows, "")
    steps = snap.get("steps") or extract_steps_from_result(str(snap.get("result") or ""))
    if both:
        script_type = "加解密脚本（解密 + 加密各一份）"
    elif role == "encrypt":
        script_type = "加密脚本"
    else:
        script_type = "解密脚本"
    return {
        "ok": True,
        "name": name,
        "code_role": role,
        "both": both,
        "script_type": script_type,
        "match": match,
        "steps": len(steps or []),
        "exists": False,
    }


@router.post("/api/ai/analyze-encrypt")
def api_analyze_encrypt():
    """解密验证通过后：反推加密并用原密文回环对照。"""
    from core.ai_project_writer import pick_sample_flow
    from core.crypto_verify import has_reversible_crypto_steps, verify_encrypt_roundtrip

    rt = get_runtime()
    snap = rt.job_snapshot()
    steps = list(snap.get("steps") or [])
    if not steps:
        steps = extract_steps_from_result(str(snap.get("result") or ""))
    if not steps:
        raise HTTPException(status_code=400, detail="没有可用的解密步骤")
    if not has_reversible_crypto_steps(steps):
        raise HTTPException(status_code=400, detail="当前步骤没有可反推的加解密字段")
    sample = pick_sample_flow(list(rt.flows), steps, preferred=None)
    if not sample:
        raise HTTPException(status_code=400, detail="没有可用的采样流量")
    report, enc_steps = verify_encrypt_roundtrip(steps, sample)
    with rt._lock:
        rt.job["encrypt_steps"] = list(enc_steps)
        rt.job["encrypt_verified"] = bool(report.overall_ok)
        attempt = int((snap.get("verify") or {}).get("attempt") or 1)
        max_a = int((snap.get("verify") or {}).get("max_attempts") or 5)
        rt.job["verify"] = rt._report_to_dict(
            report, attempt=attempt, max_attempts=max_a
        )
    return {
        "ok": True,
        "overall_ok": bool(report.overall_ok),
        "verify": rt.job_snapshot().get("verify"),
        "encrypt_steps": len(enc_steps),
    }


@router.post("/api/ai/apply-steps")
def api_apply_steps(body: ApplyBody):
    """把 Agent 结果里的 steps 写入项目 plugin（对齐 GUI「生成解密脚本」）。"""
    from core.project_name import normalize_project_name
    from mcp_server.projects import get_project
    from web.services.project_ops import save_profile_match

    rt = get_runtime()
    snap = rt.job_snapshot()
    steps = list(snap.get("steps") or [])
    if not steps:
        text = (body.result_text or "").strip() or str(snap.get("result") or "")
        steps = extract_steps_from_result(text)
    if not steps:
        raise HTTPException(status_code=400, detail="结果中未解析到 steps")

    role = (body.code_role or "decrypt").lower()
    if role not in ("encrypt", "decrypt"):
        role = "decrypt"
    roles = [r for r in (body.roles or [role]) if r in ("encrypt", "decrypt")] or [role]

    name = normalize_project_name((body.project or "").strip())
    if not name:
        from core.ai_project_writer import guess_project_name

        name = normalize_project_name(guess_project_name("", rt.flows))

    info = get_project(name)
    existed = not bool(info.get("error"))
    if info.get("error"):
        if not body.create_if_missing:
            raise HTTPException(status_code=404, detail=info["error"])
        created = create_project(name, roles=roles)
        if not created.get("ok"):
            raise HTTPException(status_code=400, detail=created.get("error") or "创建失败")
        name = created["id"]
    elif not body.overwrite:
        raise HTTPException(status_code=409, detail=f"项目已存在: {name}")

    if body.match and isinstance(body.match, dict):
        save_profile_match(name, body.match)

    # 同步 roles 到 profile
    try:
        import yaml
        from mcp_server.paths import PROFILES_DIR

        profile = PROFILES_DIR / f"{name}.yaml"
        if profile.is_file() and yaml is not None:
            data = yaml.safe_load(profile.read_text(encoding="utf-8")) or {}
            data["roles"] = roles
            profile.write_text(
                yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )
    except Exception:
        pass

    out = save_project_state(
        name,
        steps=steps,
        parsed_fields={},
        body_format="json",
        write_plugin=True,
    )
    if not out.get("ok"):
        raise HTTPException(status_code=400, detail=out.get("error") or "保存失败")

    enc_project = None
    want_both = bool(body.both) and role == "decrypt" and bool(snap.get("encrypt_verified"))
    if want_both:
        enc_steps = list(snap.get("encrypt_steps") or [])
        if enc_steps:
            enc_name = normalize_project_name(
                (body.encrypt_project or "").strip()
            ) or normalize_project_name(f"{name}_encrypt")
            if enc_name == name:
                raise HTTPException(
                    status_code=400, detail="解密项目与加密项目不能使用同一个名称"
                )
            enc_info = get_project(enc_name)
            if enc_info.get("error"):
                created = create_project(enc_name, roles=["encrypt"])
                if not created.get("ok"):
                    raise HTTPException(
                        status_code=400,
                        detail=created.get("error") or "创建加密项目失败",
                    )
                enc_name = created["id"]
            if body.match and isinstance(body.match, dict):
                save_profile_match(enc_name, body.match)
            try:
                import yaml
                from mcp_server.paths import PROFILES_DIR

                profile = PROFILES_DIR / f"{enc_name}.yaml"
                if profile.is_file() and yaml is not None:
                    data = yaml.safe_load(profile.read_text(encoding="utf-8")) or {}
                    data["roles"] = ["encrypt"]
                    profile.write_text(
                        yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
                        encoding="utf-8",
                    )
            except Exception:
                pass
            enc_out = save_project_state(
                enc_name,
                steps=enc_steps,
                parsed_fields={},
                body_format="json",
                write_plugin=True,
            )
            if enc_out.get("ok"):
                enc_project = enc_name

    return {
        "ok": True,
        "project": name,
        "encrypt_project": enc_project,
        "steps": len(steps),
        "existed": existed,
        "code_role": role,
        **out,
    }
