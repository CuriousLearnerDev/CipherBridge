"""小程序 / App 反编译 API。"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from web.services.ai_lab import get_runtime
from web.services.reverse_ops import (
    app_tools_status,
    decode_apk_file,
    decompile_miniprogram,
    list_miniprograms,
    read_hit_preview,
)

router = APIRouter(tags=["reverse"])


@router.get("/api/miniprogram/list")
def api_mini_list(extra_root: str = ""):
    roots = [extra_root] if (extra_root or "").strip() else None
    return list_miniprograms(roots)


class MiniDecompileBody(BaseModel):
    path: str
    appid: str = ""
    inject_session: bool = True


@router.post("/api/miniprogram/decompile")
def api_mini_decompile(body: MiniDecompileBody):
    out = decompile_miniprogram(path=body.path, appid=body.appid)
    if not out.get("ok"):
        raise HTTPException(status_code=400, detail=out.get("error") or "解包失败")
    scripts = out.get("scripts") or {}
    if body.inject_session and scripts:
        summary = get_runtime().merge_scripts(scripts, replace=False)
        out["session"] = summary
    return out


@router.get("/api/app/tools")
def api_app_tools():
    return app_tools_status()


class ApkDecodeBody(BaseModel):
    apk_path: str
    inject_session: bool = True


@router.post("/api/app/decode")
def api_app_decode(body: ApkDecodeBody):
    out = decode_apk_file(body.apk_path)
    if not out.get("ok"):
        raise HTTPException(status_code=400, detail=out.get("error") or "反编译失败")
    scripts = out.get("scripts") or {}
    if body.inject_session and scripts:
        summary = get_runtime().merge_scripts(scripts, replace=False)
        out["session"] = summary
    return out


class HitPreviewBody(BaseModel):
    path: str
    limit: int = Field(default=80_000, ge=1000, le=500_000)


@router.post("/api/reverse/preview")
def api_hit_preview(body: HitPreviewBody):
    out = read_hit_preview(body.path, limit=body.limit)
    if not out.get("ok"):
        raise HTTPException(status_code=404, detail=out.get("error") or "读取失败")
    return out
