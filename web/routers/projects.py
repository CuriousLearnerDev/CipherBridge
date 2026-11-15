from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from mcp_server.projects import get_plugin_code, get_project, list_projects
from web.services.project_ops import (
    create_project,
    delete_project,
    save_plugin_code,
    save_profile_match,
    save_project_state,
)

router = APIRouter(tags=["projects"])


@router.get("/api/projects")
def api_list_projects():
    return {"ok": True, "projects": list_projects()}


@router.get("/api/projects/{name}")
def api_get_project(name: str):
    data = get_project(name)
    if data.get("error"):
        raise HTTPException(status_code=404, detail=data["error"])
    return {"ok": True, **data}


@router.get("/api/projects/{name}/plugin")
def api_get_plugin(name: str, max_chars: int = Query(40000, ge=1000, le=200000)):
    data = get_plugin_code(name, max_chars=max_chars)
    if data.get("error"):
        raise HTTPException(status_code=404, detail=data["error"])
    return {"ok": True, **data}


class CreateProjectBody(BaseModel):
    name: str
    roles: list[str] = Field(default_factory=lambda: ["decrypt"])
    description: str = ""


@router.post("/api/projects")
def api_create_project(body: CreateProjectBody):
    out = create_project(body.name, roles=body.roles, description=body.description)
    if not out.get("ok"):
        raise HTTPException(status_code=400, detail=out.get("error") or "创建失败")
    return out


class SavePluginBody(BaseModel):
    code: str = ""


@router.put("/api/projects/{name}/plugin")
def api_save_plugin(name: str, body: SavePluginBody):
    out = save_plugin_code(name, body.code)
    if not out.get("ok"):
        raise HTTPException(status_code=400, detail=out.get("error") or "保存失败")
    return out


class SaveStateBody(BaseModel):
    steps: list[dict[str, Any]] = Field(default_factory=list)
    parsed_fields: dict[str, Any] = Field(default_factory=dict)
    body_format: str = "json"
    raw_http: str = ""
    write_plugin: bool = True


@router.put("/api/projects/{name}/state")
def api_save_state(name: str, body: SaveStateBody):
    out = save_project_state(
        name,
        steps=body.steps,
        parsed_fields=body.parsed_fields,
        body_format=body.body_format,
        raw_http=body.raw_http,
        write_plugin=body.write_plugin,
    )
    if not out.get("ok"):
        raise HTTPException(status_code=400, detail=out.get("error") or "保存失败")
    return out


class MatchBody(BaseModel):
    match: dict[str, Any]


@router.put("/api/projects/{name}/match")
def api_save_match(name: str, body: MatchBody):
    out = save_profile_match(name, body.match)
    if not out.get("ok"):
        raise HTTPException(status_code=400, detail=out.get("error") or "保存失败")
    return out


@router.delete("/api/projects/{name}")
def api_delete_project(name: str):
    out = delete_project(name)
    if not out.get("ok"):
        raise HTTPException(status_code=400, detail=out.get("error") or "删除失败")
    return out
