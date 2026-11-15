from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from web.services.pipeline import (
    list_ops,
    list_templates,
    merge_template_steps,
    preview_code,
    reverse_steps,
)

router = APIRouter(tags=["pipeline"])


class PreviewBody(BaseModel):
    steps: list[dict[str, Any]] = Field(default_factory=list)
    body_format: str = "json"
    profile_name: str = ""


class ReverseBody(BaseModel):
    code: str = ""


class TemplateLoadBody(BaseModel):
    name: str = ""


@router.get("/api/pipeline/ops")
def api_ops():
    return {"ok": True, "ops": list_ops()}


@router.get("/api/pipeline/templates")
def api_templates():
    return {"ok": True, "templates": list_templates()}


@router.post("/api/pipeline/templates/load")
def api_template_load(body: TemplateLoadBody):
    return merge_template_steps(body.name or "")


@router.post("/api/pipeline/preview")
def api_preview(body: PreviewBody):
    return preview_code(
        body.steps,
        body_format=body.body_format,
        profile_name=body.profile_name,
    )


@router.post("/api/pipeline/reverse")
def api_reverse(body: ReverseBody):
    return reverse_steps(body.code)
