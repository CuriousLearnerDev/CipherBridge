from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from web.services.http_parse import parse_http_raw

router = APIRouter(tags=["http"])


class ParseBody(BaseModel):
    raw: str = ""
    include_response: bool = True


@router.post("/api/http/parse")
def api_parse_http(body: ParseBody):
    return parse_http_raw(body.raw, include_response=body.include_response)
