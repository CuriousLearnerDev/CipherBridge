from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from mcp_server import proxy_ctrl as pc
from web.deps import allow_proxy_ctrl

router = APIRouter(tags=["proxy"])


class ProxyStartBody(BaseModel):
    project: str
    role: str = "decrypt"
    port: int = Field(default=8083, ge=1024, le=65535)
    burp_port: int = Field(default=8080, ge=1024, le=65535)


class ProxyStopBody(BaseModel):
    role: str = "decrypt"


def _with_proxy_auth(fn):
    if not allow_proxy_ctrl():
        return {
            "ok": False,
            "error": "未授权：设置环境变量 CB_WEB_ALLOW_PROXY=1 或 CB_MCP_ALLOW_PROXY=1",
            **pc.proxy_status(),
            "allow_proxy_ctrl": False,
        }
    old = pc.ALLOW_PROXY_CTRL
    pc.ALLOW_PROXY_CTRL = True
    try:
        out = fn()
    finally:
        pc.ALLOW_PROXY_CTRL = old
    if isinstance(out, dict):
        out = dict(out)
        out["allow_proxy_ctrl"] = True
    return out


@router.get("/api/proxy/status")
def api_proxy_status():
    st = dict(pc.proxy_status())
    st["allow_proxy_ctrl"] = allow_proxy_ctrl()
    if not st["allow_proxy_ctrl"]:
        st["hint"] = "启停需设置 CB_WEB_ALLOW_PROXY=1 或 CB_MCP_ALLOW_PROXY=1"
    return {"ok": True, **st}


@router.post("/api/proxy/start")
def api_proxy_start(body: ProxyStartBody):
    return _with_proxy_auth(
        lambda: pc.proxy_start(
            body.project,
            role=body.role,
            port=body.port,
            burp_port=body.burp_port,
        )
    )


@router.post("/api/proxy/stop")
def api_proxy_stop(body: ProxyStopBody):
    return _with_proxy_auth(lambda: pc.proxy_stop(body.role))
