from __future__ import annotations

from fastapi import APIRouter

from core.brand import APP_NAME, APP_NAME_EN, APP_SUBTITLE, APP_VERSION
from web import __version__ as web_version
from web.deps import ROOT, allow_proxy_ctrl

router = APIRouter(tags=["status"])


@router.get("/api/status")
def api_status():
    return {
        "ok": True,
        "app": APP_NAME_EN,
        "name": APP_NAME,
        "version": APP_VERSION,
        "subtitle": APP_SUBTITLE,
        "web_version": web_version,
        "root": str(ROOT),
        "ui": "web",
        "allow_proxy_ctrl": allow_proxy_ctrl(),
        "hint": (
            None
            if allow_proxy_ctrl()
            else "代理启停需设置环境变量 CB_WEB_ALLOW_PROXY=1（或 CB_MCP_ALLOW_PROXY=1）"
        ),
    }
