"""FastAPI 应用：Web UI + JSON API（与 gui.py 并行）。"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from web.deps import ensure_sys_path

ensure_sys_path()

from core.brand import APP_TITLE  # noqa: E402
from web.routers import (  # noqa: E402
    ai_lab,
    browser_lab,
    crypto,
    http_parse,
    pipeline,
    projects,
    proxy,
    reverse,
    settings,
    status,
)

WEB_DIR = Path(__file__).resolve().parent
STATIC_DIR = WEB_DIR / "static"
INDEX_HTML = WEB_DIR / "templates" / "index.html"

app = FastAPI(
    title=APP_TITLE,
    description=(
        "密桥 CipherBridge Web 界面。"
        "与桌面 GUI（python gui.py）共用 profiles/plugins/sdk；"
        "浏览器自动化 / AI Lab 仍以桌面版为准。"
    ),
    version="0.4.0",
)

app.include_router(status.router)
app.include_router(projects.router)
app.include_router(crypto.router)
app.include_router(proxy.router)
app.include_router(http_parse.router)
app.include_router(pipeline.router)
app.include_router(settings.router)
app.include_router(ai_lab.router)
app.include_router(browser_lab.router)
app.include_router(reverse.router)

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def index():
    return FileResponse(INDEX_HTML)


def create_app() -> FastAPI:
    return app
