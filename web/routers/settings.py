from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from web.deps import ROOT

router = APIRouter(tags=["settings"])

SETTINGS_PATH = ROOT / "config" / "settings.yaml"


@router.get("/api/settings")
def api_get_settings():
    try:
        import yaml

        if not SETTINGS_PATH.is_file():
            return {"ok": True, "settings": {}, "path": str(SETTINGS_PATH)}
        data = yaml.safe_load(SETTINGS_PATH.read_text(encoding="utf-8")) or {}
        return {"ok": True, "settings": data, "path": "config/settings.yaml"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


class SettingsBody(BaseModel):
    settings: dict[str, Any]


@router.put("/api/settings")
def api_put_settings(body: SettingsBody):
    try:
        import yaml

        SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        # 合并而非整文件覆盖 gui 段以外的键
        cur: dict[str, Any] = {}
        if SETTINGS_PATH.is_file():
            cur = yaml.safe_load(SETTINGS_PATH.read_text(encoding="utf-8")) or {}
        for k, v in (body.settings or {}).items():
            if isinstance(v, dict) and isinstance(cur.get(k), dict):
                cur[k] = {**cur[k], **v}
            else:
                cur[k] = v
        SETTINGS_PATH.write_text(
            yaml.safe_dump(cur, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        return {"ok": True, "settings": cur}
    except Exception as e:
        return {"ok": False, "error": str(e)}
