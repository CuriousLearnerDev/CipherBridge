"""GUI 图标加载 — 从 img/icons/ 加载 PNG/SVG，程序图标 img/main.jpg.

规则：
- 逻辑名优先找同名文件；没有再用别名
- 有 SVG 时优先用 SVG 并按主题着色；统领替换的图标已去掉 SVG，走彩色 PNG
- 仅 PNG 时：彩色图标保持原色，深色单色图标按主题字色提亮
"""

from __future__ import annotations

import os
import re
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QIcon, QPixmap, QPainter, QColor, QImage

try:
    from PyQt6.QtSvg import QSvgRenderer
    _HAS_SVG = True
except ImportError:
    _HAS_SVG = False

from core.theme import C
from core.paths import get_app_root

ROOT = get_app_root()
IMG_DIR = os.path.join(ROOT, "img")
ICON_DIR = os.path.join(IMG_DIR, "icons")
MAIN_ICON = os.path.join(IMG_DIR, "main.jpg")
TOPOLOGY_IMAGE = os.path.join(IMG_DIR, "e2f83ef5-edda-4dbf-a8f0-cf24bbc920aa.png")

# 仅：逻辑名没有同名文件时兜底（严格按文件名语义）
ICON_ALIASES: dict[str, str] = {
    "folder": "open",
    "settings": "setting",
    "logs": "log",
    "analyze": "analyzer",
    "warn": "warning",
    "help": "info",
    "run": "play",
    "import": "open",
    # 解析器旧名
    "upload": "parser",
}

# 彩色 PNG 优先（自定义解析器/构建器/浏览器图标，不走 SVG 主题染色）
_COLOR_PNG_FIRST = frozenset({"parser", "builder", "browser"})

_VARIANT_TINT = {
    "primary": C["text"],
    "accent": C["text"],
    "danger": C["danger"],
    "warn": C["text"],
    "ghost": C["text_dim"],
}

_cache: dict[tuple[str, int, str], QIcon] = {}


def clear_icon_cache() -> None:
    _cache.clear()


def _tint_svg_data(svg_data: str, color: str) -> bytes:
    """给无 fill 的 SVG 路径着色，适配深色主题."""
    svg_data = re.sub(
        r'(<svg\b[^>]*?)fill="[^"]*"',
        rf'\1fill="{color}"',
        svg_data,
        count=1,
    )
    if 'fill="' not in svg_data.split(">", 1)[0]:
        svg_data = re.sub(
            r"(<svg\b)",
            rf'\1 fill="{color}"',
            svg_data,
            count=1,
        )
    svg_data = re.sub(r'fill="#333"', f'fill="{color}"', svg_data)
    svg_data = re.sub(r"fill='#333'", f"fill='{color}'", svg_data)
    svg_data = re.sub(r'stroke="#333"', f'stroke="{color}"', svg_data)
    return svg_data.encode("utf-8")


def _render_svg(svg_path: str, size: int, tint: str | None = None) -> QIcon:
    color = tint or C["text"]
    with open(svg_path, encoding="utf-8") as f:
        svg_data = _tint_svg_data(f.read(), color)
    renderer = QSvgRenderer(svg_data)
    pixmap = QPixmap(QSize(size, size))
    pixmap.fill(Qt.GlobalColor.transparent)
    if renderer.isValid():
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        renderer.render(painter)
        painter.end()
    return QIcon(pixmap)


def _tint_png(png_path: str, size: int, tint: str) -> QIcon:
    """PNG 重着色：透明底深色图标 → 主题色；彩色图标保持原色."""
    src = QPixmap(png_path)
    if src.isNull():
        return QIcon()
    src = src.scaled(
        QSize(size, size),
        Qt.AspectRatioMode.KeepAspectRatio,
        Qt.TransformationMode.SmoothTransformation,
    )
    img = src.toImage().convertToFormat(QImage.Format.Format_ARGB32)
    dark_ink = 0
    opaque = 0
    for y in range(img.height()):
        for x in range(img.width()):
            p = img.pixelColor(x, y)
            if p.alpha() < 16:
                continue
            opaque += 1
            if (p.red() + p.green() + p.blue()) / 3 < 80:
                dark_ink += 1
    # 彩色图标（红停、蓝清等）不染色
    if opaque > 0 and dark_ink / opaque < 0.55:
        return QIcon(src)

    tinted = QPixmap(src.size())
    tinted.fill(Qt.GlobalColor.transparent)
    painter = QPainter(tinted)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
    painter.drawPixmap(0, 0, src)
    painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
    painter.fillRect(tinted.rect(), QColor(tint))
    painter.end()
    return QIcon(tinted)


def _resolve_tint(tint: str | None = None, light: bool = False, variant: str = "") -> str:
    if tint:
        return tint
    if variant in _VARIANT_TINT:
        return _VARIANT_TINT[variant]
    if light:
        return C["text"]
    return C.get("text", "#e8eaed")


def _candidate_basenames(name: str) -> list[str]:
    """同名优先，再跟别名链（避免互指死循环）."""
    names: list[str] = []
    seen: set[str] = set()
    queue = [name]
    while queue:
        cur = queue.pop(0)
        if cur in seen:
            continue
        seen.add(cur)
        names.append(cur)
        alias = ICON_ALIASES.get(cur)
        if alias and alias not in seen:
            queue.append(alias)
    return names


def icon(name: str, size: int = 20, light: bool = False, tint: str | None = None) -> QIcon:
    """按逻辑名加载：优先同名 SVG（主题着色），其次 PNG（深色自动提亮）."""
    color = _resolve_tint(tint, light=light)
    key = (name, size, color)
    if key in _cache:
        return _cache[key]

    ic = QIcon()
    for base in _candidate_basenames(name):
        png = os.path.join(ICON_DIR, f"{base}.png")
        svg = os.path.join(ICON_DIR, f"{base}.svg")
        # 彩色自定义图标：PNG 优先，避免被 SVG 主题色覆盖
        if base in _COLOR_PNG_FIRST and os.path.isfile(png):
            ic = _tint_png(png, size, color)
            break
        if os.path.isfile(svg) and _HAS_SVG:
            ic = _render_svg(svg, size, tint=color)
            break
        if os.path.isfile(png):
            ic = _tint_png(png, size, color)
            break

    _cache[key] = ic
    return ic


def app_icon() -> QIcon:
    """程序窗口图标 — img/main.jpg."""
    if os.path.isfile(MAIN_ICON):
        return QIcon(MAIN_ICON)
    return QIcon()


def set_btn_icon(btn, name: str, size: int = 18, light: bool = False, tint: str | None = None):
    """为按钮设置图标（默认 18px，比原先更易辨认）."""
    if tint is None:
        variant = btn.property("variant") or ""
        if variant == "primary":
            tint = C.get("primary_fg", C["text"])
        elif variant == "accent":
            tint = C.get("accent_fg", C["text"])
        else:
            tint = C["text"]
    ic = icon(name, size, light=light, tint=tint)
    if ic.isNull():
        btn.setIcon(QIcon())
        return
    btn.setIcon(ic)
    btn.setIconSize(QSize(size, size))


def apply_app_icon(window) -> None:
    """设置主窗口及任务栏图标."""
    ic = app_icon()
    if not ic.isNull():
        window.setWindowIcon(ic)
