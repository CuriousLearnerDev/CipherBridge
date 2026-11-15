"""Windows 窗口边框与标题栏 — 与密桥主题配色一致."""

from __future__ import annotations

import sys
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QWidget

# DWM 属性 (Windows 10 1809+ / 11)
_DWMWA_USE_IMMERSIVE_DARK_MODE = 20
_DWMWA_BORDER_COLOR = 34
_DWMWA_CAPTION_COLOR = 35
_DWMWA_TEXT_COLOR = 36


def _is_windows() -> bool:
    return sys.platform == "win32"


def _qcolor_to_dwm(color: str | QColor) -> int:
    """DWORD 颜色 0xAABBGGRR."""
    c = QColor(color) if isinstance(color, str) else QColor(color)
    a, r, g, b = c.alpha(), c.red(), c.green(), c.blue()
    return (a << 24) | (b << 16) | (g << 8) | r


def _set_dwm_int(hwnd: int, attr: int, value: int) -> None:
    import ctypes
    from ctypes import wintypes

    dwm = ctypes.windll.dwmapi
    attr_val = wintypes.DWORD(attr)
    data = wintypes.DWORD(value)
    dwm.DwmSetWindowAttribute(
        wintypes.HWND(hwnd),
        attr_val,
        ctypes.byref(data),
        ctypes.sizeof(data),
    )


def apply_window_frame(window: QWidget, theme: str, palette: dict[str, str]) -> None:
    """将系统窗口边框/标题栏设为与当前主题一致（仅 Windows）."""
    if not _is_windows() or window is None:
        return
    try:
        hwnd = int(window.winId())
    except Exception:
        return
    if hwnd <= 0:
        return

    dark = 1 if theme == "dark" else 0
    try:
        _set_dwm_int(hwnd, _DWMWA_USE_IMMERSIVE_DARK_MODE, dark)
    except Exception:
        # Win10 旧版可能用 19
        try:
            _set_dwm_int(hwnd, 19, dark)
        except Exception:
            pass

    border = palette.get("border", palette.get("bg", "#505050"))
    caption = palette.get("surface", palette.get("bg", "#323232"))
    text = palette.get("text", "#e0e0e0")

    for attr, color in (
        (_DWMWA_BORDER_COLOR, border),
        (_DWMWA_CAPTION_COLOR, caption),
        (_DWMWA_TEXT_COLOR, text),
    ):
        try:
            _set_dwm_int(hwnd, attr, _qcolor_to_dwm(color))
        except Exception:
            pass

    # 刷新非客户区，使 DWM 立即重绘
    try:
        import ctypes
        ctypes.windll.user32.SetWindowPos(
            hwnd, 0, 0, 0, 0, 0,
            0x0027,  # SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED
        )
    except Exception:
        pass
