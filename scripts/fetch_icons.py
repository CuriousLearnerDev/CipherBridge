"""从 iconfont 同源图标库下载 SVG 到 img/icons/.

用法:
  python scripts/fetch_icons.py
  python scripts/fetch_icons.py --proxy 127.0.0.1:7897
  set HTTP_PROXY=http://127.0.0.1:7897 && python scripts/fetch_icons.py

iconfont.cn 需登录才能 API 下载 PNG；手动下载 PNG 放入 img/icons/ 可覆盖 SVG。
"""
import argparse
import os
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ICON_DIR = os.path.join(ROOT, "img", "icons")
SVG_BASE = "https://raw.githubusercontent.com/ant-design/ant-design-icons/master/packages/icons-svg/svg/outlined"
DEFAULT_PROXY = os.environ.get("ICON_PROXY", "127.0.0.1:7897")

ICONS = {
    "add": "plus",
    "save": "save",
    "delete": "delete",
    "edit": "edit",
    "play": "play-circle",
    "stop": "pause-circle",
    "refresh": "reload",
    "search": "search",
    "copy": "copy",
    "undo": "undo",
    "clear": "clear",
    "eye": "eye",
    "new": "folder-add",
    "download": "download",
    "upload": "upload",
    "setting": "setting",
    "lock": "lock",
    "unlock": "unlock",
    "file": "file-text",
    "code": "code",
    "test": "experiment",
    "log": "file-search",
    "encrypt": "lock",
    "decrypt": "unlock",
    "plugin": "appstore",
    "builder": "build",
    "analyzer": "radar-chart",
}


def _build_opener(proxy: str | None):
    if not proxy or proxy.lower() in ("none", "off", "0"):
        return urllib.request.build_opener()
    if "://" not in proxy:
        proxy = f"http://{proxy}"
    handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    return urllib.request.build_opener(handler)


def download_svgs(proxy: str | None = DEFAULT_PROXY):
    os.makedirs(ICON_DIR, exist_ok=True)
    opener = _build_opener(proxy)
    ok = 0
    for name, svg_name in ICONS.items():
        url = f"{SVG_BASE}/{svg_name}.svg"
        path = os.path.join(ICON_DIR, f"{name}.svg")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with opener.open(req, timeout=30) as resp:
                data = resp.read()
            with open(path, "wb") as f:
                f.write(data)
            ok += 1
            print(f"  OK  {name}.svg")
        except Exception as e:
            print(f"  FAIL {name}: {e}")
    return ok


def svg_to_png():
    from PyQt6.QtCore import Qt, QSize
    from PyQt6.QtGui import QPixmap, QPainter
    from PyQt6.QtSvg import QSvgRenderer
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication(sys.argv)
    count = 0
    for fname in os.listdir(ICON_DIR):
        if not fname.endswith(".svg"):
            continue
        svg_path = os.path.join(ICON_DIR, fname)
        png_path = os.path.join(ICON_DIR, fname.replace(".svg", ".png"))
        renderer = QSvgRenderer(svg_path)
        if not renderer.isValid():
            print(f"  invalid svg: {fname}")
            continue
        pixmap = QPixmap(24, 24)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        renderer.render(painter)
        painter.end()
        pixmap.save(png_path, "PNG")
        count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description="下载 GUI 图标到 img/icons/")
    parser.add_argument(
        "--proxy", "-p",
        default=DEFAULT_PROXY,
        help=f"HTTP 代理，默认 {DEFAULT_PROXY}；传 none 禁用",
    )
    parser.add_argument("--png", action="store_true", help="额外生成 24px PNG")
    args = parser.parse_args()

    proxy = args.proxy
    print(f"下载图标 SVG (代理: {proxy or '直连'})...")
    n = download_svgs(proxy=proxy)
    print(f"完成: {n}/{len(ICONS)} 个 SVG → img/icons/")
    if args.png and n:
        print("转换 PNG...")
        p = svg_to_png()
        print(f"生成 {p} 个 PNG")


if __name__ == "__main__":
    main()
