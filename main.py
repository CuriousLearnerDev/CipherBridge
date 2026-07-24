"""入口 — 使用新架构.

命令行:
  mitmdump -s main.py -p 8080

Profile 匹配 → 自动加载对应插件.
"""

import sys, os, logging

_ROOT = os.path.dirname(__file__)
sys.path.insert(0, _ROOT)
_VENDOR = os.path.join(_ROOT, "vendor")
if os.path.isdir(_VENDOR) and _VENDOR not in sys.path:
    sys.path.insert(0, _VENDOR)
logging.basicConfig(level=logging.INFO, format="%(message)s")

from core.mitm_engine import MitmEngine
addons = [MitmEngine()]
