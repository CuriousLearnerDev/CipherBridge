# 密桥浏览器扩展目录
#
# cb_hook/   — CipherBridge Hook
#   · 默认注入密钥 Hook；点图标可开关页面注入（刷新生效）
#   · 反调试等请在密桥 GUI「注入」菜单勾选
#   · bootstrap.js 读取选项后注入 inject.js
# reres/     — ReRes MV3 兼容版
# vendor/    — Violentmonkey（暴力猴）
# scripts/   — 生成的 *.user.js
#
# 启动浏览器时应看到 3 个扩展：
#   1. CipherBridge Hook
#   2. 暴力猴 Violentmonkey
#   3. ReRes
#
# GitHub 慢时可在 config/ai.yaml 设 browser.ext_proxy: 127.0.0.1:7897
