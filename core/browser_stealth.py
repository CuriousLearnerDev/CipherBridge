"""浏览器拟真 / 抗自动化检测 — UA、locale、时区、webdriver 隐藏、JS 挑战重试.

用于密桥代理浏览器与 AI 实验室采集：让站点更接近「真实 Chrome」环境。
不替代本机 Chrome（channel=chrome 仍更稳）；本模块补齐 Playwright 常见指纹缺口。
"""

from __future__ import annotations

import locale as locale_mod
import platform
import re
from typing import Any, Callable


# 与近期稳定版 Chrome 接近的桌面 UA（channel=chrome 时会尽量用真实版本覆盖）
_DEFAULT_CHROME_UA_WIN = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
_DEFAULT_CHROME_UA_MAC = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
_DEFAULT_CHROME_UA_LINUX = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# Cloudflare / 常见 JS 挑战页特征
_CHALLENGE_TITLE_RE = re.compile(
    r"just a moment|attention required|checking your browser|"
    r"please wait|security check|access denied|cf-browser-verification|"
    r"验证|人机|安全检查|请稍候",
    re.I,
)
_CHALLENGE_BODY_HINTS = (
    "cf-challenge",
    "cf-browser-verification",
    "challenge-platform",
    "cdn-cgi/challenge",
    "managed_checking_msg",
    "turnstile",
    "_cf_chl",
    "ray id",
    "checking if the site connection is secure",
)


def detect_locale() -> str:
    """系统 locale → Playwright locale，如 zh-CN."""
    try:
        loc = locale_mod.getdefaultlocale()
        if loc and loc[0]:
            raw = loc[0].replace("_", "-")
            # zh_CN.UTF-8 → zh-CN
            raw = raw.split(".")[0]
            if len(raw) >= 2:
                return raw
    except Exception:
        pass
    return "zh-CN"


def detect_timezone() -> str:
    """系统时区 IANA 名，如 Asia/Shanghai."""
    try:
        import time

        name = time.tzname[0] if time.tzname else ""
        # Windows 常见非 IANA，优先 zoneinfo / tzlocal
    except Exception:
        name = ""
    try:
        from zoneinfo import ZoneInfo  # noqa: F401
        import datetime as dt

        tz = dt.datetime.now().astimezone().tzinfo
        key = getattr(tz, "key", None)
        if key:
            return str(key)
    except Exception:
        pass
    try:
        import tzlocal  # type: ignore

        return str(tzlocal.get_localzone_name())
    except Exception:
        pass
    # 中国常用回退
    if name and ("China" in name or "CST" in name or "北京" in name):
        return "Asia/Shanghai"
    return "Asia/Shanghai"


def default_user_agent() -> str:
    sysname = platform.system().lower()
    if sysname == "darwin":
        return _DEFAULT_CHROME_UA_MAC
    if sysname == "linux":
        return _DEFAULT_CHROME_UA_LINUX
    return _DEFAULT_CHROME_UA_WIN


def stealth_chromium_args(*, for_lab: bool = False) -> list[str]:
    """Chromium 启动参数：去掉明显自动化特征。

    for_lab=True 时保留扩展相关能力；不主动加 --disable-web-security
    （该参数极易被检测，由调用方自行决定）。
    """
    args = [
        "--disable-blink-features=AutomationControlled",
        "--disable-features=IsolateOrigins,site-per-process,HttpsFirstBalancedModeAutoEnable",
        "--disable-infobars",
        "--no-default-browser-check",
        "--no-first-run",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-domain-reliability",
        "--disable-client-side-phishing-detection",
        "--disable-hang-monitor",
        "--disable-popup-blocking",
        "--disable-prompt-on-repost",
        "--metrics-recording-only",
        "--password-store=basic",
        "--use-mock-keychain",
        "--start-maximized",
        # 尽量走真实 GPU，减少 SwiftShader 软件渲染指纹
        "--ignore-gpu-blocklist",
        "--enable-webgl",
        "--enable-accelerated-2d-canvas",
        "--use-angle=default",
    ]
    if for_lab:
        args.append("--enable-extensions")
    return args


def stealth_ignore_default_args() -> list[str]:
    """让 Playwright 不要注入 --enable-automation 等标记."""
    return ["--enable-automation"]


def stealth_context_options(
    *,
    locale: str | None = None,
    timezone_id: str | None = None,
    user_agent: str | None = None,
) -> dict[str, Any]:
    """给 launch_persistent_context / new_context 的拟真选项."""
    loc = locale or detect_locale()
    # languages: zh-CN → Accept-Language
    langs = [loc]
    short = loc.split("-")[0]
    if short and short not in langs:
        langs.append(short)
    if "en-US" not in langs:
        langs.append("en-US")
    if "en" not in langs:
        langs.append("en")
    parts = []
    for i, l in enumerate(langs):
        if i == 0:
            parts.append(l)
        else:
            q = max(1, 10 - i) / 10.0
            parts.append(f"{l};q={q:.1f}")
    accept_lang = ",".join(parts)
    return {
        "locale": loc,
        "timezone_id": timezone_id or detect_timezone(),
        "user_agent": user_agent or default_user_agent(),
        "ignore_https_errors": True,
        "viewport": None,  # 配合 --start-maximized，避免固定小视口指纹
        "color_scheme": "light",
        "java_script_enabled": True,
        "extra_http_headers": {
            "Accept-Language": accept_lang,
        },
    }


# 注入脚本：通用环境拟真底座（不写死某站 / 某测试页）
# 覆盖常见自动化指纹：webdriver、chrome、plugins、CDP console、SwiftShader WebGL、cdc_
# 站点差异（FingerprintJS 业务逻辑、WAF DOM、业务 token）仍由 AI hook_js 增量补
#
# 注意：瑞数等「强 JS 挑战 / 脚本完整性」站请用「真实浏览器」(use_stealth=false)，
# 勿叠拟真注入——那是策略分流，不是某站硬编码补丁。

# 通用 CDP 前置（也可单独导出给 site_early_hook）
CDP_CONSOLE_PRELUDE = r"""(function(){try{if(window.__cbCdpConsolePatched)return;window.__cbCdpConsolePatched=1;var c=console;if(!c)return;['log','debug','info','warn','error'].forEach(function(k){var o=c[k];if(typeof o!=='function')return;c[k]=function(){var a=[].slice.call(arguments);for(var i=0;i<a.length;i++){if(a[i]instanceof Error)a[i]=String(a[i]);}return o.apply(c,a);};});}catch(e){}})();"""

STEALTH_INIT_SCRIPT = r"""
(() => {
  try {
    // 挂在 Navigator.prototype，避免 own + writable 被 hasWebdriverWritable 打到
    const proto = Navigator.prototype;
    try { delete navigator.webdriver; } catch (e0) {}
    Object.defineProperty(proto, 'webdriver', {
      get: () => undefined,
      set: undefined,
      enumerable: true,
      configurable: true,
    });
  } catch (e) {}

  try {
    if (!window.chrome) {
      window.chrome = { runtime: {}, loadTimes: function(){}, csi: function(){}, app: {} };
    } else if (!window.chrome.runtime) {
      window.chrome.runtime = {};
    }
  } catch (e) {}

  try {
    const langs = navigator.languages && navigator.languages.length
      ? navigator.languages
      : [navigator.language || 'zh-CN', 'zh', 'en-US', 'en'];
    Object.defineProperty(navigator, 'languages', {
      get: () => langs,
      configurable: true,
    });
  } catch (e) {}

  try {
    if (!navigator.plugins || navigator.plugins.length === 0) {
      const fake = [
        { name: 'PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
        { name: 'Chrome PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
        { name: 'Chromium PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
      ];
      fake.item = (i) => fake[i] || null;
      fake.namedItem = (n) => fake.find(p => p.name === n) || null;
      fake.refresh = () => {};
      Object.defineProperty(navigator, 'plugins', { get: () => fake, configurable: true });
      Object.defineProperty(navigator, 'mimeTypes', {
        get: () => {
          const m = [{ type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format' }];
          m.item = (i) => m[i] || null;
          m.namedItem = (n) => m.find(x => x.type === n) || null;
          return m;
        },
        configurable: true,
      });
    }
  } catch (e) {}

  try {
    const oldQuery = window.navigator.permissions && navigator.permissions.query
      ? navigator.permissions.query.bind(navigator.permissions)
      : null;
    if (oldQuery) {
      navigator.permissions.query = (params) => {
        if (params && (params.name === 'notifications' || params.name === 'push')) {
          return Promise.resolve({ state: Notification.permission || 'default', onchange: null });
        }
        return oldQuery(params);
      };
    }
  } catch (e) {}

  try {
    Object.defineProperty(navigator, 'maxTouchPoints', { get: () => 0, configurable: true });
  } catch (e) {}

  try {
    for (const k of Object.getOwnPropertyNames(document)) {
      if (k.match(/^\$?cdc_/i) || k.match(/^\$chrome_asyncScriptInfo/i)) {
        try { delete document[k]; } catch (e2) {}
      }
    }
  } catch (e) {}

  // —— hasCDP：console 遇 Error 先 String，避免 prepareStackTrace 触达 DevTools ——
  try {
    if (!window.__cbCdpConsolePatched) {
      window.__cbCdpConsolePatched = 1;
      const c = console;
      if (c) {
        ['log', 'debug', 'info', 'warn', 'error'].forEach(function (k) {
          const o = c[k];
          if (typeof o !== 'function') return;
          c[k] = function () {
            const a = [].slice.call(arguments);
            for (let i = 0; i < a.length; i++) {
              if (a[i] instanceof Error) a[i] = String(a[i]);
            }
            return o.apply(c, a);
          };
        });
      }
    }
  } catch (e) {}

  // —— SwiftShader / 无头 GPU：仅当 UNMASKED_* 像软件渲染时替换；Worker 同步一致 ——
  try {
    const VENDOR = 'Intel Inc.';
    const RENDERER = 'Intel Iris OpenGL Engine';
    const badGpu = function (v) {
      return typeof v === 'string' && /SwiftShader|llvmpipe|softpipe|Swift Shader/i.test(v);
    };
    const patchProto = function (proto) {
      if (!proto || !proto.getParameter || proto.__cbGpuPatched) return;
      proto.__cbGpuPatched = 1;
      const orig = proto.getParameter;
      proto.getParameter = function (p) {
        const v = orig.apply(this, arguments);
        if ((p === 37445 || p === 37446) && badGpu(v)) {
          return p === 37445 ? VENDOR : RENDERER;
        }
        return v;
      };
    };
    if (window.WebGLRenderingContext) patchProto(WebGLRenderingContext.prototype);
    if (window.WebGL2RenderingContext) patchProto(WebGL2RenderingContext.prototype);

    const workerPrelude =
      '(function(){try{var V="Intel Inc.",R="Intel Iris OpenGL Engine";' +
      'function bad(v){return typeof v==="string"&&/SwiftShader|llvmpipe|softpipe/i.test(v)}' +
      'function patch(p){if(!p||!p.getParameter||p.__cbGpuPatched)return;p.__cbGpuPatched=1;' +
      'var o=p.getParameter;p.getParameter=function(x){var v=o.apply(this,arguments);' +
      'if((x===37445||x===37446)&&bad(v))return x===37445?V:R;return v}}' +
      'if(self.WebGLRenderingContext)patch(WebGLRenderingContext.prototype);' +
      'if(self.WebGL2RenderingContext)patch(WebGL2RenderingContext.prototype);' +
      '}catch(e){}})();';
    const NativeWorker = window.Worker;
    if (NativeWorker && !NativeWorker.__cbGpuWrapped) {
      function wrapUrl(u) {
        try {
          if (typeof u !== 'string') return u;
          if (/^blob:/i.test(u)) return u;
          const src =
            workerPrelude +
            ';try{importScripts(' +
            JSON.stringify(u) +
            ');}catch(e){}';
          return URL.createObjectURL(new Blob([src], { type: 'text/javascript' }));
        } catch (e) {
          return u;
        }
      }
      function WrappedWorker(scriptURL, options) {
        return new NativeWorker(wrapUrl(scriptURL), options);
      }
      WrappedWorker.prototype = NativeWorker.prototype;
      WrappedWorker.__cbGpuWrapped = 1;
      try {
        Object.defineProperty(WrappedWorker, 'name', { value: 'Worker' });
      } catch (e2) {}
      window.Worker = WrappedWorker;
    }
  } catch (e) {}
})();
"""


def merge_launch_options(
    base: dict[str, Any],
    *,
    for_lab: bool = False,
    locale: str | None = None,
    timezone_id: str | None = None,
    user_agent: str | None = None,
) -> dict[str, Any]:
    """合并拟真启动参数到 launch_persistent_context 选项."""
    out = dict(base)
    stealth = stealth_context_options(
        locale=locale, timezone_id=timezone_id, user_agent=user_agent
    )
    hdrs = dict(out.get("extra_http_headers") or {})
    hdrs.update(stealth.get("extra_http_headers") or {})
    out["extra_http_headers"] = hdrs
    for k in ("locale", "timezone_id", "user_agent", "color_scheme", "java_script_enabled"):
        if k in stealth:
            out[k] = stealth[k]
    if out.get("viewport") is not False:
        out["viewport"] = stealth.get("viewport")
    out["ignore_https_errors"] = True

    existing = list(out.get("args") or [])
    for a in stealth_chromium_args(for_lab=for_lab):
        if a not in existing:
            existing.append(a)
    drop_prefixes = ("--enable-automation",)
    existing = [a for a in existing if not any(a.startswith(p) for p in drop_prefixes)]
    # 代理浏览器不要 --disable-web-security（强指纹）
    if not for_lab:
        existing = [a for a in existing if a != "--disable-web-security"]
    out["args"] = existing
    ignore = list(out.get("ignore_default_args") or [])
    for a in stealth_ignore_default_args():
        if a not in ignore:
            ignore.append(a)
    out["ignore_default_args"] = ignore
    return out


def apply_stealth_to_context(context) -> None:
    """同步 Context：注入 stealth init script."""
    context.add_init_script(STEALTH_INIT_SCRIPT)


async def apply_stealth_to_context_async(context) -> None:
    await context.add_init_script(STEALTH_INIT_SCRIPT)


# 必须在其它 init_script / expose_binding 之后再注入，否则 hasPlaywright 仍会命中
PW_MARKER_CLEANUP_SCRIPT = r"""
(() => {
  const names = [
    '__pwInitScripts',
    '__playwright__binding__',
    '__pw_manual',
    '__PW_inspect',
  ];
  for (let i = 0; i < names.length; i++) {
    const n = names[i];
    try { delete window[n]; } catch (e) {}
  }
  // 兜底：扫一遍仍带 playwright / __pw 的可配置自有属性
  try {
    const keys = Object.getOwnPropertyNames(window);
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      if (!k) continue;
      const low = k.toLowerCase();
      if (k.indexOf('__pw') === 0 || low.indexOf('playwright') >= 0) {
        try { delete window[k]; } catch (e2) {}
      }
    }
  } catch (e3) {}
})();
"""


def apply_playwright_marker_cleanup(context) -> None:
    """清掉 Playwright 暴露的全局标记（须放在全部 init_script 最后）。"""
    context.add_init_script(PW_MARKER_CLEANUP_SCRIPT)


async def apply_playwright_marker_cleanup_async(context) -> None:
    await context.add_init_script(PW_MARKER_CLEANUP_SCRIPT)


def _page_looks_like_challenge_sync(page) -> bool:
    try:
        title = (page.title() or "").strip()
        if title and _CHALLENGE_TITLE_RE.search(title):
            return True
    except Exception:
        pass
    try:
        body = page.content() or ""
        low = body.lower()
        hits = sum(1 for h in _CHALLENGE_BODY_HINTS if h in low)
        if hits >= 1 and (
            "cloudflare" in low
            or "cf-" in low
            or "challenge" in low
            or "turnstile" in low
            or "验证" in body
        ):
            return True
    except Exception:
        pass
    return False


async def _page_looks_like_challenge_async(page) -> bool:
    try:
        title = (await page.title() or "").strip()
        if title and _CHALLENGE_TITLE_RE.search(title):
            return True
    except Exception:
        pass
    try:
        body = await page.content() or ""
        low = body.lower()
        hits = sum(1 for h in _CHALLENGE_BODY_HINTS if h in low)
        if hits >= 1 and (
            "cloudflare" in low
            or "cf-" in low
            or "challenge" in low
            or "turnstile" in low
            or "验证" in body
        ):
            return True
    except Exception:
        pass
    return False


def wait_out_js_challenge_sync(
    page,
    *,
    timeout_ms: int = 45000,
    poll_ms: int = 800,
    max_reload: int = 2,
    log: Callable[[str], None] | None = None,
) -> bool:
    """同步：若落在 JS 挑战页则等待通过，必要时自动 reload 重试.

    返回 True=看起来已离开挑战页（或本来就不是）；False=超时仍像挑战页。
    """
    import time

    def _log(msg: str) -> None:
        if log:
            try:
                log(msg)
            except Exception:
                pass

    deadline = time.time() + timeout_ms / 1000.0
    reloads = 0
    saw = False
    while time.time() < deadline:
        try:
            if page.is_closed():
                return False
        except Exception:
            return False
        challenged = _page_looks_like_challenge_sync(page)
        if not challenged:
            if saw:
                _log("JS 挑战已通过")
            return True
        if not saw:
            saw = True
            _log("检测到 JS/人机挑战页，等待自动通过…")
        # 挑战中：稍等；过半仍卡则 reload
        elapsed_ratio = 1 - (deadline - time.time()) / (timeout_ms / 1000.0)
        if elapsed_ratio > 0.45 and reloads < max_reload:
            reloads += 1
            _log(f"挑战未完成，自动重试刷新 ({reloads}/{max_reload})…")
            try:
                page.reload(wait_until="domcontentloaded", timeout=30000)
            except Exception as e:
                _log(f"刷新失败: {e}")
        try:
            page.wait_for_timeout(poll_ms)
        except Exception:
            time.sleep(poll_ms / 1000.0)
    _log("JS 挑战等待超时（可手动在窗口内完成验证）")
    return not _page_looks_like_challenge_sync(page)


async def wait_out_js_challenge_async(
    page,
    *,
    timeout_ms: int = 45000,
    poll_ms: int = 800,
    max_reload: int = 2,
    log: Callable[[str], None] | None = None,
) -> bool:
    """异步版 wait_out_js_challenge_sync."""
    import asyncio
    import time

    def _log(msg: str) -> None:
        if log:
            try:
                log(msg)
            except Exception:
                pass

    deadline = time.time() + timeout_ms / 1000.0
    reloads = 0
    saw = False
    while time.time() < deadline:
        try:
            if page.is_closed():
                return False
        except Exception:
            return False
        challenged = await _page_looks_like_challenge_async(page)
        if not challenged:
            if saw:
                _log("JS 挑战已通过")
            return True
        if not saw:
            saw = True
            _log("检测到 JS/人机挑战页，等待自动通过…")
        elapsed_ratio = 1 - (deadline - time.time()) / (timeout_ms / 1000.0)
        if elapsed_ratio > 0.45 and reloads < max_reload:
            reloads += 1
            _log(f"挑战未完成，自动重试刷新 ({reloads}/{max_reload})…")
            try:
                await page.reload(wait_until="domcontentloaded", timeout=30000)
            except Exception as e:
                _log(f"刷新失败: {e}")
        await asyncio.sleep(poll_ms / 1000.0)
    _log("JS 挑战等待超时（可手动在窗口内完成验证）")
    return not await _page_looks_like_challenge_async(page)


def stealth_summary() -> str:
    return (
        f"UA/locale/tz + CDP console + SwiftShader WebGL/Worker · "
        f"locale={detect_locale()} · tz={detect_timezone()}"
    )
