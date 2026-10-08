# -*- coding: utf-8 -*-
"""拦截 / 中和前端「反 DevTools」库（常见闪一下变 about:blank）。

不写死某一站点的文件名。识别方式：
1) URL 含 disable-devtool（npm 包常见路径）
2) JS 正文含该库特征（如 DisableDevtool / permission to use DEVTOOL）

Playwright 必连 CDP，这类库常会清页；替换为无害 stub。
"""

from __future__ import annotations

from typing import Any, Callable

# 页面兜底：占坑 + 挡 about:blank（不依赖具体脚本名）
DISABLE_DEVTOOL_GUARD_JS = r"""
(function () {
  if (window.__cbDisableDevtoolGuard) return;
  window.__cbDisableDevtoolGuard = 1;
  try {
    window.DisableDevtool = function () {
      return { success: true, isRunning: false };
    };
    window.DisableDevtool.isRunning = false;
    window.DisableDevtool.version = 'cb-stub';
  } catch (e) {}
  function bad(u) {
    u = String(u == null ? '' : u);
    return u === '' || u === 'about:blank' || /^about:blank/i.test(u);
  }
  try {
    window.close = function () {};
  } catch (e) {}
  try {
    ['assign', 'replace'].forEach(function (k) {
      var o = Location.prototype[k];
      Location.prototype[k] = function (u) {
        if (bad(u)) return;
        return o.apply(this, arguments);
      };
    });
  } catch (e) {}
  try {
    var p = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
    if (p && p.set) {
      Object.defineProperty(Location.prototype, 'href', {
        configurable: true,
        enumerable: true,
        get: function () {
          return p.get.call(this);
        },
        set: function (u) {
          if (bad(u)) return;
          return p.set.call(this, u);
        },
      });
    }
  } catch (e) {}
})();
"""

_STUB_BODY = (
    "/* CipherBridge: anti-devtools stub */\n"
    "window.DisableDevtool=function(){return{success:true,isRunning:false}};\n"
    "window.DisableDevtool.isRunning=false;\n"
)

def _url_looks_like_lib(url: str) -> bool:
    """URL 路径含包名（不写死某站文件名）。"""
    return "disable-devtool" in (url or "").lower()


# 正文特征：只认「库本体」，不认业务脚本里顺带写到的属性字符串
def _content_looks_like_lib(text: str) -> bool:
    if not text or len(text) < 80:
        return False
    # 库运行时典型日志 / 文案
    if "permission to use DEVTOOL" in text or "You don't have permission to use DEVTOOL" in text:
        return True
    # 官方库主入口 + 回调（业务里 document.write 带 disable-devtool-auto 不算）
    low = text.lower()
    has_api = ("DisableDevtool" in text) or ("disabledevtool" in low)
    has_hook = ("ondevtoolopen" in low) or ("ondevtoolclose" in low)
    has_detector = ("devtools" in low and ("debugger" in low or "console.clear" in low))
    if has_api and (has_hook or has_detector):
        return True
    return False


def _is_script_request(url: str, resource_type: str = "") -> bool:
    rt = (resource_type or "").lower()
    if rt in ("script", "stylesheet"):  # stylesheet 不管
        return rt == "script"
    u = (url or "").split("?", 1)[0].lower()
    return u.endswith(".js") or u.endswith(".mjs")


def install_disable_devtool_routes(context, *, log: Callable[[str], None] | None = None) -> None:
    """同步：按 URL/正文特征把反 DevTools 库换成 stub（不写死文件名）。"""

    def _on_route(route: Any) -> None:
        try:
            req = route.request
            url = req.url or ""
            rtype = getattr(req, "resource_type", "") or ""
            # URL 已标明库名 → 直接 stub
            if _url_looks_like_lib(url):
                if log:
                    try:
                        log(f"已拦截反 DevTools 库(URL): {url[:100]}")
                    except Exception:
                        pass
                route.fulfill(
                    status=200,
                    content_type="application/javascript; charset=utf-8",
                    body=_STUB_BODY,
                )
                return
            # 其它 JS：拉正文看特征（覆盖改名后的脚本）
            if _is_script_request(url, rtype):
                resp = route.fetch()
                body = resp.body() or b""
                try:
                    text = body.decode("utf-8", "replace")
                except Exception:
                    text = ""
                if _content_looks_like_lib(text):
                    if log:
                        try:
                            log(f"已拦截反 DevTools 库(特征): {url[:100]}")
                        except Exception:
                            pass
                    route.fulfill(
                        status=200,
                        content_type="application/javascript; charset=utf-8",
                        body=_STUB_BODY,
                    )
                    return
                route.fulfill(response=resp)
                return
        except Exception:
            pass
        try:
            route.continue_()
        except Exception:
            try:
                route.fallback()
            except Exception:
                pass

    # 只挂脚本类，避免与实验室全局改写抢所有请求
    for pattern in ("**/*.js", "**/*.js?*", "**/*.mjs", "**/*.mjs?*", "**/*disable-devtool*"):
        context.route(pattern, _on_route)


async def install_disable_devtool_routes_async(
    context, *, log: Callable[[str], None] | None = None
) -> None:
    """异步同上。"""

    async def _on_route(route: Any) -> None:
        try:
            req = route.request
            url = req.url or ""
            rtype = getattr(req, "resource_type", "") or ""
            if _url_looks_like_lib(url):
                if log:
                    try:
                        log(f"已拦截反 DevTools 库(URL): {url[:100]}")
                    except Exception:
                        pass
                await route.fulfill(
                    status=200,
                    content_type="application/javascript; charset=utf-8",
                    body=_STUB_BODY,
                )
                return
            if _is_script_request(url, rtype):
                resp = await route.fetch()
                body = await resp.body() if hasattr(resp.body, "__await__") else resp.body()
                if callable(body):
                    body = body()
                body = body or b""
                try:
                    text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body)
                except Exception:
                    text = ""
                if _content_looks_like_lib(text):
                    if log:
                        try:
                            log(f"已拦截反 DevTools 库(特征): {url[:100]}")
                        except Exception:
                            pass
                    await route.fulfill(
                        status=200,
                        content_type="application/javascript; charset=utf-8",
                        body=_STUB_BODY,
                    )
                    return
                await route.fulfill(response=resp)
                return
        except Exception:
            pass
        try:
            await route.continue_()
        except Exception:
            try:
                await route.fallback()
            except Exception:
                pass

    for pattern in ("**/*.js", "**/*.js?*", "**/*.mjs", "**/*.mjs?*", "**/*disable-devtool*"):
        await context.route(pattern, _on_route)
