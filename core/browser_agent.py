"""通用浏览器交互 Agent — QThread + agent-core ReAct + 实时浏览器运行时.

与专门逆向用的 CryptoAgent 不同，本 Agent 刻意保持【完全通用】:
- system prompt 不含任何领域名词（WAF/反爬/指纹/挑战等一律不写）,
  只教“观测→判断→行动”的闭环求解方法论；
- 工具是浏览器原子的观测源（打开/查看/等/刷新/截图/Cookie/执行 JS），
  领域常识由模型用自身知识与工具观测自行组合，不在 prompt 里预设；
- 目标 URL 由运行时的 goal 动态注入；“是否达成”以页面可复核证据为准，
  不写死任何成功判据。
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from typing import Any, Callable

from PyQt6.QtCore import QThread, pyqtSignal

from core.ai_config import load_ai_config, normalize_browser_channel, resolve_agent_base_url
from core.paths import get_app_root
from core.playwright_env import (
    apply_launch_channel,
    channel_label,
    setup_playwright_browsers_path,
)

from agent_core import Agent
from agent_core.tools.base import BaseTool, ToolMetadata

logger = logging.getLogger(__name__)

# ======================================================================
# 唯一写死的“心智”：方法论，不含任何领域知识
# ======================================================================
GENERAL_SYSTEM_PROMPT = """你是一个通用浏览器交互智能体。
系统会在运行时给你一个【目标】和一个【浏览器工具集】。你对该领域的预判全部可能是错的：
一切判断只能来自工具返回的观测数据，禁止把模型记忆或猜测当作事实。

求解原则（唯一固定规则，必须遵守）：

1. 闭环： 每个动作都先想清楚“依据哪个观测”、“为了验证什么”，再调用工具。
   禁止在未观测的情况下断言页面状态或结果。
2. 证据： 任何“成功/失败/存在/不存在”的结论，必须附可复核的证据
   （页面标题、可见文本、截图路径、工具返回值）。没有证据的状态一律按“未完成”对待。
3. 假设验证： 一旦产生猜测，立刻设计一个最小实验去证实或证伪它，而不是继续空想。
4. 预算： 行动次数有限（会告知最大步数）。不要重复做相同动作；
   每一步都必须让状态比上一步更接近目标或更了解障碍。
5. 变参数： 同一个方向连续失败时，主动改变变量（等待时长、是否刷新、
   换入口、观察方式、拆分动作、换档案、等人操作、**切换浏览器启动策略**等），
   不要原地重试同一操作。启动策略可通过 browser_restart.reconfigure 切换：
   use_stealth(拟真开/关≈实验室「普通注入」vs「接近真实浏览器」)、
   browser_channel(chrome|chromium)、headless、proxy、fresh_profile(是否清档案)、
   neutralize_devtools(中和反 DevTools；闪一下变 about:blank 时打开)。
   连续 2～3 次同策略仍卡死时，必须换策略再试，禁止死磕同一浏览器配置。
6. 终态： 预算内达成目标就立即收工并输出结论与证据；
   预算耗尽仍未达成，则如实报告“已试路径、卡点、仍然未知什么”，禁止编造成功。
   最终 JSON 建议附带 launch(最后一次启动参数) 便于实验室同步。

输出：
- 思考： 一句话说明“当前判断 + 依据的哪个观测”。
- 行动： 调用的工具名与参数。
- 最终： 返回一个 JSON，至少含 goal(原目标)、reached(bool)、
  evidence(证据字符串，如页面标题/文本片段/截图路径)、attempts(调用工具次数)。
  除 evidence 外的任何“成功”都视为未完成。
"""

_DEFAULT_GOAL_TPL = (
    "访问目标页面 {url}，判断并报告：页面是否能正常显示其主要内容。"
    "若未正常显示，请自主尝试你能想到的一切合理手段使其显示，"
    "并在每一步用证据说明你看到了什么。最后按规则输出 JSON。"
)


def agent_profile_dir_for_channel(channel: str | None) -> str:
    """Agent 专用持久档案（与实验室档案分离，避免双开锁死）。"""
    ch = normalize_browser_channel(channel)
    if ch == "chrome":
        return os.path.join(get_app_root(), "data", "browser_agent_profile_chrome")
    return os.path.join(get_app_root(), "data", "browser_agent_profile")


def _clip(text: str, n: int) -> str:
    s = text or ""
    if len(s) <= n:
        return s
    return s[:n] + f"…(+{len(s) - n})"


# ======================================================================
# 浏览器运行时
# ======================================================================


class BrowserRuntime:
    """持久浏览器会话：工具调用它执行动作，并返回结构化观测。"""

    def __init__(
        self,
        *,
        profile_dir: str | None = None,
        headless: bool = False,
        proxy: str | None = None,
        browser_channel: str = "chromium",
        use_stealth: bool = True,
        neutralize_devtools: bool = False,
        max_text: int = 1200,
    ) -> None:
        self.browser_channel = normalize_browser_channel(browser_channel)
        if profile_dir is None:
            profile_dir = agent_profile_dir_for_channel(self.browser_channel)
        os.makedirs(profile_dir, exist_ok=True)
        self.profile_dir = profile_dir
        self.headless = headless
        self.proxy = proxy
        self.use_stealth = bool(use_stealth)
        self.neutralize_devtools = bool(neutralize_devtools)
        self.max_text = max_text

        self._pw = None
        self._ctx = None
        self._page = None
        self._profile_dir = profile_dir

    async def _launch(self, profile_dir: str) -> None:
        from playwright.async_api import async_playwright

        from core.browser_stealth import (
            apply_stealth_to_context_async,
            merge_launch_options,
            stealth_summary,
        )

        setup_playwright_browsers_path()
        os.makedirs(profile_dir, exist_ok=True)
        if self._pw is None:
            self._pw = await async_playwright().start()

        ctx_opts: dict[str, Any] = {
            "headless": bool(self.headless),
            "args": ["--no-sandbox", "--ignore-certificate-errors"],
            "ignore_https_errors": True,
            "viewport": None,
        }
        if self.proxy:
            ctx_opts["proxy"] = {"server": self.proxy}
            args = list(ctx_opts["args"])
            args.append(f"--proxy-server={self.proxy}")
            args.append("--proxy-bypass-list=<-loopback>")
            ctx_opts["args"] = args

        ctx_opts = apply_launch_channel(ctx_opts, self.browser_channel)
        if self.use_stealth:
            ctx_opts = merge_launch_options(ctx_opts, for_lab=False)

        self._ctx = await self._pw.chromium.launch_persistent_context(
            profile_dir, **ctx_opts
        )
        self._ctx.set_default_timeout(40_000)
        if self.use_stealth:
            try:
                await apply_stealth_to_context_async(self._ctx)
            except Exception as e:
                logger.warning("stealth init failed: %s", e)
        # 与实验室「反调试」勾选同步：仅开启时中和反 DevTools
        if self.neutralize_devtools:
            try:
                from core.disable_devtool_guard import (
                    DISABLE_DEVTOOL_GUARD_JS,
                    install_disable_devtool_routes_async,
                )

                await self._ctx.add_init_script(DISABLE_DEVTOOL_GUARD_JS)
                await install_disable_devtool_routes_async(self._ctx)
            except Exception as e:
                logger.warning("disable-devtool guard failed: %s", e)
        self._page = self._ctx.pages[0] if self._ctx.pages else await self._ctx.new_page()
        self._profile_dir = profile_dir
        # 供 Worker 日志用
        self._stealth_summary = stealth_summary() if self.use_stealth else "关闭"

    def launch_config(self) -> dict[str, Any]:
        """当前启动参数快照（供 AI 决策 / 通关后回写实验室）。"""
        return {
            "use_stealth": bool(self.use_stealth),
            "headless": bool(self.headless),
            "browser_channel": self.browser_channel,
            "proxy": self.proxy or "",
            "profile_dir": self._profile_dir or self.profile_dir,
            "mode": (
                "拟真(stealth)"
                if self.use_stealth
                else "接近真实浏览器(无拟真注入)"
            ),
            "neutralize_devtools": bool(self.neutralize_devtools),
        }

    async def start(self) -> None:
        await self._launch(self.profile_dir)

    async def close(self) -> None:
        try:
            if self._ctx:
                await self._ctx.close()
        except Exception:
            pass
        try:
            if self._pw:
                await self._pw.stop()
        except Exception:
            pass
        self._ctx = self._pw = self._page = None

    async def restart(
        self,
        profile_dir: str | None = None,
        *,
        fresh_profile: bool = True,
        use_stealth: bool | None = None,
        headless: bool | None = None,
        browser_channel: str | None = None,
        proxy: str | None | object = ...,
        neutralize_devtools: bool | None = None,
    ) -> dict[str, Any]:
        """重启浏览器；可同时切换拟真/无头/通道/代理/反DevTools中和。"""
        if use_stealth is not None:
            self.use_stealth = bool(use_stealth)
        if headless is not None:
            self.headless = bool(headless)
        if browser_channel is not None and str(browser_channel).strip():
            self.browser_channel = normalize_browser_channel(browser_channel)
        if neutralize_devtools is not None:
            self.neutralize_devtools = bool(neutralize_devtools)
        # proxy: ... = 不改；None / "" = 清掉；字符串 = 新代理
        if proxy is not ...:
            p = (str(proxy).strip() if proxy is not None else "") or None
            self.proxy = p

        if profile_dir:
            target = profile_dir
        elif fresh_profile:
            import tempfile

            target = tempfile.mkdtemp(prefix="cb-agent-altprof-")
        else:
            # 保留档案但切换引擎时换对应目录，避免 chrome/chromium 档案混用
            target = agent_profile_dir_for_channel(self.browser_channel)
            os.makedirs(target, exist_ok=True)

        try:
            if self._ctx:
                await self._ctx.close()
        except Exception:
            pass
        try:
            self._ctx = self._page = None
            await self._launch(target)
        except Exception as e:
            return {
                "ok": False,
                "error": f"重启浏览器失败: {e}",
                "launch": self.launch_config(),
            }
        obs = await self.observe()
        obs["restarted"] = True
        obs["launch"] = self.launch_config()
        obs["hint"] = (
            "已按新启动参数打开浏览器。若仍失败，请再换一组参数"
            "（如关闭拟真 / 开拟真 / 换 chrome / 清档案）。"
        )
        return obs

    def profile_status(self) -> dict[str, Any]:
        d = self._profile_dir
        out: dict[str, Any] = {"ok": True, "profile_dir": d or ""}
        default = os.path.join(d, "Default") if d else ""
        try:
            history = os.path.join(default, "History")
            out["has_history"] = os.path.isfile(history) and os.path.getsize(history) > 0
        except Exception:
            out["has_history"] = False
        try:
            out["has_cookies"] = (
                os.path.isfile(os.path.join(default, "Cookies"))
                and os.path.getsize(os.path.join(default, "Cookies")) > 0
            )
        except Exception:
            out["has_cookies"] = False
        try:
            out["has_localstorage"] = os.path.isdir(os.path.join(default, "Local Storage"))
        except Exception:
            out["has_localstorage"] = False
        return out

    async def warm_up(self, sites: list[str] | None = None, hold_ms: int = 1500) -> dict[str, Any]:
        sites = sites or [
            "https://www.baidu.com/",
            "https://www.qq.com/",
            "https://cn.bing.com/",
        ]
        visited = []
        for s in sites:
            try:
                await self.navigate(s, timeout_ms=20_000)
                await asyncio.sleep(hold_ms / 1000.0)
            except Exception as e:
                visited.append({"url": s, "ok": False, "error": str(e)[:120]})
                continue
            obs = await self.observe()
            visited.append(
                {
                    "url": s,
                    "ok": True,
                    "title": obs.get("title"),
                    "text_chars": obs.get("text_chars"),
                }
            )
        return {
            "ok": True,
            "visited": visited,
            "profile": self.profile_status(),
            "hint": "档案已更新；可 restart/navigate 回目标站重试",
        }

    async def observe(self) -> dict[str, Any]:
        if not self._page:
            return {"ok": False, "error": "浏览器未启动"}
        title = ""
        url = ""
        text = ""
        try:
            title = (await self._page.title()).strip() or ""
        except Exception:
            pass
        try:
            url = self._page.url or ""
        except Exception:
            pass
        try:
            text = await self._page.evaluate(
                "() => document.body ? document.body.innerText : ''"
            )
        except Exception:
            pass
        return {
            "ok": True,
            "url": url,
            "title": _clip(title, 120),
            "text": _clip(text, self.max_text),
            "text_chars": len(text or ""),
            "launch": self.launch_config(),
        }

    async def navigate(self, target: str, timeout_ms: int = 45_000) -> dict[str, Any]:
        if not self._page:
            await self.start()
        if not target.startswith(("http://", "https://", "about:", "file:", "data:")):
            target = "https://" + target
        try:
            await self._page.goto(target, wait_until="domcontentloaded", timeout=timeout_ms)
        except Exception as e:
            obs = await self.observe()
            obs["error"] = f"goto 异常（可能超时或被拒）: {e}"
            return obs
        return await self.observe()

    async def reload(self) -> dict[str, Any]:
        try:
            if self._page:
                await self._page.reload(wait_until="domcontentloaded")
        except Exception as e:
            obs = await self.observe()
            obs["error"] = f"reload 异常: {e}"
            return obs
        return await self.observe()

    async def wait(self, ms: int) -> dict[str, Any]:
        await asyncio.sleep(max(0, int(ms)) / 1000.0)
        return {"ok": True, "waited_ms": int(ms)}

    async def wait_human(self, ms: int = 30_000) -> dict[str, Any]:
        """暂停让真人操作浏览器（点验证等），然后返回最新观测。"""
        ms = max(1000, min(int(ms), 180_000))
        await asyncio.sleep(ms / 1000.0)
        obs = await self.observe()
        obs["waited_for_human_ms"] = ms
        return obs

    async def screenshot(self, name: str = "") -> dict[str, Any]:
        if not self._page:
            return {"ok": False, "error": "浏览器未启动"}
        shots = os.path.join(get_app_root(), "data", "agent_shots")
        os.makedirs(shots, exist_ok=True)
        save = os.path.join(
            shots,
            f"{name or 'shot'}_{time.strftime('%H%M%S')}_{uuid.uuid4().hex[:6]}.png",
        )
        try:
            await self._page.screenshot(path=save, full_page=False)
        except Exception as e:
            return {"ok": False, "error": f"截图失败: {e}"}
        return {"ok": True, "path": save}

    async def cookie_summary(self) -> dict[str, Any]:
        try:
            cookies = await self._ctx.cookies()
        except Exception as e:
            return {"ok": False, "error": f"读取 Cookie 失败: {e}"}
        rows = []
        for c in cookies[:80]:
            rows.append(
                {
                    "name": c.get("name", ""),
                    "domain": c.get("domain", ""),
                    "len": len(c.get("value") or ""),
                }
            )
        return {"ok": True, "count": len(cookies), "cookies": rows}

    async def exec_js(self, code: str) -> dict[str, Any]:
        if not self._page:
            return {"ok": False, "error": "浏览器未启动"}
        src = str(code or "").strip()
        if not src:
            return {"ok": False, "error": "code 为空"}
        low = src.lower()
        if any(x in low for x in ("fetch(", "xmlhttprequest", "websocket(", "eval(")):
            return {"ok": False, "error": "禁止外联或 eval；只做页面内只读/环境探查"}
        try:
            result = await self._page.evaluate(src)
        except Exception as e:
            return {"ok": False, "error": f"JS 执行失败: {e}"}
        return {"ok": True, "result": _clip(str(result), 2000)}

    async def new_page(self) -> dict[str, Any]:
        self._page = await self._ctx.new_page()
        return await self.observe()


# ======================================================================
# 原子工具集
# ======================================================================


class GenericNavigateTool(BaseTool):
    def __init__(self, runtime: BrowserRuntime) -> None:
        super().__init__()
        self._rt = runtime

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="browser_navigate",
            description=(
                "让浏览器打开指定目标（也接受未写协议的裸域名，自动补 https://）。"
                "返回当前页的 url/title/text（页面可见文本，长度有限）/text_chars。"
                "text 是判断页面内容是否出现的核心证据。"
            ),
            actions=["goto"],
            tags=["browser", "observe"],
        )

    async def execute(self, action: str, **kwargs: Any) -> Any:
        if action != "goto":
            raise ValueError(f"Unknown action: {action}")
        return await self._rt.navigate(
            str(kwargs.get("url") or kwargs.get("target") or "").strip(),
            timeout_ms=int(kwargs.get("timeout_ms") or kwargs.get("timeout") or 45_000),
        )


class GenericObserveTool(BaseTool):
    def __init__(self, runtime: BrowserRuntime) -> None:
        super().__init__()
        self._rt = runtime

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="browser_observe",
            description=(
                "返回当前页面的实时状态：url、title、text（可见文本，长度有限）、"
                "text_chars。观察结果是你判断页面是否正常的唯一证据来源。"
            ),
            actions=["now"],
            tags=["browser", "observe"],
        )

    async def execute(self, action: str, **kwargs: Any) -> Any:
        if action != "now":
            raise ValueError(f"Unknown action: {action}")
        return await self._rt.observe()


class GenericWaitTool(BaseTool):
    def __init__(self, runtime: BrowserRuntime) -> None:
        super().__init__()
        self._rt = runtime

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="browser_wait",
            description=(
                "让页面保持当前状态并等待指定毫秒数。适合等待异步内容出现、"
                "跳转完成、或验证“不行动会怎样”。参数 ms 为正整数。"
            ),
            actions=["sleep"],
            tags=["browser", "wait"],
        )

    async def execute(self, action: str, **kwargs: Any) -> Any:
        if action != "sleep":
            raise ValueError(f"Unknown action: {action}")
        try:
            ms = int(kwargs.get("ms", kwargs.get("wait_ms", 1000)))
        except (TypeError, ValueError):
            ms = 1000
        return await self._rt.wait(ms)


class GenericWaitHumanTool(BaseTool):
    def __init__(self, runtime: BrowserRuntime) -> None:
        super().__init__()
        self._rt = runtime

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="browser_wait_human",
            description=(
                "暂停指定毫秒，留时间给真人在有头浏览器里手动操作（例如点击可见控件），"
                "然后返回最新页面观测。ms 默认 30000，上限 180000。"
                "当工具观测显示需要人工介入、而你又无法用脚本可靠完成时再用。"
            ),
            actions=["pause"],
            tags=["browser", "wait"],
        )

    async def execute(self, action: str, **kwargs: Any) -> Any:
        if action != "pause":
            raise ValueError(f"Unknown action: {action}")
        try:
            ms = int(kwargs.get("ms", 30_000))
        except (TypeError, ValueError):
            ms = 30_000
        return await self._rt.wait_human(ms)


class GenericReloadTool(BaseTool):
    def __init__(self, runtime: BrowserRuntime) -> None:
        super().__init__()
        self._rt = runtime

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="browser_reload",
            description="刷新当前页面，返回刷新后的观测（url/title/text）。",
            actions=["again"],
            tags=["browser", "observe"],
        )

    async def execute(self, action: str, **kwargs: Any) -> Any:
        if action != "again":
            raise ValueError(f"Unknown action: {action}")
        return await self._rt.reload()


class GenericScreenshotTool(BaseTool):
    def __init__(self, runtime: BrowserRuntime) -> None:
        super().__init__()
        self._rt = runtime

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="browser_screenshot",
            description=(
                "截取当前页面，返回 PNG 图片的绝对路径。作为可视化证据，"
                "适合在不能只靠文本判断时使用。name 可选，用于命名文件。"
            ),
            actions=["capture"],
            tags=["browser", "evidence"],
        )

    async def execute(self, action: str, **kwargs: Any) -> Any:
        if action != "capture":
            raise ValueError(f"Unknown action: {action}")
        return await self._rt.screenshot(str(kwargs.get("name") or "shot"))


class GenericCookieTool(BaseTool):
    def __init__(self, runtime: BrowserRuntime) -> None:
        super().__init__()
        self._rt = runtime

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="browser_cookies",
            description=(
                "返回浏览器当前持有的 Cookie 列表概要（name/domain/value长度）"
                "与总数。用于观察会话状态变化。"
            ),
            actions=["list"],
            tags=["browser", "session"],
        )

    async def execute(self, action: str, **kwargs: Any) -> Any:
        if action != "list":
            raise ValueError(f"Unknown action: {action}")
        return await self._rt.cookie_summary()


class GenericExecTool(BaseTool):
    def __init__(self, runtime: BrowserRuntime) -> None:
        super().__init__()
        self._rt = runtime

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="browser_exec",
            description=(
                "在当前页面上下文执行一段 JavaScript 表达式/函数体，返回求值结果"
                "（转为字符串，长度受限）。可用于读取页面内部状态、检查环境特征。"
                "禁止外联远程脚本与 eval，只做页面内最小探查。"
            ),
            actions=["run"],
            tags=["browser", "script"],
        )

    async def execute(self, action: str, **kwargs: Any) -> Any:
        if action != "run":
            raise ValueError(f"Unknown action: {action}")
        return await self._rt.exec_js(str(kwargs.get("code") or kwargs.get("js") or ""))


class GenericNewPageTool(BaseTool):
    def __init__(self, runtime: BrowserRuntime) -> None:
        super().__init__()
        self._rt = runtime

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="browser_new_page",
            description="新开一个空白标签页，并让后续操作切换到它；返回新页观测。",
            actions=["open"],
            tags=["browser"],
        )

    async def execute(self, action: str, **kwargs: Any) -> Any:
        if action != "open":
            raise ValueError(f"Unknown action: {action}")
        return await self._rt.new_page()


class GenericRestartTool(BaseTool):
    def __init__(self, runtime: BrowserRuntime) -> None:
        super().__init__()
        self._rt = runtime

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="browser_restart",
            description=(
                "重启浏览器并可选切换启动策略（不要死磕同一配置）。\n"
                "action=new_identity：清档案换新身份，其它启动参数不变。\n"
                "action=reconfigure：可改 use_stealth / headless / browser_channel / "
                "proxy / fresh_profile / neutralize_devtools。\n"
                "策略建议：卡住时可试 use_stealth=false（接近实验室「真实浏览器」、无拟真注入）；"
                "或 use_stealth=true + channel=chrome；或 fresh_profile=true 清 Cookie；"
                "闪一下变空白时 neutralize_devtools=true。"
            ),
            actions=["new_identity", "reconfigure"],
            tags=["browser", "session", "strategy"],
        )

    async def execute(self, action: str, **kwargs: Any) -> Any:
        if action == "new_identity":
            return await self._rt.restart(profile_dir=kwargs.get("profile_dir"))
        if action == "reconfigure":
            fresh = kwargs.get("fresh_profile")
            if fresh is None:
                fresh = True
            proxy_raw = kwargs.get("proxy", ...)
            return await self._rt.restart(
                profile_dir=kwargs.get("profile_dir"),
                fresh_profile=bool(fresh),
                use_stealth=(
                    bool(kwargs["use_stealth"])
                    if "use_stealth" in kwargs and kwargs["use_stealth"] is not None
                    else None
                ),
                headless=(
                    bool(kwargs["headless"])
                    if "headless" in kwargs and kwargs["headless"] is not None
                    else None
                ),
                browser_channel=kwargs.get("browser_channel"),
                proxy=proxy_raw,
                neutralize_devtools=(
                    bool(kwargs["neutralize_devtools"])
                    if "neutralize_devtools" in kwargs
                    and kwargs["neutralize_devtools"] is not None
                    else None
                ),
            )
        raise ValueError(f"Unknown action: {action}")


class GenericWarmupTool(BaseTool):
    def __init__(self, runtime: BrowserRuntime) -> None:
        super().__init__()
        self._rt = runtime

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="browser_warmup",
            description=(
                "让浏览器先依次访问几个真实网站(百度/腾讯/必应)各停留约1.5秒，"
                "在当前档案里制造浏览历史与 cookie，模拟“用了一段日子的老用户”。"
                "之后再 restart 或 navigate 回目标站。返回每个站的访问结果与档案状态。"
            ),
            actions=["seed"],
            tags=["browser", "profile"],
        )

    async def execute(self, action: str, **kwargs: Any) -> Any:
        if action != "seed":
            raise ValueError(f"Unknown action: {action}")
        return await self._rt.warm_up(
            sites=None, hold_ms=int(kwargs.get("hold_ms") or 1500)
        )


def build_browser_tools(runtime: BrowserRuntime) -> list[BaseTool]:
    return [
        GenericNavigateTool(runtime),
        GenericObserveTool(runtime),
        GenericReloadTool(runtime),
        GenericWaitTool(runtime),
        GenericWaitHumanTool(runtime),
        GenericScreenshotTool(runtime),
        GenericCookieTool(runtime),
        GenericExecTool(runtime),
        GenericNewPageTool(runtime),
        GenericRestartTool(runtime),
        GenericWarmupTool(runtime),
    ]


# ======================================================================
# Agent
# ======================================================================


def build_agent_system_prompt(extra_context: str = "") -> str:
    base = GENERAL_SYSTEM_PROMPT
    extra = (extra_context or "").strip()
    return base + (("\n\n【用户附加上下文】\n" + extra) if extra else "")


class BrowserAgent(Agent):
    """完全通用的浏览器 Agent — 只做闭环求解，不带任何领域结论。"""

    def __init__(
        self,
        *args: Any,
        cancel_check: Callable[[], bool] | None = None,
        on_step: Callable[[str], None] | None = None,
        extra_context: str = "",
        **kwargs: Any,
    ) -> None:
        kwargs.setdefault("system_prompt", build_agent_system_prompt(extra_context))
        kwargs.setdefault("verbose", False)
        super().__init__(*args, **kwargs)
        self._cancel_check = cancel_check or (lambda: False)
        self._on_step = on_step
        self._call_count = 0

    def _emit(self, msg: str) -> None:
        if self._on_step:
            try:
                self._on_step(msg)
            except Exception:
                pass

    def _build_tool_schemas(self) -> list[dict[str, Any]]:
        schemas: list[dict[str, Any]] = []
        for name in self._tools.list_tools():
            tool = self._tools.get(name)
            if not tool:
                continue
            props: dict[str, Any] = {
                "action": {
                    "type": "string",
                    "enum": tool.metadata.actions,
                    "description": f"操作，取值之一: {tool.metadata.actions}",
                },
            }
            required = ["action"]
            if name == "browser_navigate":
                props.update(
                    {
                        "url": {"type": "string", "description": "要打开的地址"},
                        "timeout_ms": {
                            "type": "integer",
                            "description": "超时毫秒（默认45000）",
                        },
                    }
                )
                required += ["url"]
            elif name == "browser_wait":
                props["ms"] = {"type": "integer", "description": "等待毫秒数"}
                required += ["ms"]
            elif name == "browser_wait_human":
                props["ms"] = {
                    "type": "integer",
                    "description": "留给真人操作的毫秒（默认30000）",
                }
            elif name == "browser_screenshot":
                props["name"] = {"type": "string", "description": "截图文件名（可选）"}
            elif name == "browser_exec":
                props["code"] = {
                    "type": "string",
                    "description": "要执行的 JS 表达式/函数体",
                }
                required += ["code"]
            elif name == "browser_warmup":
                props["hold_ms"] = {
                    "type": "integer",
                    "description": "每站停留毫秒（默认1500）",
                }
            elif name == "browser_restart":
                props["profile_dir"] = {
                    "type": "string",
                    "description": "新档案目录路径（可选；缺省按 fresh_profile 决定）",
                }
                props["use_stealth"] = {
                    "type": "boolean",
                    "description": (
                        "是否拟真注入。true≈实验室普通模式；"
                        "false≈接近「真实浏览器」(无拟真)。reconfigure 时用"
                    ),
                }
                props["headless"] = {
                    "type": "boolean",
                    "description": "是否无头。有验证码时建议 false",
                }
                props["browser_channel"] = {
                    "type": "string",
                    "enum": ["chrome", "chromium"],
                    "description": "浏览器引擎。强检测站优先 chrome",
                }
                props["proxy"] = {
                    "type": "string",
                    "description": (
                        "HTTP 代理如 http://127.0.0.1:8083；"
                        "传空字符串表示取消代理。省略则不改"
                    ),
                }
                props["fresh_profile"] = {
                    "type": "boolean",
                    "description": "true=全新临时档案；false=沿用对应引擎持久档案。默认 true",
                }
                props["neutralize_devtools"] = {
                    "type": "boolean",
                    "description": (
                        "是否中和页面反 DevTools（disable-devtool 等）。"
                        "true=拦截/替换防闪白；false=保留站点反调试。"
                        "与实验室「反调试」勾选对应"
                    ),
                }
            schemas.append(
                {
                    "name": name,
                    "description": tool.metadata.description,
                    "input_schema": {
                        "type": "object",
                        "properties": props,
                        "required": required,
                    },
                }
            )
        return schemas

    async def run(self, goal: str) -> str:
        if self._cancel_check():
            raise RuntimeError("已取消")
        system = self._build_system_prompt()
        messages: list[dict[str, Any]] = [{"role": "user", "content": goal}]
        tools = self._build_tool_schemas()
        await self._tools.initialize_all()

        for step in range(1, self.max_steps + 1):
            if self._cancel_check():
                await self._tools.shutdown_all()
                raise RuntimeError("已取消")
            self._emit(f"[step {step}] 思考…")
            try:
                response = await self._call_llm(system, messages, tools)
            except Exception as e:
                logger.error("LLM call failed at step %d: %s", step, e)
                self._emit(f"[step {step}] API 错误，重试: {e}")
                await asyncio.sleep(2)
                if self._cancel_check():
                    await self._tools.shutdown_all()
                    raise RuntimeError("已取消")
                continue

            thought, tool_calls, _stop = self._parse(response)
            messages.append({"role": "assistant", "content": response.get("content", [])})

            if not tool_calls:
                self._emit(f"[step {step}] 完成")
                await self._tools.shutdown_all()
                return thought or "任务完成。"

            results = []
            for tc in tool_calls:
                if self._cancel_check():
                    await self._tools.shutdown_all()
                    raise RuntimeError("已取消")
                name, inputs = tc.get("name", ""), tc.get("input", {}) or {}
                action = str(inputs.get("action") or "")
                self._call_count += 1
                self._emit(f"[step {step}] 🔧 {name}.{action}")
                res = await self._execute(name, action, inputs)
                preview = res.replace("\n", " ")[:200]
                self._emit(f"  → {preview}")
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tc.get("id", ""),
                        "content": res,
                    }
                )
            messages.append({"role": "user", "content": results})

        await self._tools.shutdown_all()
        return (
            "已达最大步数仍未收工。请把最终 JSON 里的 reached 置 false，"
            "并在 evidence 里如实写出已尝试的路径与卡点。"
        )


# ======================================================================
# Worker
# ======================================================================


def _proxy_url(cfg: dict) -> str | None:
    if not cfg.get("use_http_proxy"):
        return None
    p = str(cfg.get("http_proxy") or "").strip()
    if not p:
        return None
    return p if p.startswith("http") else f"http://{p}"


class BrowserAgentWorker(QThread):
    log = pyqtSignal(str)
    finished_ok = pyqtSignal(str)
    failed = pyqtSignal(str)

    def __init__(
        self,
        goal: str = "",
        url: str = "",
        *,
        cfg: dict | None = None,
        headless: bool = False,
        browser_channel: str = "chromium",
        use_stealth: bool = True,
        browser_proxy: str | None = None,
        profile_dir: str | None = None,
        extra_context: str = "",
        neutralize_devtools: bool = False,
        parent=None,
    ):
        super().__init__(parent)
        self.goal = (goal or "").strip()
        self.url = (url or "").strip()
        self.cfg = dict(cfg or load_ai_config())
        self.headless = bool(headless)
        self.browser_channel = normalize_browser_channel(browser_channel)
        self.use_stealth = bool(use_stealth)
        self.browser_proxy = (browser_proxy or "").strip() or None
        self.profile_dir = profile_dir
        self.extra_context = (extra_context or "").strip()
        self.neutralize_devtools = bool(neutralize_devtools)
        self._cancelled = False
        self.last_launch: dict = {}

    def cancel(self) -> None:
        self._cancelled = True

    async def _run_async(self) -> str:
        base = resolve_agent_base_url(self.cfg)
        model = str(self.cfg.get("model") or "deepseek-chat").strip()
        try:
            max_steps = max(3, min(int(self.cfg.get("agent_max_steps") or 40), 80))
        except (TypeError, ValueError):
            max_steps = 40

        from core.agent_runner import ProxiedLLMClient

        llm = ProxiedLLMClient(
            api_key=str(self.cfg.get("api_key") or "").strip(),
            base_url=base,
            model=model,
            max_tokens=4096,
            temperature=0.2,
            timeout=180.0,
            proxy=_proxy_url(self.cfg),
            ai_cfg=self.cfg,
        )

        goal = self.goal or _DEFAULT_GOAL_TPL.format(url=self.url or "目标地址")
        profile = self.profile_dir or agent_profile_dir_for_channel(self.browser_channel)
        runtime = BrowserRuntime(
            profile_dir=profile,
            headless=self.headless,
            proxy=self.browser_proxy,
            browser_channel=self.browser_channel,
            use_stealth=self.use_stealth,
            neutralize_devtools=self.neutralize_devtools,
        )
        await runtime.start()
        self.last_launch = runtime.launch_config()
        self.log.emit(
            f"浏览器已启动 · {channel_label(self.browser_channel)} · "
            f"无头={runtime.headless} · 拟真={getattr(runtime, '_stealth_summary', '')} · "
            f"反DevTools中和={runtime.neutralize_devtools}"
        )
        self.log.emit(f"档案: {runtime.profile_dir}")
        self.log.emit(
            "提示: 卡住时可 browser_restart.reconfigure 切换拟真/"
            "通道/清档案/neutralize_devtools(反DevTools中和)"
        )
        if self.browser_proxy:
            self.log.emit(f"浏览器代理: {self.browser_proxy}")
        self.log.emit(f"模型: {model} · 步数上限: {max_steps} · 模式: 完全通用")

        agent = BrowserAgent(
            llm=llm,
            max_steps=max_steps,
            cancel_check=lambda: self._cancelled,
            on_step=lambda m: self.log.emit(m),
            extra_context=self.extra_context,
        )
        for tool in build_browser_tools(runtime):
            agent.register_tool(tool)

        try:
            result = await agent.run(goal)
            self.last_launch = runtime.launch_config()
        finally:
            await runtime.close()
        if self._cancelled:
            raise RuntimeError("已取消")
        self.log.emit(f"工具调用次数: {agent._call_count}")
        return result

    def run(self) -> None:
        try:
            api_key = str(self.cfg.get("api_key") or "").strip()
            if not api_key:
                self.failed.emit("请先在「配置」填写 API Key")
                return
            self.log.emit("启动通用浏览器 Agent …")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(self._run_async())
            finally:
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                except Exception:
                    pass
                loop.close()
            self.finished_ok.emit(result)
        except RuntimeError as e:
            msg = str(e)
            if "已取消" in msg or self._cancelled:
                self.failed.emit("已取消")
            else:
                self.failed.emit(msg)
        except Exception as e:
            logger.exception("BrowserAgentWorker failed")
            self.failed.emit(str(e))
