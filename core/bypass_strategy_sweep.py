"""环境绕过：全量启动策略扫描（挨个测一遍）。

不依赖模型自己「想起来」换参；由密桥按预设矩阵切换
use_stealth / neutralize_devtools / channel / fresh_profile / warmup / proxy，
每套打开目标 URL、观测页面，打分后汇总。
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable

from core.ai_config import normalize_browser_channel
from core.playwright_env import channel_label

logger = logging.getLogger(__name__)

# 强失败信号（标题/正文/URL 命中即判 fail）
_FAIL_MARKERS = (
    "about:blank",
    "just a moment",
    "checking your browser",
    "attention required",
    "access denied",
    "cf-browser-verification",
    "challenge-platform",
    "enable javascript and cookies",
    "请开启javascript",
    "安全验证",
    "人机验证",
    "访问频率过高",
    "请求被拒绝",
    "403 forbidden",
    "502 bad gateway",
    "503 service",
)

LogFn = Callable[[str], None]
CancelFn = Callable[[], bool]


def build_strategy_matrix(
    *,
    base_channel: str = "chrome",
    proxy: str | None = None,
) -> list[dict[str, Any]]:
    """生成有序策略表（去重后约 8～14 项，覆盖常用防检测开关组合）。"""
    base_ch = normalize_browser_channel(base_channel)
    alt_channels: list[str] = []
    for c in ("chrome", "msedge", "chromium"):
        if c != base_ch:
            alt_channels.append(c)

    rows: list[dict[str, Any]] = [
        {
            "id": "stealth",
            "label": "拟真注入",
            "use_stealth": True,
            "neutralize_devtools": False,
            "fresh_profile": False,
            "warmup": False,
            "clear_proxy": False,
            "browser_channel": base_ch,
        },
        {
            "id": "stealth_anti_dt",
            "label": "拟真 + 反DevTools中和",
            "use_stealth": True,
            "neutralize_devtools": True,
            "fresh_profile": False,
            "warmup": False,
            "clear_proxy": False,
            "browser_channel": base_ch,
        },
        {
            "id": "real",
            "label": "真实浏览器（无拟真）",
            "use_stealth": False,
            "neutralize_devtools": False,
            "fresh_profile": False,
            "warmup": False,
            "clear_proxy": False,
            "browser_channel": base_ch,
        },
        {
            "id": "real_anti_dt",
            "label": "真实浏览器 + 反DevTools中和",
            "use_stealth": False,
            "neutralize_devtools": True,
            "fresh_profile": False,
            "warmup": False,
            "clear_proxy": False,
            "browser_channel": base_ch,
        },
        {
            "id": "stealth_warmup",
            "label": "拟真 + 档案预热（百度/腾讯/必应）",
            "use_stealth": True,
            "neutralize_devtools": True,
            "fresh_profile": False,
            "warmup": True,
            "clear_proxy": False,
            "browser_channel": base_ch,
        },
        {
            "id": "stealth_fresh",
            "label": "拟真 + 清档案",
            "use_stealth": True,
            "neutralize_devtools": True,
            "fresh_profile": True,
            "warmup": False,
            "clear_proxy": False,
            "browser_channel": base_ch,
        },
        {
            "id": "real_fresh",
            "label": "真实浏览器 + 清档案",
            "use_stealth": False,
            "neutralize_devtools": True,
            "fresh_profile": True,
            "warmup": False,
            "clear_proxy": False,
            "browser_channel": base_ch,
            "cdp_attach": False,
        },
        {
            "id": "cdp_edge",
            "label": "系统浏览器 + CDP · Edge",
            "use_stealth": False,
            "neutralize_devtools": False,
            "fresh_profile": False,
            "warmup": False,
            "clear_proxy": False,
            "browser_channel": "msedge",
            "cdp_attach": True,
        },
        {
            "id": "cdp_chrome",
            "label": "系统浏览器 + CDP · Chrome",
            "use_stealth": False,
            "neutralize_devtools": False,
            "fresh_profile": False,
            "warmup": False,
            "clear_proxy": False,
            "browser_channel": "chrome",
            "cdp_attach": True,
        },
    ]

    # 给早期非 CDP 行补默认 cdp_attach=false
    for r in rows:
        r.setdefault("cdp_attach", False)

    # 换通道：对核心 4 组再测一次备选浏览器
    for alt in alt_channels[:2]:  # 最多再测 2 个通道，避免过久
        for src_id, label_suffix in (
            ("stealth_anti_dt", "拟真+反DT"),
            ("real", "真实浏览器"),
        ):
            rows.append(
                {
                    "id": f"{src_id}_{alt}",
                    "label": f"{label_suffix} · {channel_label(alt)}",
                    "use_stealth": src_id.startswith("stealth"),
                    "neutralize_devtools": src_id != "real",
                    "fresh_profile": False,
                    "warmup": False,
                    "clear_proxy": False,
                    "browser_channel": alt,
                    "cdp_attach": False,
                }
            )
    # 若初始走了代理：额外测「直连」两组（代理本身也可能触发风控）
    if (proxy or "").strip():
        rows.append(
            {
                "id": "stealth_direct",
                "label": "拟真 + 直连（关解密代理）",
                "use_stealth": True,
                "neutralize_devtools": True,
                "fresh_profile": False,
                "warmup": False,
                "clear_proxy": True,
                "browser_channel": base_ch,
                "cdp_attach": False,
            }
        )
        rows.append(
            {
                "id": "real_direct",
                "label": "真实浏览器 + 直连（关解密代理）",
                "use_stealth": False,
                "neutralize_devtools": False,
                "fresh_profile": False,
                "warmup": False,
                "clear_proxy": True,
                "browser_channel": base_ch,
                "cdp_attach": False,
            }
        )
        rows.append(
            {
                "id": "cdp_edge_direct",
                "label": "系统浏览器 + CDP · Edge · 直连",
                "use_stealth": False,
                "neutralize_devtools": False,
                "fresh_profile": False,
                "warmup": False,
                "clear_proxy": True,
                "browser_channel": "msedge",
                "cdp_attach": True,
            }
        )

    # 去重（id）
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for r in rows:
        rid = str(r.get("id") or "")
        if not rid or rid in seen:
            continue
        seen.add(rid)
        out.append(r)
    return out


def score_observation(obs: dict[str, Any] | None) -> dict[str, Any]:
    """根据页面观测打分：fail / soft_pass / pass。"""
    obs = obs if isinstance(obs, dict) else {}
    url = str(obs.get("url") or "")
    title = str(obs.get("title") or "")
    text = str(obs.get("text") or "")
    chars = int(obs.get("text_chars") or len(text) or 0)
    err = str(obs.get("error") or "").strip()
    blob = f"{url}\n{title}\n{text}".lower()

    reasons: list[str] = []
    if err:
        reasons.append(f"导航异常: {err[:80]}")
    if not url or url.startswith("about:blank"):
        reasons.append("空白页 about:blank")
    for m in _FAIL_MARKERS:
        if m in blob:
            reasons.append(f"命中拦截特征: {m}")
            break
    if chars < 60:
        reasons.append(f"正文过短({chars}字)")

    if reasons:
        return {
            "verdict": "fail",
            "score": max(0, 20 - 5 * len(reasons)),
            "reasons": reasons,
            "text_chars": chars,
            "title": title[:80],
            "url": url[:160],
        }

    # 无明显失败信号
    if chars >= 400:
        verdict, score = "pass", 90
    elif chars >= 120:
        verdict, score = "soft_pass", 65
    else:
        verdict, score = "soft_pass", 50
        reasons.append("正文偏短，建议人工确认")

    return {
        "verdict": verdict,
        "score": score,
        "reasons": reasons,
        "text_chars": chars,
        "title": title[:80],
        "url": url[:160],
    }


def _pick_best(results: list[dict[str, Any]]) -> dict[str, Any] | None:
    order = {"pass": 0, "soft_pass": 1, "fail": 2, "error": 3}
    ranked = sorted(
        results,
        key=lambda r: (
            order.get(str(r.get("verdict") or "error"), 9),
            -int(r.get("score") or 0),
        ),
    )
    return ranked[0] if ranked else None


async def run_strategy_sweep(
    *,
    url: str,
    headless: bool = False,
    base_channel: str = "chrome",
    use_stealth: bool = True,
    neutralize_devtools: bool = False,
    proxy: str | None = None,
    settle_ms: int = 2800,
    on_log: LogFn | None = None,
    cancel_check: CancelFn | None = None,
) -> dict[str, Any]:
    """按矩阵逐项测目标 URL，返回汇总 JSON 可序列化结构。"""
    from core.browser_agent import BrowserRuntime, agent_profile_dir_for_channel

    url = (url or "").strip()
    if not url:
        return {"ok": False, "error": "缺少目标 URL", "results": []}

    def log(msg: str) -> None:
        if on_log:
            try:
                on_log(msg)
            except Exception:
                pass

    matrix = build_strategy_matrix(base_channel=base_channel, proxy=proxy)
    log(f"全量策略扫描：共 {len(matrix)} 组，目标 {url}")

    runtime = BrowserRuntime(
        profile_dir=agent_profile_dir_for_channel(base_channel),
        headless=headless,
        proxy=proxy,
        browser_channel=base_channel,
        use_stealth=use_stealth,
        neutralize_devtools=neutralize_devtools,
    )
    results: list[dict[str, Any]] = []
    started = False

    try:
        for i, strat in enumerate(matrix, 1):
            if cancel_check and cancel_check():
                log("全量扫描已取消")
                break

            label = str(strat.get("label") or strat.get("id"))
            ch = normalize_browser_channel(strat.get("browser_channel") or base_channel)
            want_stealth = bool(strat.get("use_stealth"))
            want_anti = bool(strat.get("neutralize_devtools"))
            fresh = bool(strat.get("fresh_profile"))
            clear_proxy = bool(strat.get("clear_proxy"))
            do_warmup = bool(strat.get("warmup"))
            want_cdp = bool(strat.get("cdp_attach"))
            prox = None if clear_proxy else proxy
            if want_cdp:
                want_stealth = False
                want_anti = False
                if ch not in ("msedge", "chrome"):
                    ch = "msedge"

            log(
                f"[{i}/{len(matrix)}] {label} · "
                f"拟真={want_stealth} · 反DT={want_anti} · "
                f"{'CDP·' if want_cdp else ''}{channel_label(ch)} · 清档案={fresh} · "
                f"代理={'关' if clear_proxy else ('开' if prox else '无')}"
            )

            row: dict[str, Any] = {
                "id": strat.get("id"),
                "label": label,
                "strategy": {
                    "use_stealth": want_stealth,
                    "neutralize_devtools": want_anti,
                    "browser_channel": ch,
                    "fresh_profile": fresh,
                    "warmup": do_warmup,
                    "proxy": prox or "",
                    "cdp_attach": want_cdp,
                },
            }

            try:
                if not started:
                    runtime.use_stealth = want_stealth
                    runtime.neutralize_devtools = want_anti
                    runtime.browser_channel = ch
                    runtime.proxy = prox
                    runtime.cdp_attach = want_cdp
                    from core.browser_agent import agent_profile_dir_for_cdp

                    runtime.profile_dir = (
                        agent_profile_dir_for_cdp()
                        if want_cdp
                        else agent_profile_dir_for_channel(ch)
                    )
                    await runtime.start()
                    started = True
                    if fresh:
                        # 首项就要清档案：重启到临时目录
                        await runtime.restart(
                            fresh_profile=True,
                            use_stealth=want_stealth,
                            neutralize_devtools=want_anti,
                            browser_channel=ch,
                            proxy=prox,
                            cdp_attach=want_cdp,
                        )
                else:
                    # 每项显式写入 proxy（None=直连），避免上一组「清代理」粘住
                    await runtime.restart(
                        fresh_profile=fresh,
                        use_stealth=want_stealth,
                        neutralize_devtools=want_anti,
                        browser_channel=ch,
                        proxy=prox,
                        cdp_attach=want_cdp,
                    )
                if do_warmup:
                    log("  → 档案预热中…")
                    await runtime.warm_up()

                obs = await runtime.navigate(url)
                await runtime.wait(settle_ms)
                obs = await runtime.observe()
                scored = score_observation(obs)
                row.update(scored)
                row["launch"] = runtime.launch_config()
                row["obs_error"] = str(obs.get("error") or "")
            except Exception as e:
                logger.exception("strategy sweep item failed: %s", label)
                row.update(
                    {
                        "verdict": "error",
                        "score": 0,
                        "reasons": [str(e)[:160]],
                        "text_chars": 0,
                        "title": "",
                        "url": "",
                        "launch": runtime.launch_config() if started else {},
                    }
                )

            results.append(row)
            log(
                f"  → {row.get('verdict')} · score={row.get('score')} · "
                f"标题={row.get('title') or '-'} · "
                f"{';'.join(row.get('reasons') or []) or '无明显失败信号'}"
            )

            # 明确通关即停，不必跑完剩余矩阵
            if str(row.get("verdict") or "") == "pass":
                skipped = len(matrix) - i
                log(
                    f"已通关「{label}」，提前结束扫描"
                    + (f"（跳过剩余 {skipped} 组）" if skipped > 0 else "")
                )
                break

    finally:
        try:
            await runtime.close()
        except Exception:
            pass

    best = _pick_best(results)
    early_stop = bool(
        best
        and best.get("verdict") == "pass"
        and len(results) < len(matrix)
    )
    summary_lines = []
    for r in results:
        summary_lines.append(
            f"- [{r.get('verdict')}] {r.get('label')} (score={r.get('score')})"
        )
    if early_stop:
        summary_lines.append(
            f"（提前结束：已 pass，未测剩余 {len(matrix) - len(results)} 组）"
        )
    advice = "扫描无有效结果"
    if best:
        if best.get("verdict") == "pass":
            advice = (
                f"策略「{best.get('label')}」已通关"
                + ("，扫描已提前结束。" if early_stop else "。")
                + "可直接同步到实验室使用。"
            )
        else:
            advice = (
                "已测启动策略（含系统浏览器+CDP）。"
                "若最佳为 soft_pass，建议用人眼确认或再开「开始通关」细测；"
                "验证码类仍需手动点击。"
            )
    return {
        "ok": True,
        "mode": "strategy_sweep",
        "url": url,
        "total": len(results),
        "matrix_size": len(matrix),
        "early_stop": early_stop,
        "results": results,
        "best": best,
        "summary": "\n".join(summary_lines),
        "recommended_launch": (best or {}).get("launch") or {},
        # 仅明确 pass 才标 reached，避免 soft_pass 误触发「通关成功」弹窗
        "reached": bool(best and best.get("verdict") == "pass"),
        "goal": f"扫描目标页能否正常打开：{url}",
        "reason": _sweep_reason(best, results),
        "evidence": _sweep_evidence(best),
        "advice": advice,
        "browser_opts": _launch_to_browser_opts((best or {}).get("launch") or {}),
    }


def _sweep_evidence(best: dict | None) -> str:
    if not best:
        return "暂无可用策略结果"
    label = str(best.get("label") or best.get("id") or "未命名")
    title = str(best.get("title") or "").strip()
    verd = _verdict_zh(str(best.get("verdict") or ""))
    bit = f"最佳策略「{label}」→ {verd}"
    if title:
        bit += f"，页面标题「{title}」"
    return bit


def _verdict_zh(verdict: str) -> str:
    return {
        "pass": "通过",
        "soft_pass": "勉强可用",
        "fail": "失败",
        "error": "出错",
    }.get((verdict or "").strip().lower(), verdict or "未知")


def _sweep_reason(best: dict | None, results: list[dict]) -> str:
    """扫描汇总：过了/过不了的原因（给人看 + 给后续 Agent）。"""
    if not best:
        return "策略扫描没有得到有效结果，暂时无法判断能否通关。"
    verdict = str(best.get("verdict") or "")
    label = str(best.get("label") or best.get("id") or "")
    reasons = best.get("reasons") if isinstance(best.get("reasons"), list) else []
    reason_txt = "；".join(str(x) for x in reasons if x)
    n = len(results)
    if verdict == "pass":
        base = (
            f"已通关。采用「{label}」时页面能正常打开，"
            f"标题/正文未见拦截特征。"
        )
        if reason_txt and reason_txt != "无明显失败信号":
            base += f"补充：{reason_txt}。"
        if n <= 1:
            base += "本组策略已可用，未再试其余组合。"
        else:
            base += f"共试了 {n} 组，通关后提前结束。"
        return base
    if verdict == "soft_pass":
        base = (
            f"尚未完全通关。「{label}」相对最好，但建议再人工看一眼页面。"
        )
        if reason_txt:
            base += f"依据：{reason_txt}。"
        return base
    base = (
        f"尚未通关。目前最好的「{label}」仍是{_verdict_zh(verdict)}。"
        f"已试 {n} 组，都还不够稳。"
    )
    if reason_txt:
        base += f"卡点：{reason_txt}。"
    return base


def _launch_to_browser_opts(launch: dict) -> dict:
    if not isinstance(launch, dict) or not launch:
        return {}
    opts: dict[str, Any] = {
        "prefer_stealth": bool(launch.get("use_stealth", True)),
        "record_mode": True,
    }
    ch = str(launch.get("browser_channel") or "").strip().lower()
    if ch in ("chrome", "chromium", "msedge"):
        opts["browser_channel"] = ch
    if "neutralize_devtools" in launch:
        opts["anti_debug"] = bool(launch.get("neutralize_devtools"))
    if launch.get("cdp_attach"):
        opts["cdp_attach"] = True
        opts["prefer_stealth"] = False
        opts["cdp_browser"] = ch if ch in ("msedge", "chrome") else "msedge"
    else:
        opts["cdp_attach"] = False
    return opts


def format_sweep_extra_context(sweep: dict[str, Any]) -> str:
    """给后续通关 Agent 的附加上下文。"""
    best = sweep.get("best") if isinstance(sweep.get("best"), dict) else {}
    lines = [
        "【全量策略扫描已完成 — 勿再机械重扫矩阵】",
        f"共测 {sweep.get('total')} 组。汇总：",
        str(sweep.get("summary") or ""),
        "",
        f"推荐策略: {best.get('label')} → verdict={best.get('verdict')} "
        f"score={best.get('score')}",
        f"launch={best.get('launch') or sweep.get('recommended_launch')}",
        "请从推荐策略继续交互验证；仅在推荐仍失败时再换 1～2 组未试交互手段"
        "（如 wait_human 点验证码、或 cdp_attach 系统浏览器+CDP），不要重复扫完全表。",
        "最终 JSON 必填 reason：说明为什么过了或为什么过不了。",
    ]
    return "\n".join(lines)
