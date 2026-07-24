"""代理启动前检查与失败提示 — 端口 / 证书 / 角色 / 匹配."""

from __future__ import annotations

import os
import socket
from typing import Any

import yaml

from core.cert_helper import is_cert_trusted, mitmproxy_cert_path
from core.paths import get_app_root

PROFILES_DIR = os.path.join(get_app_root(), "profiles")


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """检测本地端口是否已有进程在监听."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.4)
            return s.connect_ex((host, int(port))) == 0
    except OSError:
        return False


def port_in_use_message(port: int, role_label: str = "代理") -> str:
    return (
        f"{role_label}端口 {port} 已被占用。\n\n"
        f"请：\n"
        f"1. 在左侧改用其他端口，或\n"
        f"2. 结束占用该端口的进程（任务管理器 / netstat -ano | findstr {port}）\n"
        f"3. 确认没有重复启动了多个解密/加密端"
    )


def load_profile(profile: str) -> dict[str, Any]:
    if not profile:
        return {}
    path = os.path.join(PROFILES_DIR, f"{profile}.yaml")
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def profile_roles(profile: str) -> list[str] | None:
    """返回 roles 列表。None = 配置缺失按默认两端；[] = 显式空."""
    cfg = load_profile(profile)
    if not cfg:
        return None
    if "roles" not in cfg:
        return None
    roles = cfg.get("roles")
    if roles is None:
        return None
    if isinstance(roles, str):
        return [roles]
    return list(roles)


def check_roles(profile: str, role: str) -> tuple[bool, str]:
    """(ok, message). role: decrypt | encrypt."""
    role_cn = "解密" if role == "decrypt" else "加密"
    roles = profile_roles(profile)
    if roles is None:
        return True, ""
    if not roles:
        return False, (
            f"项目「{profile}」的 roles 为空，无法启动{role_cn}端。\n\n"
            f"请：\n"
            f"1. 编辑 profiles/{profile}.yaml，设置 roles: [decrypt, encrypt]\n"
            f"2. 或删除项目后重新「新建」并勾选角色"
        )
    if role not in roles:
        return False, (
            f"项目「{profile}」仅配置了 {roles}，没有{role_cn}端。\n\n"
            f"请：\n"
            f"1. 换一个含「{role}」角色的项目，或\n"
            f"2. 编辑 profiles/{profile}.yaml 的 roles，加入 {role}"
        )
    return True, ""


def check_cert_before_decrypt() -> tuple[str, str]:
    """
    返回 (level, message)。
    level: ok | warn | block
    """
    if is_cert_trusted():
        return "ok", ""
    if os.path.isfile(mitmproxy_cert_path()):
        return "warn", (
            "HTTPS 证书尚未安装到系统信任区。\n\n"
            "不安装时：HTTPS 站点会握手失败，浏览器报证书错误。\n\n"
            "请：\n"
            "1. 左侧解密端点「证书」，或「设置 → 安装 HTTPS 证书」\n"
            "2. 安装后完全退出并重启浏览器\n"
            "3. 代理指向解密端后访问 https://mitm.it 验证\n\n"
            "仍要继续启动解密端吗？"
        )
    return "warn", (
        "尚未生成 mitmproxy 根证书。\n\n"
        "首次启动解密端会自动生成证书文件；HTTPS 抓包前仍需点「证书」安装。\n\n"
        "继续启动吗？"
    )


def format_match_summary(match: dict[str, Any] | None) -> str:
    if not match:
        return "未配置 match（将处理全部请求）"
    hosts = match.get("host") or ["*"]
    paths = match.get("path") or ["*"]
    methods = match.get("methods") or ["*"]
    return (
        f"Host={','.join(str(h) for h in hosts)} | "
        f"Path={','.join(str(p) for p in paths)} | "
        f"Methods={','.join(str(m) for m in methods)}"
    )


def match_startup_tips(profile: str) -> list[str]:
    """启动时写入日志的匹配提示."""
    cfg = load_profile(profile)
    match = cfg.get("match") or {}
    tips = [f"匹配规则: {format_match_summary(match)}"]
    paths = match.get("path") or []
    methods = match.get("methods") or []
    hosts = match.get("host") or []
    if paths and all(p not in ("*", "/*") for p in paths):
        tips.append(
            "提示: Path 有限制。请求路径对不上时插件不会改包 → 左侧点「规则」放宽 path，"
            "或导出 PAC 只让目标站走代理。"
        )
    if methods and set(m.upper() for m in methods) != {"*"}:
        tips.append(
            f"提示: 仅处理 {', '.join(methods)}。"
            "若浏览器发的是 GET 而规则只有 POST，会表现为「匹配没命中」。"
        )
    if hosts and "*" not in hosts and not any("*" in str(h) for h in hosts):
        tips.append(
            f"提示: Host 限定为 {', '.join(str(h) for h in hosts)}。"
            "域名不一致时点「规则」修改。"
        )
    tips.append(
        "若日志出现「未匹配/跳过」：核对浏览器是否走了解密端代理，并对照上述 Host/Path/Method。"
    )
    return tips


def diagnose_proxy_line(line: str) -> str | None:
    """根据 mitmdump / 插件输出给出可操作提示；无关则 None."""
    low = line.lower()
    text = line.strip()

    if any(
        k in low
        for k in (
            "address already in use",
            "only one usage of each socket address",
            "通常每个套接字地址",
            "10048",
            "eaddrinuse",
            "error starting proxy server",
            "failed to listen",
        )
    ) or ("bind" in low and "fail" in low):
        return (
            "端口被占用，代理未能监听。\n"
            "请更换左侧端口，或结束占用进程后重试。"
        )

    if "tls handshake failed" in low or "certificate verify failed" in low:
        return (
            "HTTPS 握手失败，多半是证书未信任。\n"
            "请点左侧「证书」安装，然后完全退出并重启浏览器，再访问 https://mitm.it 验证。"
        )

    if "未匹配项目，跳过" in text or "跳过(未匹配规则)" in text or "跳过（未匹配规则）" in text:
        return (
            "请求未命中当前项目的匹配规则，插件未处理。\n"
            "请：左侧「规则」放宽 Host/Path/Method；确认浏览器代理指向解密端；"
            "必要时导出 PAC 只代理目标域名。"
        )

    if "转发到 burp 失败" in low or "proxyerror" in low or "connection refused" in low:
        if "burp" in low or "8083" in text or "proxy" in low:
            return (
                "转发到 Burp 失败（连接被拒绝或代理不可达）。\n"
                "请确认 Burp 已监听对应端口，且左侧「→ Burp」端口填写正确。"
            )

    if "no module named" in low or "modulenotfounderror" in low:
        return (
            f"插件依赖缺失: {text}\n"
            "请检查 plugins 与 sdk 是否完整，或查看完整报错后安装缺失包。"
        )

    return None


def exit_code_hint(code: int, role_label: str, port: int) -> str:
    if code == 0:
        return f"{role_label}已正常停止"
    return (
        f"{role_label}异常退出 (code={code})。\n"
        f"常见原因：端口 {port} 被占用、mitmdump 未找到、插件语法错误。\n"
        f"请向上翻日志中的 [ERROR] / Traceback，或换端口后重试。"
    )
