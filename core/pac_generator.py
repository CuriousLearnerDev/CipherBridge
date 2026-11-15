"""PAC 脚本生成 — 仅让匹配规则的流量走代理."""

from __future__ import annotations

from core.brand import APP_TITLE


def _host_to_url_patterns(host: str, path: str) -> list[str]:
    host = (host or "").strip()
    path = (path or "/*").strip() or "/*"
    if not path.startswith("/"):
        path = "/" + path
    if host in ("", "*"):
        return [f"*://*{path}"]
    return [f"*://{host}{path}"]


def build_proxy_url_patterns(match: dict) -> list[str]:
    """将 profile match 转为 PAC 可用的 URL 通配模式."""
    hosts = [h.strip() for h in (match.get("host") or []) if str(h).strip()]
    paths = [p.strip() for p in (match.get("path") or []) if str(p).strip()]
    if not hosts:
        return []
    if not paths:
        paths = ["/*"]
    patterns: list[str] = []
    for host in hosts:
        for path in paths:
            for pat in _host_to_url_patterns(host, path):
                if pat not in patterns:
                    patterns.append(pat)
    return patterns


def generate_pac(match: dict, proxy_port: int, proxy_host: str = "127.0.0.1") -> str:
    """生成 PAC 文件内容."""
    patterns = build_proxy_url_patterns(match)
    proxy = f"PROXY {proxy_host}:{proxy_port}"
    if not patterns:
        return (
            f"// {APP_TITLE} — 未配置匹配规则，所有流量直连\n"
            "function FindProxyForURL(url, host) { return \"DIRECT\"; }\n"
        )

    lines = [
        f"// {APP_TITLE} 自动生成 — 仅匹配流量走代理",
        "// 浏览器 → 系统代理/PAC → 仅下列 URL 走 mitmdump，其余直连",
        "function FindProxyForURL(url, host) {",
        "    url = url.toLowerCase();",
        "    host = host.toLowerCase();",
    ]
    for pat in patterns:
        lines.append(f'    if (shExpMatch(url, "{pat.lower()}")) return "{proxy}";')
    lines.append('    return "DIRECT";')
    lines.append("}")
    lines.append("")
    return "\n".join(lines)
