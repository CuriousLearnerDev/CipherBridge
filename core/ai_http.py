"""AI API HTTP — curl_cffi 浏览器指纹 + 失败自动回退普通 HTTP。"""

from __future__ import annotations

import json
import logging
from typing import Any, Iterator

logger = logging.getLogger(__name__)

_CF_MARKERS = (
    "just a moment",
    "attention required",
    "cf-browser-verification",
    "challenge-platform",
    "cdn-cgi/challenge",
    "cloudflare",
)

# 走代理时 chrome131 等易 SSL_ERROR_SYSCALL；chrome120 相对稳
_IMPERSONATE_WITH_PROXY = ("chrome120", "chrome124", "chrome110")
_IMPERSONATE_DIRECT = ("chrome131", "chrome120", "chrome124")


def looks_like_cloudflare(text: str | None, status: int | None = None) -> bool:
    if not text:
        return False
    low = text[:2000].lower()
    if "just a moment" in low or "attention required" in low:
        return True
    if status == 403 and any(m in low for m in _CF_MARKERS) and "<!doctype html" in low:
        return True
    return False


def cloudflare_hint(url: str = "") -> str:
    return (
        "Cloudflare 人机验证拦截了请求（不是 API Key 写错）。\n"
        f"端点: {url or '(未知)'}\n\n"
        "若仍 403：\n"
        "1. 换能过 CF 的代理节点（住宅/干净 IP）\n"
        "2. 问网关方要未套 CF 的 API 域名\n"
        "3. 或改用其它可用 NewAPI"
    )


def ssl_proxy_hint(url: str = "", detail: str = "") -> str:
    return (
        "代理与目标站 TLS 握手失败（常见于 curl 走 HTTP 代理时被节点掐断）。\n"
        f"端点: {url or '(未知)'}\n"
        f"细节: {(detail or '')[:180]}\n\n"
        "可尝试：\n"
        "1. 换一个代理节点后再测\n"
        "2. 在 Clash 等开启「允许局域网 / TUN」并确认 7897 是 HTTP 端口\n"
        "3. 若浏览器能开 gorouter 而密桥不行，换未套 CF 的网关更稳"
    )


def _proxy_url(proxies: dict | None) -> str | None:
    if not proxies:
        return None
    p = (proxies.get("https") or proxies.get("http") or "").strip()
    return p or None


def _timeout_sec(timeout: float | tuple, default: float = 60.0) -> float:
    if isinstance(timeout, tuple):
        return float(timeout[-1] if timeout else default)
    try:
        return float(timeout)
    except (TypeError, ValueError):
        return default


def _has_curl_cffi() -> bool:
    try:
        import curl_cffi  # noqa: F401

        return True
    except Exception:
        return False


def _is_transport_error(exc: BaseException) -> bool:
    msg = str(exc).lower()
    keys = (
        "ssl_error",
        "ssl_connect",
        "boringssl",
        "connection closed",
        "curl: (35)",
        "curl: (56)",
        "curl: (7)",
        "curl: (28)",
        "connection reset",
        "timed out",
        "timeout",
        "proxy",
        "failed to perform",
    )
    return any(k in msg for k in keys)


class AIHttpError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None, body: str = ""):
        super().__init__(message)
        self.status = status
        self.body = body


def _raise_from_response(url: str, status: int, text: str) -> None:
    if looks_like_cloudflare(text, status):
        raise AIHttpError(cloudflare_hint(url), status=status, body=text[:400])
    raise AIHttpError(
        f"HTTP {status}: {text[:400]}",
        status=status,
        body=text[:800],
    )


def _parse_json_response(resp: Any) -> dict[str, Any]:
    if hasattr(resp, "json"):
        try:
            data = resp.json()
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    raw = getattr(resp, "content", None) or getattr(resp, "text", "") or ""
    if isinstance(raw, (bytes, bytearray)):
        return json.loads(raw)
    return json.loads(str(raw))


def _post_curl_cffi(
    url: str,
    *,
    headers: dict,
    body: dict,
    proxy: str | None,
    timeout_s: float,
    impersonates: tuple[str, ...],
) -> dict[str, Any]:
    from curl_cffi import requests as creq

    last_exc: BaseException | None = None
    for imp in impersonates:
        try:
            resp = creq.post(
                url,
                headers=headers,
                json=body,
                proxy=proxy,
                timeout=timeout_s,
                impersonate=imp,
                allow_redirects=True,
            )
            text = resp.text or ""
            if resp.status_code >= 400:
                _raise_from_response(url, resp.status_code, text)
            return _parse_json_response(resp)
        except AIHttpError:
            raise
        except Exception as e:
            last_exc = e
            logger.info("curl_cffi POST %s impersonate=%s failed: %s", url, imp, e)
            if not _is_transport_error(e):
                raise AIHttpError(str(e)) from e
            continue
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("curl_cffi 无可用指纹")


def _post_requests(
    url: str,
    *,
    headers: dict,
    body: dict,
    proxies: dict | None,
    timeout: float | tuple,
) -> dict[str, Any]:
    import requests

    resp = requests.post(
        url,
        headers=headers,
        json=body,
        proxies=proxies,
        timeout=timeout,
    )
    text = resp.text or ""
    if resp.status_code >= 400:
        _raise_from_response(url, resp.status_code, text)
    return resp.json()


def post_json(
    url: str,
    *,
    headers: dict,
    body: dict,
    proxies: dict | None = None,
    timeout: float | tuple = 60.0,
    impersonate: str = "chrome120",
) -> dict[str, Any]:
    """POST JSON。

    有 HTTP 代理时优先 requests（curl_cffi+代理易 SSL_ERROR_SYSCALL）；
    直连时优先 curl_cffi 指纹，失败再回退。
    """
    proxy = _proxy_url(proxies)
    timeout_s = _timeout_sec(timeout, 60.0)
    imps = (impersonate,) + tuple(
        x
        for x in (_IMPERSONATE_WITH_PROXY if proxy else _IMPERSONATE_DIRECT)
        if x != impersonate
    )

    # 代理模式：先普通 HTTP（握手更稳）
    if proxy:
        try:
            return _post_requests(
                url, headers=headers, body=body, proxies=proxies, timeout=timeout
            )
        except AIHttpError:
            raise
        except Exception as e:
            logger.warning("requests+proxy 失败，尝试 curl_cffi: %s", e)
            if _has_curl_cffi():
                try:
                    return _post_curl_cffi(
                        url,
                        headers=headers,
                        body=body,
                        proxy=proxy,
                        timeout_s=timeout_s,
                        impersonates=imps,
                    )
                except AIHttpError:
                    raise
                except Exception as e2:
                    raise AIHttpError(
                        ssl_proxy_hint(url, f"{e}; curl_cffi: {e2}"),
                    ) from e2
            raise AIHttpError(ssl_proxy_hint(url, str(e))) from e

    if _has_curl_cffi():
        try:
            return _post_curl_cffi(
                url,
                headers=headers,
                body=body,
                proxy=None,
                timeout_s=timeout_s,
                impersonates=imps,
            )
        except AIHttpError:
            raise
        except Exception as e:
            if not _is_transport_error(e):
                raise AIHttpError(str(e)) from e
            logger.warning("curl_cffi 传输失败，回退 requests: %s", e)

    return _post_requests(
        url, headers=headers, body=body, proxies=proxies, timeout=timeout
    )


def _iter_sse_requests(
    url: str,
    *,
    headers: dict,
    body: dict,
    proxies: dict | None,
    timeout: float | tuple,
) -> Iterator[str]:
    import requests

    with requests.post(
        url,
        headers=headers,
        json=body,
        proxies=proxies,
        timeout=timeout,
        stream=True,
    ) as resp:
        if resp.status_code >= 400:
            text_head = (resp.text or "")[:800]
            _raise_from_response(url, resp.status_code, text_head)
        for raw in resp.iter_lines(decode_unicode=True):
            if not raw or not raw.startswith("data: "):
                continue
            data = raw[6:].strip()
            if data == "[DONE]":
                break
            yield data


def iter_sse_lines(
    url: str,
    *,
    headers: dict,
    body: dict,
    proxies: dict | None = None,
    timeout: float | tuple = 180.0,
    impersonate: str = "chrome120",
) -> Iterator[str]:
    """流式 POST。有代理时优先 requests。"""
    proxy = _proxy_url(proxies)
    timeout_s = _timeout_sec(timeout, 180.0)
    imps = (impersonate,) + tuple(
        x
        for x in (_IMPERSONATE_WITH_PROXY if proxy else _IMPERSONATE_DIRECT)
        if x != impersonate
    )

    if proxy:
        try:
            yield from _iter_sse_requests(
                url, headers=headers, body=body, proxies=proxies, timeout=timeout
            )
            return
        except AIHttpError:
            raise
        except Exception as e:
            logger.warning("requests SSE+proxy 失败，尝试 curl_cffi: %s", e)
            if not _has_curl_cffi():
                raise AIHttpError(ssl_proxy_hint(url, str(e))) from e

    if _has_curl_cffi() and not proxy:
        from curl_cffi import requests as creq

        last_exc: BaseException | None = None
        for imp in imps:
            try:
                with creq.post(
                    url,
                    headers=headers,
                    json=body,
                    proxy=None,
                    timeout=timeout_s,
                    impersonate=imp,
                    stream=True,
                    allow_redirects=True,
                ) as resp:
                    if resp.status_code >= 400:
                        peek = ""
                        try:
                            peek = (resp.text or "")[:800]
                        except Exception:
                            pass
                        _raise_from_response(url, resp.status_code, peek)
                    for raw in resp.iter_lines():
                        if raw is None:
                            continue
                        if isinstance(raw, bytes):
                            try:
                                raw = raw.decode("utf-8", errors="replace")
                            except Exception:
                                continue
                        line = str(raw).strip()
                        if not line.startswith("data: "):
                            continue
                        data = line[6:].strip()
                        if data == "[DONE]":
                            break
                        yield data
                return
            except AIHttpError:
                raise
            except Exception as e:
                last_exc = e
                logger.info("curl_cffi SSE %s impersonate=%s failed: %s", url, imp, e)
                if not _is_transport_error(e):
                    raise AIHttpError(str(e)) from e
                continue
        logger.warning("curl_cffi SSE 失败，回退 requests: %s", last_exc)

    yield from _iter_sse_requests(
        url, headers=headers, body=body, proxies=proxies, timeout=timeout
    )


async def apost_json(
    url: str,
    *,
    headers: dict,
    body: dict,
    proxy: str | None = None,
    timeout: float = 180.0,
    impersonate: str = "chrome120",
) -> dict[str, Any]:
    """异步 POST（Agent）。有代理时优先 httpx，避免 curl_cffi SSL 掐断。"""
    import httpx

    async def _via_httpx() -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=timeout, proxy=proxy) as client:
            resp = await client.post(url, json=body, headers=headers)
            text = resp.text or ""
            if looks_like_cloudflare(text, resp.status_code):
                raise AIHttpError(
                    cloudflare_hint(url), status=resp.status_code, body=text[:400]
                )
            if resp.status_code != 200:
                raise AIHttpError(
                    f"LLM API error [{resp.status_code}]: {text[:500]}",
                    status=resp.status_code,
                    body=text[:800],
                )
            return resp.json()

    if proxy:
        try:
            return await _via_httpx()
        except AIHttpError:
            raise
        except Exception as e:
            raise AIHttpError(ssl_proxy_hint(url, str(e) or repr(e))) from e

    if _has_curl_cffi():
        from curl_cffi.requests import AsyncSession

        imps = (impersonate,) + tuple(
            x for x in _IMPERSONATE_DIRECT if x != impersonate
        )
        last_exc: BaseException | None = None
        for imp in imps:
            try:
                async with AsyncSession() as session:
                    resp = await session.post(
                        url,
                        headers=headers,
                        json=body,
                        proxy=None,
                        timeout=timeout,
                        impersonate=imp,
                        allow_redirects=True,
                    )
                    text = resp.text or ""
                    if resp.status_code >= 400:
                        _raise_from_response(url, resp.status_code, text)
                    return _parse_json_response(resp)
            except AIHttpError:
                raise
            except Exception as e:
                last_exc = e
                logger.info("curl_cffi async %s impersonate=%s failed: %s", url, imp, e)
                if not _is_transport_error(e):
                    raise AIHttpError(str(e)) from e
                continue
        logger.warning("curl_cffi async 失败，回退 httpx: %s", last_exc)

    try:
        return await _via_httpx()
    except AIHttpError:
        raise
    except Exception as e:
        raise AIHttpError(ssl_proxy_hint(url, str(e) or repr(e))) from e
