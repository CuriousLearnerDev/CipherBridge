"""Context对象 — 插件与mitmproxy之间的抽象层.

所有插件通过 ctx 访问请求/响应数据，而不是直接操作 flow 对象.
"""

import json
import urllib.parse
from mitmproxy import http


class Context:
    """请求/响应上下文，封装了 mitmproxy flow 的底层细节."""

    # 会话级存储 — 同一个mitmproxy实例中所有请求共享
    _session: dict = {}

    def __init__(self, flow: http.HTTPFlow):
        self._flow = flow
        self._request_json = None
        self._request_form = None
        self._query_params = None
        self._response_json = None
        self._response_form = None
        self._modified = False

    # ---- 会话密钥管理 ----
    @property
    def session(self) -> dict:
        """会话级存储，跨请求持久化. 如 ctx.session['encryptKey']."""
        return Context._session

    def get_key(self, name: str, default: str = "") -> str:
        """从会话中获取密钥."""
        return Context._session.get(name, default)

    def save_key(self, name: str, value: str):
        """保存密钥到会话."""
        Context._session[name] = value

    def set_key_from_response(self, name: str, field_path: str):
        """从当前响应中提取字段值保存为密钥.

        例如: ctx.set_key_from_response('aesKey', 'result.encryptKey')
        将 ctx.response_json['result']['encryptKey'] 的值保存为 'aesKey'
        """
        if not self._flow.response:
            return
        try:
            body = json.loads(self.response_text)
            parts = field_path.split(".")
            val = body
            for p in parts:
                val = val[p]
            Context._session[name] = str(val)
        except Exception:
            pass

    def set_key_from_header(self, name: str, header_name: str):
        """从当前响应Header中提取值保存为密钥."""
        val = self._flow.response.headers.get(header_name, "") if self._flow.response else ""
        if val:
            Context._session[name] = val

    def set_key_from_cookie(self, name: str, cookie_name: str):
        """从请求Cookie中提取值保存为密钥."""
        val = self.cookies.get(cookie_name, "")
        if val:
            Context._session[name] = val

    def derive_key(self, name: str, formula: str):
        """从公式派生密钥. 支持的变量: $field, $key, $timestamp_ms, $random16.

        例如: ctx.derive_key('aesKey', '$timestamp_ms + $key:clientId')
        """
        import hashlib, time, secrets, re as _re
        result = formula
        # $field:xxx → 取body字段
        for field_name in set(_re.findall(r'\$field:(\w+)', formula)):
            val = json.loads(self.request_text).get(field_name, "") if self.has_body else ""
            result = result.replace(f'$field:{field_name}', str(val))
        # $key:xxx → 取已存储密钥
        for key_name in set(_re.findall(r'\$key:(\w+)', formula)):
            result = result.replace(f'$key:{key_name}', Context._session.get(key_name, ""))
        result = result.replace('$timestamp_ms', str(int(time.time() * 1000)))
        result = result.replace('$timestamp_s', str(int(time.time())))
        result = result.replace('$random16', secrets.token_bytes(16).hex())
        result = result.replace('$random8', secrets.token_bytes(8).hex())

        # 如果公式看起来像纯拼接，直接保存
        if not _re.search(r'[$]', result):
            Context._session[name] = result

    def has_key(self, name: str) -> bool:
        return name in Context._session

    # ---- 基本信息 ----
    @property
    def method(self) -> str:
        return self._flow.request.method

    @property
    def url(self) -> str:
        return self._flow.request.url

    @property
    def path(self) -> str:
        return self._flow.request.path

    @property
    def query_params(self) -> dict:
        """URL 查询参数 (?a=1&b=2)，修改后自动回写 URL."""
        if self._query_params is None:
            parsed = urllib.parse.urlparse(self.url)
            self._query_params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        return self._query_params

    @query_params.setter
    def query_params(self, value: dict):
        self._query_params = dict(value)
        parsed = urllib.parse.urlparse(self.url)
        new_query = urllib.parse.urlencode(value, doseq=True)
        self._flow.request.url = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment,
        ))

    @property
    def host(self) -> str:
        return self._flow.request.host

    @property
    def scheme(self) -> str:
        return self._flow.request.scheme

    # ---- Headers ----
    @property
    def headers(self) -> dict:
        return dict(self._flow.request.headers)

    def get_header(self, name: str, default: str = "") -> str:
        return self._flow.request.headers.get(name, default)

    def set_header(self, name: str, value: str):
        self._flow.request.headers[name] = value

    def del_header(self, name: str):
        if name in self._flow.request.headers:
            del self._flow.request.headers[name]

    @property
    def response_headers(self) -> dict:
        if self._flow.response:
            return dict(self._flow.response.headers)
        return {}

    # ---- Cookies ----
    @property
    def cookies(self) -> dict:
        cookie_str = self._flow.request.headers.get("Cookie", "")
        result = {}
        for item in cookie_str.split(";"):
            item = item.strip()
            if "=" in item:
                k, v = item.split("=", 1)
                result[k.strip()] = v.strip()
        return result

    def get_cookie(self, name: str, default: str = "") -> str:
        return self.cookies.get(name, default)

    def set_cookie(self, name: str, value: str):
        cookies = self.cookies
        cookies[name] = value
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        self._flow.request.headers["Cookie"] = cookie_str

    # ---- 请求体 ----
    @property
    def content_type(self) -> str:
        return self._flow.request.headers.get("Content-Type", "").lower()

    @property
    def request_text(self) -> str:
        return self._flow.request.text or ""

    @request_text.setter
    def request_text(self, value: str):
        body = value.encode("utf-8")
        self._flow.request.content = body
        self._flow.request.headers["Content-Length"] = str(len(body))

    @property
    def request_bytes(self) -> bytes:
        return self._flow.request.content or b""

    @request_bytes.setter
    def request_bytes(self, value: bytes):
        self._flow.request.content = value

    @property
    def request_json(self) -> dict:
        """解析请求体为JSON dict，修改后自动回写."""
        if self._request_json is None:
            try:
                self._request_json = json.loads(self.request_text)
            except (json.JSONDecodeError, ValueError):
                self._request_json = {}
        return self._request_json

    @request_json.setter
    def request_json(self, value: dict):
        self._request_json = value
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._flow.request.content = body
        self._flow.request.headers["Content-Length"] = str(len(body))

    @property
    def request_form(self) -> dict:
        """解析请求体为URL-encoded form字典."""
        if self._request_form is None:
            self._request_form = dict(urllib.parse.parse_qsl(self.request_text))
        return self._request_form

    @request_form.setter
    def request_form(self, value: dict):
        self._request_form = value
        self._flow.request.content = urllib.parse.urlencode(value, doseq=True).encode("utf-8")

    @property
    def request_raw(self) -> str:
        return self.request_text

    @request_raw.setter
    def request_raw(self, value: str):
        self._flow.request.content = value.encode("utf-8")

    # ---- 响应体 ----
    @property
    def response_text(self) -> str:
        if self._flow.response:
            return self._flow.response.text or ""
        return ""

    @response_text.setter
    def response_text(self, value: str):
        if self._flow.response:
            self._flow.response.content = value.encode("utf-8")

    @property
    def response_json(self) -> dict:
        if self._response_json is None and self._flow.response:
            try:
                self._response_json = json.loads(self.response_text)
            except (json.JSONDecodeError, ValueError):
                self._response_json = {}
        return self._response_json or {}

    @response_json.setter
    def response_json(self, value: dict):
        self._response_json = value
        if self._flow.response:
            self._flow.response.content = json.dumps(value, ensure_ascii=False).encode("utf-8")

    @property
    def response_status(self) -> int:
        if self._flow.response:
            return self._flow.response.status_code
        return 0

    @property
    def has_body(self) -> bool:
        return bool(self._flow.request.content)

    @property
    def has_response(self) -> bool:
        return self._flow.response is not None and bool(self._flow.response.content)

    # ---- 内部 ----
    @property
    def _raw_flow(self):
        """访问原始 mitmproxy flow (仅框架内部使用)."""
        return self._flow
