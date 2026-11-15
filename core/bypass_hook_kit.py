# -*- coding: utf-8 -*-
"""Bypass Hook 运行时脚手架 — 提高 AI 生成油猴绕过成功率."""

from __future__ import annotations

import re

# 注入到 AI hook_js 之前：统一延迟挂钩 / 路径挂钩 / XHR 明文兜底
BYPASS_RUNTIME_JS = r"""
/* --- CipherBridge BypassHook runtime --- */
(function (g) {
  if (g.__cbBypassRT) return;
  var RT = {
    log: function () {
      try {
        var a = ["[密桥·BypassHook]"].concat([].slice.call(arguments));
        console.log.apply(console, a);
      } catch (e) {}
    },
    keepPlain: function (name, v) {
      RT.log("plain", name, v);
      return v;
    },
    /** 轮询直到 fn 返回 true，最长 ms */
    poll: function (fn, ms) {
      ms = ms || 20000;
      var ok = false;
      try { ok = !!fn(); } catch (e) {}
      if (ok) return;
      var t0 = Date.now();
      var id = setInterval(function () {
        var done = false;
        try { done = !!fn(); } catch (e) {}
        if (done || Date.now() - t0 > ms) clearInterval(id);
      }, 40);
    },
    /** 按 a.b.c 路径挂钩函数；wrapper(orig, args, thisObj) */
    hookPath: function (path, wrapper, label) {
      label = label || path;
      RT.poll(function () {
        var parts = String(path).split(".");
        var obj = g;
        for (var i = 0; i < parts.length - 1; i++) {
          if (!obj) return false;
          obj = obj[parts[i]];
        }
        var key = parts[parts.length - 1];
        if (!obj || typeof obj[key] !== "function") return false;
        if (obj[key].__cbBypass) return true;
        var orig = obj[key];
        var hooked = function () {
          return wrapper(orig, arguments, this);
        };
        hooked.__cbBypass = 1;
        try { obj[key] = hooked; } catch (e) { return false; }
        RT.log("hooked", label);
        return true;
      });
    },
    /** 等 getter() 得到函数再挂钩 */
    hookWhen: function (getter, wrapper, label) {
      RT.poll(function () {
        var fn = null;
        try { fn = getter(); } catch (e) {}
        if (typeof fn !== "function") return false;
        if (fn.__cbBypass) return true;
        var parent = null, key = null;
        // 无法可靠取 parent 时：仅包装返回值场景由调用方处理
        return false;
      });
    },
    /** CryptoJS 常见哈希/加密 → identity（有则挂） */
    hookCryptoJSIdentity: function () {
      RT.poll(function () {
        var C = g.CryptoJS;
        if (!C) return false;
        var n = 0;
        function wrapName(name) {
          if (typeof C[name] !== "function" || C[name].__cbBypass) return;
          C[name] = (function (nm) {
            var w = function (msg) {
              var s = msg;
              try {
                if (msg && typeof msg === "object" && typeof msg.toString === "function")
                  s = msg.toString(C.enc && C.enc.Utf8 ? C.enc.Utf8 : undefined);
              } catch (e) {
                try { s = String(msg); } catch (e2) {}
              }
              return RT.keepPlain("CryptoJS." + nm, s);
            };
            w.__cbBypass = 1;
            return w;
          })(name);
          n++;
          RT.log("hooked CryptoJS." + name);
        }
        ["MD5", "SHA1", "SHA256", "SHA512", "HmacMD5", "HmacSHA1", "HmacSHA256"].forEach(wrapName);
        if (C.AES && typeof C.AES.encrypt === "function" && !C.AES.encrypt.__cbBypass) {
          C.AES.encrypt = function (msg) {
            var s = msg;
            try {
              if (msg && typeof msg.toString === "function") s = msg.toString();
            } catch (e) {}
            var plain = RT.keepPlain("AES.encrypt", s);
            return {
              toString: function () { return String(plain); },
              ciphertext: plain
            };
          };
          C.AES.encrypt.__cbBypass = 1;
          n++;
          RT.log("hooked CryptoJS.AES.encrypt");
        }
        return n > 0;
      }, 25000);
    },
    /** 常见全局 md5 / hex_md5 / sha256 */
    hookGlobalHashIdentity: function () {
      ["md5", "MD5", "hex_md5", "hex_md5_32", "sha1", "sha256", "SHA256", "hmac"].forEach(function (name) {
        RT.hookPath(name, function (orig, args) {
          var v = args[0];
          return RT.keepPlain(name, v);
        }, name);
      });
    },
    /**
     * XHR/fetch 兜底：若 body 里字段值像密文且我们缓存了明文，则替换。
     * 更常见：加密函数已 identity，字段本身就是明文，此函数作双保险日志。
     */
    patchTransportLog: function (fields) {
      fields = fields || [];
      try {
        var _open = XMLHttpRequest.prototype.open;
        var _send = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.open = function () {
          this.__cbUrl = arguments[1];
          return _open.apply(this, arguments);
        };
        XMLHttpRequest.prototype.send = function (body) {
          try {
            if (typeof body === "string" && fields.length) {
              RT.log("XHR.send", this.__cbUrl, body.slice(0, 300));
            }
          } catch (e) {}
          return _send.apply(this, arguments);
        };
      } catch (e) {}
      try {
        if (g.fetch) {
          var _f = g.fetch;
          g.fetch = function (input, init) {
            try {
              if (init && typeof init.body === "string")
                RT.log("fetch", String(input).slice(0, 120), init.body.slice(0, 300));
            } catch (e) {}
            return _f.apply(this, arguments);
          };
        }
      } catch (e2) {}
    }
  };
  g.__cbBypassRT = RT;
  g.cbBypass = RT;
  RT.log("runtime ready");
})(typeof window !== "undefined" ? window : this);
"""


def looks_like_oneshot_hook(js: str) -> bool:
    """粗判：只有一次 if 判断、没有轮询/延迟。"""
    s = js or ""
    if "setInterval" in s or "__cbBypassRT" in s or "cbBypass" in s:
        return False
    if "poll(" in s or "hookPath" in s:
        return False
    # 典型失败写法
    if re.search(r"if\s*\(\s*(?:window\.)?\w+", s) and "setInterval" not in s:
        return True
    return "setInterval" not in s and "document-start" not in s.lower()


def wrap_bypass_hook_js(hook_js: str, *, fields: list | None = None) -> str:
    """前置运行时 +（必要时）提示 AI 脚本应使用 cbBypass。"""
    body = (hook_js or "").strip()
    if body.startswith("```"):
        lines = body.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        body = "\n".join(lines).strip()

    field_list = [str(f).strip() for f in (fields or []) if str(f).strip()]
    field_js = ",".join(f'"{f}"' for f in field_list[:12])

    # 若 AI 未使用运行时，仍前置 runtime，并追加通用兜底（CryptoJS/全局 hash + 传输日志）
    extras = []
    if "cbBypass" not in body and "__cbBypassRT" not in body:
        extras.append(
            "try{cbBypass.hookCryptoJSIdentity();cbBypass.hookGlobalHashIdentity();"
            + "cbBypass.patchTransportLog([" + field_js + "]);}catch(e){}"
        )
    elif field_list:
        extras.append(
            "try{cbBypass.patchTransportLog([" + field_js + "]);}catch(e){}"
        )

    parts = [
        BYPASS_RUNTIME_JS.strip(),
        "/* --- AI bypass site patch --- */",
        body,
    ]
    if extras:
        parts.append("/* --- CipherBridge bypass fallbacks --- */")
        parts.append("(function(){" + "".join(extras) + "})();")
    return "\n".join(parts)


def harden_hint_for_goal(fields: list[str] | None = None) -> str:
    """拼进 Agent goal 的高成功率规则。"""
    fl = "、".join(fields or []) or "（从 flow 推断）"
    return (
        "\n【高成功率强制规则】"
        "\n1. hook_js 开头不要重复实现轮询；运行时已注入 window.cbBypass："
        "cbBypass.hookPath('Encrypt.oldPwd', function(orig,args){return cbBypass.keepPlain('oldPwd', args[0]);}),"
        "cbBypass.hookCryptoJSIdentity(), cbBypass.hookGlobalHashIdentity()。"
        "\n2. 禁止只写 if(window.Xxx){...} 一次；必须用 cbBypass.hookPath 或 setInterval 轮询。"
        "\n3. 优先顺序：业务函数路径(如 Encrypt.oldPwd) → CryptoJS → 全局 md5/hex_md5 → XHR/fetch 日志。"
        f"\n4. 目标明文字段: {fl}；包装函数必须 return 明文入参(identity)，禁止再调用 orig 加密。"
        "\n5. script.search 优先: encrypt, oldPwd, md5, hex_md5, CryptoJS, password, sign, AES。"
        "\n6. 从 flow.request_body 确认字段名；targets 填真实函数路径。"
    )
