/*! CipherBridge Hook — 页面引导：读取扩展勾选 → 注入 opts + inject.js */
(function () {
  "use strict";

  var DEFAULTS = {
    functionHook: true,
    evalHook: true,
    timerHook: true,
    timerNuke: false,
    consoleClear: true,
    sizeSpoof: true,
    rewriteResponse: false,
  };

  function injectPageCode(code) {
    try {
      var root = document.documentElement || document.head || document;
      var s = document.createElement("script");
      s.textContent = code;
      root.appendChild(s);
      s.remove();
    } catch (e) {
      try {
        console.warn("[CipherBridge] bootstrap inject failed", e);
      } catch (_) {}
    }
  }

  async function loadOpts() {
    var enabled = true;
    var opts = Object.assign({}, DEFAULTS);
    try {
      var stored = await chrome.storage.local.get(["cbEnabled", "cbInjectOpts"]);
      if (stored.cbEnabled === false) enabled = false;
      if (stored.cbInjectOpts && typeof stored.cbInjectOpts === "object") {
        opts = Object.assign(opts, stored.cbInjectOpts);
        return { enabled: enabled, opts: opts };
      }
    } catch (e) {}
    try {
      var resp = await fetch(chrome.runtime.getURL("options.json"));
      if (resp.ok) {
        var j = await resp.json();
        if (j && typeof j === "object") opts = Object.assign(opts, j);
      }
    } catch (e) {}
    return { enabled: enabled, opts: opts };
  }

  (async function main() {
    var cfg = await loadOpts();
    if (!cfg.enabled) {
      try {
        console.log("[CipherBridge] 扩展注入已关闭（可在插件弹窗开启）");
      } catch (e) {}
      return;
    }
    // 若 Playwright / 页面已写入 opts，不覆盖（GUI 启动优先）
    var prelude =
      "try{if(!window.__cbInjectOpts){window.__cbInjectOpts=" +
      JSON.stringify(cfg.opts) +
      ";}}catch(e){}";
    try {
      var resp = await fetch(chrome.runtime.getURL("inject.js"));
      var body = await resp.text();
      injectPageCode(prelude + "\n" + body);
    } catch (e) {
      // 回退：至少写入 opts
      injectPageCode(prelude);
      try {
        console.warn("[CipherBridge] 加载 inject.js 失败", e);
      } catch (_) {}
    }
  })();
})();
