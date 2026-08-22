/* CipherBridge Hook — 代理切换（chrome.proxy） */
(function () {
  "use strict";

  var DEFAULT = {
    mode: "direct", // direct | decrypt | burp | custom
    host: "127.0.0.1",
    port: 8083,
  };

  function fixedConfig(host, port) {
    return {
      mode: "fixed_servers",
      rules: {
        singleProxy: {
          scheme: "http",
          host: host || "127.0.0.1",
          port: Number(port) || 8083,
        },
        bypassList: ["<-loopback>", "localhost", "127.0.0.1"],
      },
    };
  }

  function applyProxy(cfg) {
    cfg = Object.assign({}, DEFAULT, cfg || {});
    var value;
    if (cfg.mode === "direct" || !cfg.mode) {
      value = { mode: "direct" };
    } else if (cfg.mode === "system") {
      value = { mode: "system" };
    } else {
      var port = cfg.port;
      if (cfg.mode === "decrypt") port = cfg.port || 8083;
      if (cfg.mode === "burp") port = cfg.port || 8080;
      value = fixedConfig(cfg.host || "127.0.0.1", port);
    }
    return new Promise(function (resolve, reject) {
      chrome.proxy.settings.set({ value: value, scope: "regular" }, function () {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        chrome.storage.local.set({ cbProxy: cfg }, function () {
          resolve(cfg);
        });
      });
    });
  }

  async function loadPrefFile() {
    try {
      var url = chrome.runtime.getURL("proxy_pref.json");
      var resp = await fetch(url);
      if (!resp.ok) return null;
      return await resp.json();
    } catch (e) {
      return null;
    }
  }

  async function bootstrap() {
    try {
      var pref = await loadPrefFile();
      var stored = await chrome.storage.local.get(["cbProxy"]);
      var cfg = DEFAULT;
      // 启动时优先密桥写入的 proxy_pref.json（与本次启动意图一致）
      if (pref && typeof pref === "object" && pref.mode) {
        cfg = Object.assign({}, DEFAULT, pref);
      } else if (stored.cbProxy && typeof stored.cbProxy === "object") {
        cfg = Object.assign({}, DEFAULT, stored.cbProxy);
      }
      await applyProxy(cfg);
      console.log("[CipherBridge] proxy applied", cfg);
    } catch (e) {
      console.warn("[CipherBridge] proxy bootstrap", e);
    }
  }

  chrome.runtime.onMessage.addListener(function (msg, _sender, sendResponse) {
    if (!msg || msg.type !== "cbSetProxy") return;
    applyProxy(msg.cfg || {})
      .then(function (cfg) {
        sendResponse({ ok: true, cfg: cfg });
      })
      .catch(function (err) {
        sendResponse({ ok: false, error: String(err && err.message ? err.message : err) });
      });
    return true;
  });

  chrome.runtime.onInstalled.addListener(bootstrap);
  chrome.runtime.onStartup.addListener(bootstrap);
  bootstrap();
})();
