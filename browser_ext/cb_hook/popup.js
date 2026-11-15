/* CipherBridge Hook popup — 注入开关 + 代理切换 */
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

  var PROXY_DEFAULT = {
    mode: "direct",
    host: "127.0.0.1",
    port: 8083,
  };

  var enabledEl = document.getElementById("cbEnabled");
  var hostEl = document.getElementById("proxyHost");
  var portEl = document.getElementById("proxyPort");
  var msgEl = document.getElementById("msg");

  function showMsg(t, isErr) {
    msgEl.textContent = t || "";
    msgEl.className = isErr ? "err" : "";
  }

  function selectedMode() {
    var el = document.querySelector('input[name="proxyMode"]:checked');
    return el ? el.value : "direct";
  }

  function setMode(mode) {
    var el = document.querySelector('input[name="proxyMode"][value="' + mode + '"]');
    if (el) el.checked = true;
  }

  function syncPortPlaceholder() {
    var mode = selectedMode();
    if (mode === "decrypt") {
      if (!portEl.value || portEl.value === "8080") portEl.value = "8083";
    } else if (mode === "burp") {
      if (!portEl.value || portEl.value === "8083") portEl.value = "8080";
    }
  }

  function readProxyCfg() {
    var mode = selectedMode();
    var host = (hostEl.value || "127.0.0.1").trim() || "127.0.0.1";
    var port = parseInt(portEl.value, 10) || 8083;
    if (mode === "decrypt" && !portEl.value) port = 8083;
    if (mode === "burp" && !portEl.value) port = 8080;
    return { mode: mode, host: host, port: port };
  }

  async function load() {
    try {
      var stored = await chrome.storage.local.get(["cbEnabled", "cbInjectOpts", "cbProxy"]);
      enabledEl.checked = stored.cbEnabled !== false;
      var px = Object.assign({}, PROXY_DEFAULT, stored.cbProxy || {});
      setMode(px.mode || "direct");
      hostEl.value = px.host || "127.0.0.1";
      portEl.value = String(px.port || (px.mode === "burp" ? 8080 : 8083));
      return;
    } catch (e) {}
    enabledEl.checked = true;
  }

  function sendProxy(cfg) {
    return new Promise(function (resolve) {
      chrome.runtime.sendMessage({ type: "cbSetProxy", cfg: cfg }, function (resp) {
        if (chrome.runtime.lastError) {
          resolve({ ok: false, error: chrome.runtime.lastError.message });
          return;
        }
        resolve(resp || { ok: false, error: "no response" });
      });
    });
  }

  async function save() {
    var opts = Object.assign({}, DEFAULTS);
    try {
      var prev = await chrome.storage.local.get(["cbInjectOpts"]);
      if (prev.cbInjectOpts && typeof prev.cbInjectOpts === "object") {
        opts = Object.assign(opts, prev.cbInjectOpts);
      }
    } catch (e) {}

    await chrome.storage.local.set({
      cbEnabled: !!enabledEl.checked,
      cbInjectOpts: opts,
    });

    var cfg = readProxyCfg();
    var resp = await sendProxy(cfg);
    if (resp && resp.ok) {
      var tip =
        cfg.mode === "direct"
          ? "已直连"
          : "代理 → " + cfg.host + ":" + cfg.port;
      showMsg(tip + " · 注入已保存");
    } else {
      showMsg("代理失败: " + ((resp && resp.error) || "unknown"), true);
    }
    setTimeout(function () {
      showMsg("");
    }, 2800);
  }

  async function reset() {
    enabledEl.checked = true;
    setMode("direct");
    hostEl.value = "127.0.0.1";
    portEl.value = "8083";
    await chrome.storage.local.set({
      cbEnabled: true,
      cbInjectOpts: Object.assign({}, DEFAULTS),
      cbProxy: Object.assign({}, PROXY_DEFAULT),
    });
    var resp = await sendProxy(PROXY_DEFAULT);
    showMsg(resp && resp.ok ? "已恢复直连" : "已重置（代理可能未生效）", !(resp && resp.ok));
    setTimeout(function () {
      showMsg("");
    }, 2000);
  }

  document.getElementById("btnSave").addEventListener("click", save);
  document.getElementById("btnReset").addEventListener("click", reset);
  enabledEl.addEventListener("change", save);
  document.querySelectorAll('input[name="proxyMode"]').forEach(function (el) {
    el.addEventListener("change", syncPortPlaceholder);
  });

  load();
})();
