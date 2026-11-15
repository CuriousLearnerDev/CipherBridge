/* 密桥 CipherBridge Web */
(() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  const state = {
    projects: [],
    current: localStorage.getItem("cb_current_project") || "",
    ops: [],
    steps: [],
    fields: {},
    bodyFormat: "json",
    rawHttp: "",
    _pipelineDirty: false,
  };

  let _autoSaveTimer = null;
  let _autoSaving = false;

  function rememberCurrentProject(id) {
    state.current = id || "";
    if (state.current) localStorage.setItem("cb_current_project", state.current);
    else localStorage.removeItem("cb_current_project");
  }

  function pipelineDraftKey() {
    return state.current ? `cb_pipeline_draft_${state.current}` : "cb_pipeline_draft__none";
  }

  function writePipelineDraft() {
    try {
      const raw = ($("#rawHttp") && $("#rawHttp").value) || state.rawHttp || "";
      localStorage.setItem(
        pipelineDraftKey(),
        JSON.stringify({
          steps: state.steps,
          fields: state.fields,
          bodyFormat: state.bodyFormat || "json",
          rawHttp: raw,
          ts: Date.now(),
        })
      );
    } catch (_) {
      /* quota / private mode */
    }
  }

  function readPipelineDraft() {
    try {
      const raw = localStorage.getItem(pipelineDraftKey());
      return raw ? JSON.parse(raw) : null;
    } catch (_) {
      return null;
    }
  }

  async function persistPipelineState({ writePlugin = false, silent = true } = {}) {
    const raw = ($("#rawHttp") && $("#rawHttp").value) || state.rawHttp || "";
    state.rawHttp = raw;
    writePipelineDraft();
    if (!state.current) {
      if (!silent) toast("未选项目：已暂存在本机，选项目后会写入 state.json");
      return null;
    }
    if (_autoSaving) return null;
    _autoSaving = true;
    try {
      const out = await api(`/api/projects/${encodeURIComponent(state.current)}/state`, {
        method: "PUT",
        body: JSON.stringify({
          steps: state.steps,
          parsed_fields: state.fields,
          body_format: state.bodyFormat || "json",
          raw_http: raw,
          write_plugin: !!writePlugin,
        }),
      });
      state._pipelineDirty = false;
      if (writePlugin && out.plugin_code && $("#projectCode")) {
        $("#projectCode").value = out.plugin_code;
        if (typeof syncProjectCodeHighlight === "function") syncProjectCodeHighlight();
      }
      if (!silent) {
        toast(
          writePlugin
            ? `已保存 ${out.plugin_path}（${out.steps} 步）`
            : `已自动保存步骤（${out.steps} 步）`
        );
      } else if ($("#parseHint") && state.steps.length) {
        $("#parseHint").textContent = `已自动保存 ${state.steps.length} 步 · 刷新页面可恢复`;
      }
      return out;
    } catch (e) {
      console.warn("auto-save failed", e);
      if (!silent) showErr(e);
      return null;
    } finally {
      _autoSaving = false;
    }
  }

  function schedulePipelineAutoSave(delayMs) {
    state._pipelineDirty = true;
    writePipelineDraft();
    if (_autoSaveTimer) clearTimeout(_autoSaveTimer);
    _autoSaveTimer = setTimeout(() => {
      persistPipelineState({ writePlugin: false, silent: true }).catch(() => {});
    }, delayMs == null ? 600 : delayMs);
  }

  window.addEventListener("beforeunload", () => {
    if (state._pipelineDirty || state.steps.length || state.rawHttp) writePipelineDraft();
  });

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden" && state._pipelineDirty) {
      persistPipelineState({ writePlugin: false, silent: true }).catch(() => {});
    }
  });

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
      ...opts,
    });
    const text = await res.text();
    let data;
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      throw new Error(text || res.statusText);
    }
    if (!res.ok) {
      const detail = data.detail;
      throw new Error(
        typeof detail === "string"
          ? detail
          : detail
            ? JSON.stringify(detail)
            : data.error || res.statusText
      );
    }
    return data;
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }
  function escapeAttr(s) {
    return escapeHtml(s).replace(/'/g, "&#39;");
  }
  function showErr(e) {
    console.error(e);
    alert(e.message || String(e));
  }
  function toast(msg) {
    $("#sideStatus").textContent = msg;
  }

  function showTab(name) {
    $$(".panel").forEach((p) => p.classList.toggle("active", p.id === `tab-${name}`));
    $$("#nav button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  }
  $$("#nav button").forEach((btn) =>
    btn.addEventListener("click", () => showTab(btn.dataset.tab))
  );

  // ── 全局项目 ──────────────────────────────────────
  function fillProjectSelects() {
    const opts = state.projects
      .filter((p) => !p.is_template)
      .map(
        (p) =>
          `<option value="${escapeAttr(p.id)}">${escapeHtml(p.name)}${
            p.plugin_exists ? "" : " · 无插件"
          }</option>`
      )
      .join("");
    ["#globalProject", "#proxyProject"].forEach((sel) => {
      const el = $(sel);
      const cur = el.value || state.current;
      el.innerHTML = opts;
      if (cur) el.value = cur;
    });
  }

  $("#globalProject").addEventListener("change", async () => {
    if (state._pipelineDirty) {
      await persistPipelineState({ writePlugin: false, silent: true });
    }
    rememberCurrentProject($("#globalProject").value);
    await openProject(state.current);
    await loadPipelineFromProject();
  });

  // ── 概览 ──────────────────────────────────────────
  async function loadHome() {
    const st = await api("/api/status");
    $("#sideStatus").textContent = `${st.name} ${st.version} · Web ${st.web_version}`;
    const n = state.projects.filter((p) => !p.is_template).length;
    const withPlugin = state.projects.filter((p) => !p.is_template && p.plugin_exists).length;
    $("#homeCards").innerHTML = [
      ["产品", `${st.name} ${st.version}`],
      ["项目数", `${n}（有插件 ${withPlugin}）`],
      ["代理控制", st.allow_proxy_ctrl ? "已授权" : "只读"],
      ["当前项目", state.current || "-"],
    ]
      .map(
        ([k, v]) =>
          `<div class="card"><div class="k">${k}</div><div class="v">${escapeHtml(
            String(v)
          )}</div></div>`
      )
      .join("");
    $("#homeNote").innerHTML = `
      <strong>Web AI 分析已对齐桌面主流程</strong>：浏览器启动（普通注入 / 真实浏览器 / CDP）、
      流量·JS·Hook 采集、多模式 Agent、全量策略扫描、写回项目。<br/>
      桌面 GUI 仍更适合：独立通关弹窗里的实时点选验证码、油猴安装引导等细交互。`;
  }

  // ── 项目 ──────────────────────────────────────────
  function highlightPy(src) {
    const s = String(src || "");
    const max = 120000;
    const chunk = s.length > max ? s.slice(0, max) : s;
    const kw =
      "False|None|True|and|as|assert|async|await|break|class|continue|def|del|elif|else|except|finally|for|from|global|if|import|in|is|lambda|nonlocal|not|or|pass|raise|return|try|while|with|yield";
    const builtin =
      "abs|all|any|bin|bool|bytearray|bytes|callable|chr|classmethod|dict|dir|enumerate|eval|filter|float|format|frozenset|getattr|hasattr|hash|help|hex|id|input|int|isinstance|issubclass|iter|len|list|map|max|min|next|object|oct|open|ord|pow|print|property|range|repr|reversed|round|set|setattr|slice|sorted|staticmethod|str|sum|super|tuple|type|vars|zip";
    const re = new RegExp(
      String.raw`(#[^\n]*|"""[\s\S]*?"""|'''[\s\S]*?''')|(@[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|\b(${kw})\b|\b(${builtin})\b|\b(0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\b|([{}()\[\];,.:=+\-*/%&|^~<>!]+)|(\s+)|([A-Za-z_]\w*)`,
      "g"
    );
    let out = "";
    let m;
    while ((m = re.exec(chunk))) {
      if (m[1]) out += `<span class="hk-comment">${escapeHtml(m[1])}</span>`;
      else if (m[2]) out += `<span class="hk-decorator">${escapeHtml(m[2])}</span>`;
      else if (m[3]) out += `<span class="hk-str">${escapeHtml(m[3])}</span>`;
      else if (m[4]) out += `<span class="hk-kw">${escapeHtml(m[4])}</span>`;
      else if (m[5]) out += `<span class="hk-builtin">${escapeHtml(m[5])}</span>`;
      else if (m[6]) out += `<span class="hk-num">${escapeHtml(m[6])}</span>`;
      else if (m[7]) out += `<span class="hk-op">${escapeHtml(m[7])}</span>`;
      else if (m[8]) out += escapeHtml(m[8]);
      else if (m[9]) out += `<span class="hk-ident">${escapeHtml(m[9])}</span>`;
    }
    if (s.length > max) {
      out += `<span class="hk-muted">\n…(代码过长，已截断高亮)</span>`;
    }
    // 末尾补换行，避免最后一行高度对不齐
    if (!out.endsWith("\n")) out += "\n";
    return out || "\n";
  }

  let _projHlTimer = null;
  function syncProjectCodeHighlight() {
    const ta = $("#projectCode");
    const hl = $("#projectCodeHl");
    if (!ta || !hl) return;
    hl.innerHTML = highlightPy(ta.value);
    hl.scrollTop = ta.scrollTop;
    hl.scrollLeft = ta.scrollLeft;
  }

  function scheduleProjectCodeHighlight() {
    if (_projHlTimer) clearTimeout(_projHlTimer);
    _projHlTimer = setTimeout(syncProjectCodeHighlight, 60);
  }

  function roleLabel(roles) {
    const r = Array.isArray(roles) ? roles : [];
    const hasD = r.includes("decrypt");
    const hasE = r.includes("encrypt");
    if (hasD && hasE) return "解密 · 加密";
    if (hasD) return "解密";
    if (hasE) return "加密";
    return "未设角色";
  }

  function clearProjectMeta() {
    const set = (id, text) => {
      const el = $(id);
      if (el) el.textContent = text;
    };
    set("#projMetaName", "—");
    set("#projMetaRoles", "—");
    set("#projMetaPlugin", "—");
    set("#projMetaFiles", "—");
    set("#projMetaMatch", "—");
    set("#projectMeta", "plugin.py");
  }

  function renderProjectList(filterText) {
    const list = $("#projectList");
    if (!list) return;
    const q = String(filterText || "").trim().toLowerCase();
    const items = state.projects.filter((p) => {
      if (p.is_template) return false;
      if (!q) return true;
      const hay = `${p.id} ${p.name} ${(p.roles || []).join(" ")} ${p.plugin || ""}`.toLowerCase();
      return hay.includes(q);
    });
    const count = $("#projectCount");
    if (count) count.textContent = String(items.length);
    if (!items.length) {
      list.innerHTML = `<div class="muted" style="padding:12px">${
        q ? "无匹配项目" : "暂无项目，点「新建」开始"
      }</div>`;
      return;
    }
    list.innerHTML = items
      .map((p) => {
        const isCur = p.id === state.current;
        const miss = !p.plugin_exists;
        return `<button type="button" data-id="${escapeAttr(p.id)}" class="${
          isCur ? "active" : ""
        }${miss ? " miss" : ""}">
          <div class="proj-row-main">
            <div class="name" title="${escapeAttr(p.name)}">${escapeHtml(p.name)}</div>
            <div class="sub">${escapeHtml(roleLabel(p.roles))} · ${
          miss ? "缺 plugin.py" : "有插件"
        }</div>
          </div>
          ${isCur ? '<span class="cur">当前</span>' : ""}
        </button>`;
      })
      .join("");
    list.querySelectorAll("button").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (state._pipelineDirty) {
          await persistPipelineState({ writePlugin: false, silent: true });
        }
        rememberCurrentProject(btn.dataset.id);
        if ($("#globalProject")) $("#globalProject").value = state.current;
        openProject(state.current).catch(showErr);
        loadPipelineFromProject().catch(showErr);
      });
    });
  }

  async function loadProjects() {
    const data = await api("/api/projects");
    state.projects = data.projects || [];
    fillProjectSelects();
    const remembered = localStorage.getItem("cb_current_project") || state.current;
    const exists = state.projects.some((p) => p.id === remembered && !p.is_template);
    if (exists) {
      rememberCurrentProject(remembered);
      if ($("#globalProject")) $("#globalProject").value = state.current;
    } else if (!state.current && state.projects.length) {
      const first = state.projects.find((p) => !p.is_template);
      if (first) {
        rememberCurrentProject(first.id);
        if ($("#globalProject")) $("#globalProject").value = state.current;
      }
    }
    const filter = ($("#projectFilter") && $("#projectFilter").value) || "";
    renderProjectList(filter);
  }

  async function openProject(id) {
    if (!id) return;
    const metaPath = $("#projectMeta");
    if (metaPath) metaPath.textContent = `加载 ${id}…`;
    $("#btnSavePlugin").disabled = true;
    $("#btnDeleteProject").disabled = true;
    const data = await api(`/api/projects/${encodeURIComponent(id)}`);
    const profile = data.profile || {};
    const roles = profile.roles || [];
    const match = profile.match && typeof profile.match === "object" ? profile.match : {};
    const hosts = match.host || [];
    const paths = match.path || [];
    const matchBits = [];
    if (hosts.length) matchBits.push("host=" + hosts.slice(0, 3).join(","));
    if (paths.length) matchBits.push("path=" + paths.slice(0, 3).join(","));

    const set = (sel, text) => {
      const el = $(sel);
      if (el) el.textContent = text;
    };
    set("#projMetaName", data.id || id);
    set("#projMetaRoles", roleLabel(roles));
    set("#projMetaPlugin", data.plugin_path || `plugins/${id}/`);
    set(
      "#projMetaFiles",
      [
        data.plugin_exists ? "plugin.py ✓" : "plugin.py 缺失",
        data.has_state ? "state.json ✓" : "state.json —",
      ].join(" · ")
    );
    set("#projMetaMatch", matchBits.join(" · ") || "未限制");
    set("#projectMeta", data.plugin_path || `plugins/${id}/plugin.py`);

    $("#projectCode").value =
      data.plugin_code ||
      `# 尚无 plugins 代码。可在「可视化构建」添加步骤后保存，或点保存写入空白模板。\n`;
    syncProjectCodeHighlight();
    $("#btnSavePlugin").disabled = false;
    $("#btnDeleteProject").disabled = false;
    renderProjectList(($("#projectFilter") && $("#projectFilter").value) || "");
  }

  $("#projectFilter") &&
    $("#projectFilter").addEventListener("input", () => {
      renderProjectList($("#projectFilter").value);
    });

  (function bindProjectCodeEditor() {
    const ta = $("#projectCode");
    if (!ta) return;
    ta.addEventListener("input", scheduleProjectCodeHighlight);
    ta.addEventListener("scroll", () => {
      const hl = $("#projectCodeHl");
      if (!hl) return;
      hl.scrollTop = ta.scrollTop;
      hl.scrollLeft = ta.scrollLeft;
    });
    // Tab 插入空格，避免失焦
    ta.addEventListener("keydown", (e) => {
      if (e.key !== "Tab" || e.ctrlKey || e.metaKey || e.altKey) return;
      e.preventDefault();
      const start = ta.selectionStart;
      const end = ta.selectionEnd;
      const v = ta.value;
      ta.value = v.slice(0, start) + "    " + v.slice(end);
      ta.selectionStart = ta.selectionEnd = start + 4;
      scheduleProjectCodeHighlight();
    });
  })();

  $("#btnRefreshProjects").addEventListener("click", () =>
    loadProjects().then(loadHome).catch(showErr)
  );
  $("#btnSavePlugin").addEventListener("click", async () => {
    if (!state.current) return;
    try {
      const out = await api(`/api/projects/${encodeURIComponent(state.current)}/plugin`, {
        method: "PUT",
        body: JSON.stringify({ code: $("#projectCode").value }),
      });
      toast(`已保存 ${out.plugin_path}`);
      await loadProjects();
    } catch (e) {
      showErr(e);
    }
  });
  $("#btnDeleteProject").addEventListener("click", async () => {
    if (!state.current) return;
    if (!confirm(`删除项目 ${state.current}？`)) return;
    try {
      await api(`/api/projects/${encodeURIComponent(state.current)}`, { method: "DELETE" });
      state.current = "";
      await loadProjects();
      $("#projectCode").value = "";
      syncProjectCodeHighlight();
      clearProjectMeta();
      $("#btnSavePlugin").disabled = true;
      $("#btnDeleteProject").disabled = true;
      if (state.current) await openProject(state.current);
      toast("项目已删除");
    } catch (e) {
      showErr(e);
    }
  });
  $("#btnNewProject").addEventListener("click", async () => {
    const name = prompt("新项目名称");
    if (!name) return;
    const roles = ["decrypt"];
    if (confirm("同时启用加密端角色？")) roles.push("encrypt");
    try {
      const out = await api("/api/projects", {
        method: "POST",
        body: JSON.stringify({ name, roles }),
      });
      rememberCurrentProject(out.id);
      await loadProjects();
      $("#globalProject").value = state.current;
      await openProject(state.current);
      state.steps = [];
      state.fields = {};
      state.rawHttp = "";
      if ($("#rawHttp")) $("#rawHttp").value = "";
      renderSteps();
      await refreshPreview();
      await persistPipelineState({ writePlugin: false, silent: true });
      toast(`已创建 ${out.id}`);
      showTab("builder");
    } catch (e) {
      showErr(e);
    }
  });

  // ── 请求解析 ──────────────────────────────────────
  let _rawHlTimer = null;

  function syncRawHttpHighlight() {
    const ta = $("#rawHttp");
    const hl = $("#rawHttpHl");
    if (!ta || !hl) return;
    const text = ta.value || "";
    if (!text.trim()) {
      hl.innerHTML = "";
    } else if (typeof highlightHttp === "function") {
      hl.innerHTML = highlightHttp(text) + "\n";
    } else {
      hl.textContent = text + "\n";
    }
    hl.scrollTop = ta.scrollTop;
    hl.scrollLeft = ta.scrollLeft;
  }

  function scheduleRawHttpHighlight() {
    if (_rawHlTimer) clearTimeout(_rawHlTimer);
    _rawHlTimer = setTimeout(syncRawHttpHighlight, 60);
  }

  function clipVal(v, n) {
    const s = String(v ?? "");
    return s.length > n ? s.slice(0, n) + "…" : s;
  }

  let _fieldOpCtx = null; // { field, value, scope }

  function stripOpEmoji(t) {
    return String(t || "").replace(/^[^\w\u4e00-\u9fffA-Za-z0-9(]+\s*/, "");
  }

  function looksEncrypted(val) {
    const s = String(val || "");
    if (s.length < 16) return false;
    return /^[A-Za-z0-9+/=_-]+$/.test(s);
  }

  function detectScopeFromGroup(groupKey) {
    const g = String(groupKey || "").toLowerCase();
    if (g.includes("response") || g.includes("响应")) return "response";
    if (g.includes("query") || g.includes("url")) return "query";
    if (g.includes("form")) return "form";
    if (g.includes("header")) return "header";
    return "body";
  }

  function appendFieldLeaf(box, key, value, scope) {
    const row = document.createElement("div");
    row.className = "leaf";
    row.title = "点击添加加解密";
    const full = String(value ?? "");
    row.innerHTML = `<span class="fk" title="${escapeAttr(key)}">${escapeHtml(
      key
    )}</span><span class="fv" title="${escapeAttr(full)}">${escapeHtml(
      clipVal(full, 160)
    )}</span>`;
    row.addEventListener("click", () => openFieldOpDialog(key, full, scope));
    box.appendChild(row);
  }

  function renderTree(nodes, root, parentScope) {
    if (!root) return;
    root.innerHTML = "";
    if (!nodes || !nodes.length) {
      root.innerHTML = `<div class="parser-empty">未解析到字段。检查报文是否完整（请求行 / Headers / 空行 / Body）。</div>`;
      return;
    }
    (nodes || []).forEach((n) => {
      const scope = detectScopeFromGroup(n.key) || parentScope || "body";
      if (n.children && n.children.length) {
        const d = document.createElement("details");
        d.open = true;
        const sum = document.createElement("summary");
        sum.textContent = n.value ? `${n.key} · ${n.value}` : n.key;
        d.appendChild(sum);
        const box = document.createElement("div");
        n.children.forEach((c) => {
          if (c.children) {
            renderTree([c], box, scope);
            return;
          }
          appendFieldLeaf(box, c.key, c.value, scope);
        });
        d.appendChild(box);
        root.appendChild(d);
      } else {
        appendFieldLeaf(root, n.key, n.value, scope);
      }
    });
  }

  function setHighlightedPy(el, code) {
    if (!el) return;
    const text = code || "";
    el.dataset.plain = text;
    if (!text) {
      el.textContent = "";
      el.innerHTML = "";
      return;
    }
    try {
      el.innerHTML = highlightPy(text);
    } catch (_) {
      el.textContent = text;
    }
  }

  function setParserCodePreview(code) {
    const el = $("#parserCodePreview");
    const meta = $("#parserCodeMeta");
    setHighlightedPy(el, code);
    if (meta) {
      meta.textContent = state.current
        ? `${state.steps.length} 步 · ${state.current}`
        : `${state.steps.length} 步 · 未选项目`;
    }
  }

  function rebuildFieldOpParams(opType, fieldName) {
    const box = $("#fieldOpParams");
    if (!box) return;
    const op = state.ops.find((o) => o.type === opType) || {};
    const fields = op.fields || [];
    const defaults = { ...(op.defaults || {}) };
    if (fieldName) {
      if ("field" in defaults) defaults.field = fieldName;
      if ("source" in defaults) defaults.source = fieldName;
    }
    if (!fields.length) {
      // 无 schema 时用 defaults 键生成输入
      box.innerHTML = Object.keys(defaults)
        .map(
          (k) =>
            `<label>${escapeHtml(k)}<input data-pk="${escapeAttr(k)}" value="${escapeAttr(
              String(defaults[k] ?? "")
            )}" /></label>`
        )
        .join("");
      return;
    }
    box.innerHTML = fields
      .map(([label, key, choices]) => {
        const val = defaults[key] ?? "";
        if (Array.isArray(choices) && choices.length) {
          return `<label>${escapeHtml(label)}
            <select data-pk="${escapeAttr(key)}">
              ${choices
                .map(
                  (c) =>
                    `<option value="${escapeAttr(c)}" ${
                      String(c) === String(val) ? "selected" : ""
                    }>${escapeHtml(c)}</option>`
                )
                .join("")}
            </select>
          </label>`;
        }
        return `<label>${escapeHtml(label)}
          <input data-pk="${escapeAttr(key)}" value="${escapeAttr(String(val))}" placeholder="${
          key === "key" || key === "iv" ? "输入密钥 或 $变量名" : ""
        }" />
        </label>`;
      })
      .join("");
  }

  function collectFieldOpParams() {
    const params = {};
    $$("#fieldOpParams [data-pk]").forEach((el) => {
      params[el.dataset.pk] = el.value;
    });
    return params;
  }

  function openFieldOpDialog(field, value, scope) {
    if (!state.ops.length) {
      toast("操作类型尚未加载");
      return;
    }
    _fieldOpCtx = { field, value, scope: scope || "body" };
    const encrypted = looksEncrypted(value);
    let prefer =
      scope === "response"
        ? encrypted
          ? "🔓 解密响应字段"
          : "🔒 加密响应字段"
        : encrypted
          ? "🔓 解密字段"
          : "🔒 加密字段";
    if (!state.ops.some((o) => o.type === prefer)) prefer = state.ops[0].type;

    const title = $("#fieldOpTitle");
    if (title) title.textContent = `添加加解密 — ${field}`;
    const valEl = $("#fieldOpValue");
    if (valEl) valEl.textContent = value || "(空)";
    const sel = $("#fieldOpType");
    if (sel) {
      sel.innerHTML = state.ops
        .map(
          (o) =>
            `<option value="${escapeAttr(o.type)}">${escapeHtml(
              stripOpEmoji(o.type)
            )}</option>`
        )
        .join("");
      sel.value = prefer;
    }
    rebuildFieldOpParams(prefer, field);
    const test = $("#fieldOpTest");
    if (test) {
      test.className = "field-op-test";
      test.textContent = "填好密钥后可点「测试」预览";
    }
    $("#fieldOpMask").hidden = false;
  }

  function closeFieldOpDialog() {
    const mask = $("#fieldOpMask");
    if (mask) mask.hidden = true;
    _fieldOpCtx = null;
  }

  async function testFieldOp() {
    const ctx = _fieldOpCtx;
    const test = $("#fieldOpTest");
    if (!ctx || !test) return;
    const opType = ($("#fieldOpType") && $("#fieldOpType").value) || "";
    const params = collectFieldOpParams();
    test.className = "field-op-test";
    test.textContent = "测试中…";
    try {
      if (opType.includes("编码")) {
        const enc = params.encoding || "";
        const map = {
          Base64编码: "b64_encode",
          Base64解码: "b64_decode",
          Hex编码: "hex_encode",
          Hex解码: "hex_decode",
          URL编码: "url_encode",
          URL解码: "url_decode",
        };
        const apiOp = map[enc];
        if (!apiOp) {
          test.textContent = "请选择编码类型";
          return;
        }
        const data = await api("/api/crypto/encode", {
          method: "POST",
          body: JSON.stringify({ op: apiOp, data: ctx.value }),
        });
        const r = data.result ?? data.output ?? JSON.stringify(data);
        test.className = "field-op-test ok";
        test.textContent = `结果: ${String(r).slice(0, 240)}`;
        return;
      }
      if (!opType.includes("加密") && !opType.includes("解密")) {
        test.textContent = "当前操作类型暂不支持就地测试（仍可确定加入步骤）";
        return;
      }
      const key = params.key || "";
      if (!key || String(key).startsWith("$")) {
        test.textContent = "请先填写密钥再测试";
        return;
      }
      const data = await api("/api/crypto/aes", {
        method: "POST",
        body: JSON.stringify({
          op: opType.includes("解密") ? "decrypt" : "encrypt",
          data: ctx.value,
          key,
          mode: params.mode || "ECB",
          padding: params.padding || "PKCS7",
          iv: params.iv || "",
          fmt: params.input_fmt || "base64",
        }),
      });
      const r = data.result ?? data.output ?? data.plain ?? data.ciphertext ?? JSON.stringify(data);
      test.className = "field-op-test ok";
      test.textContent = (opType.includes("解密") ? "解密结果: " : "加密结果: ") + String(r).slice(0, 240);
    } catch (e) {
      test.className = "field-op-test err";
      test.textContent = String(e.message || e);
    }
  }

  function confirmFieldOp() {
    const ctx = _fieldOpCtx;
    if (!ctx) return;
    const opType = ($("#fieldOpType") && $("#fieldOpType").value) || "";
    if (!opType) return;
    const params = collectFieldOpParams();
    // scope 标签与 GUI 大致对齐
    if (params.scope == null || params.scope === "body" || params.scope === "form") {
      if (ctx.scope === "response") params.scope = "response";
      else if (ctx.scope === "form") params.scope = "📋 Body (Form)";
      else if (ctx.scope === "query") params.scope = "🔗 URL Query";
      else if (ctx.scope === "body") params.scope = "📋 Body (JSON)";
    }
    state.steps.push({ type: opType, params });
    closeFieldOpDialog();
    renderSteps();
    refreshPreview();
    schedulePipelineAutoSave(400);
    if ($("#fieldActions")) {
      $("#fieldActions").textContent = `已添加 ${stripOpEmoji(opType)} · ${ctx.field}（共 ${
        state.steps.length
      } 步）`;
    }
    if ($("#parseHint")) {
      $("#parseHint").textContent = `已添加 ${state.steps.length} 步 · 自动保存中…`;
    }
    toast(`已添加: ${stripOpEmoji(opType)} → ${ctx.field}`);
  }

  $("#btnClearHttp") &&
    $("#btnClearHttp").addEventListener("click", () => {
      if ($("#rawHttp")) $("#rawHttp").value = "";
      state.rawHttp = "";
      syncRawHttpHighlight();
      const tree = $("#parseTree");
      if (tree) {
        tree.innerHTML = `<div class="parser-empty" id="parseEmpty">
          粘贴上方报文后点「解析」。<br />
          再<strong>点击字段值</strong>弹出加解密配置（同 GUI）。
        </div>`;
      }
      if ($("#parseMeta")) $("#parseMeta").textContent = "尚未解析 · 点击字段值添加加解密";
      if ($("#fieldActions")) $("#fieldActions").textContent = "";
      // 不清空步骤；只清报文。步骤用「撤销/构建器清空」
      schedulePipelineAutoSave(400);
    });

  $("#btnUndoStep") &&
    $("#btnUndoStep").addEventListener("click", () => {
      if (!state.steps.length) {
        toast("没有可撤销的步骤");
        return;
      }
      const last = state.steps.pop();
      renderSteps();
      refreshPreview();
      schedulePipelineAutoSave(300);
      toast(`已撤销: ${stripOpEmoji(last.type)}`);
    });

  $("#btnSaveFromParser") &&
    $("#btnSaveFromParser").addEventListener("click", () => {
      if ($("#btnSavePipeline")) $("#btnSavePipeline").click();
      else toast("请先在构建器保存");
    });

  $("#btnCopyParserCode") &&
    $("#btnCopyParserCode").addEventListener("click", async () => {
      const el = $("#parserCodePreview");
      const text = el ? el.textContent || "" : "";
      if (!text.trim()) {
        toast("暂无代码可复制");
        return;
      }
      try {
        await navigator.clipboard.writeText(text);
        toast("已复制代码");
      } catch {
        toast("复制失败");
      }
    });

  $("#btnParseHttp").addEventListener("click", async () => {
    try {
      const raw = $("#rawHttp").value;
      if (!String(raw || "").trim()) {
        toast("请先粘贴 HTTP 报文");
        return;
      }
      const data = await api("/api/http/parse", {
        method: "POST",
        body: JSON.stringify({
          raw,
          include_response: $("#parseResp").checked,
        }),
      });
      if (!data.ok) throw new Error(data.error || "解析失败");
      state.fields = data.fields || {};
      state.bodyFormat = data.body_format || "json";
      state.rawHttp = raw;
      const n = Object.keys(state.fields).length;
      $("#parseMeta").textContent = `${data.method || ""} ${data.url || data.path || ""} · ${n} 字段 · ${
        data.body_format || "-"
      } · 点击字段值添加加解密`;
      renderTree(data.tree || [], $("#parseTree"));
      if ($("#fieldActions")) {
        $("#fieldActions").textContent =
          n > 0 ? "点击字段值配置加解密；右侧实时看生成代码。" : "未识别到可操作字段。";
      }
      syncRawHttpHighlight();
      refreshPreview();
      schedulePipelineAutoSave(500);
      toast("解析完成");
    } catch (e) {
      showErr(e);
    }
  });

  (function bindRawHttpEditor() {
    const ta = $("#rawHttp");
    if (!ta) return;
    ta.addEventListener("input", scheduleRawHttpHighlight);
    ta.addEventListener("paste", () => setTimeout(syncRawHttpHighlight, 0));
    ta.addEventListener("blur", () => {
      state.rawHttp = ta.value || "";
      if (String(state.rawHttp).trim()) schedulePipelineAutoSave(700);
    });
    ta.addEventListener("scroll", () => {
      const hl = $("#rawHttpHl");
      if (!hl) return;
      hl.scrollTop = ta.scrollTop;
      hl.scrollLeft = ta.scrollLeft;
    });
    if (ta.value) scheduleRawHttpHighlight();
  })();

  (function bindFieldOpDialog() {
    const mask = $("#fieldOpMask");
    if (!mask) return;
    $("#btnFieldOpClose") && $("#btnFieldOpClose").addEventListener("click", closeFieldOpDialog);
    $("#btnFieldOpCancel") && $("#btnFieldOpCancel").addEventListener("click", closeFieldOpDialog);
    $("#btnFieldOpOk") && $("#btnFieldOpOk").addEventListener("click", confirmFieldOp);
    $("#btnFieldOpTest") &&
      $("#btnFieldOpTest").addEventListener("click", () => testFieldOp().catch(showErr));
    $("#fieldOpType") &&
      $("#fieldOpType").addEventListener("change", () => {
        const t = $("#fieldOpType").value;
        rebuildFieldOpParams(t, _fieldOpCtx && _fieldOpCtx.field);
      });
    mask.addEventListener("click", (e) => {
      if (e.target === mask) closeFieldOpDialog();
    });
  })();

  // ── 构建器 ────────────────────────────────────────
  function stepSummary(opType, params) {
    const p = params || {};
    const parts = [];
    const field =
      p.field || p.field_path || p.source || p.target_field || p.target || p.header_name || p.key_name;
    if (field) parts.push(String(field));
    if (p.algo) parts.push(String(p.algo));
    if (p.mode) parts.push(String(p.mode));
    if (p.encode_type || p.encoding) parts.push(String(p.encode_type || p.encoding));
    return parts.length ? parts.join(" · ") : stripOpEmoji(opType);
  }

  function renderParamControl(i, label, key, value, choices) {
    const v = value == null ? "" : String(value);
    if (Array.isArray(choices) && choices.length) {
      const opts = choices
        .map(
          (c) =>
            `<option value="${escapeAttr(c)}"${c === v ? " selected" : ""}>${escapeHtml(
              c
            )}</option>`
        )
        .join("");
      return `<label>${escapeHtml(label)}
        <select data-i="${i}" data-k="${escapeAttr(key)}">${opts}</select></label>`;
    }
    return `<label>${escapeHtml(label)}
      <input data-i="${i}" data-k="${escapeAttr(key)}" value="${escapeAttr(v)}" /></label>`;
  }

  async function loadOps() {
    const data = await api("/api/pipeline/ops");
    state.ops = data.ops || [];
    const sel = $("#addOpSelect");
    if (!sel) return;
    const groups = {};
    state.ops.forEach((o) => {
      const g = o.group || "其他";
      if (!groups[g]) groups[g] = [];
      groups[g].push(o);
    });
    sel.innerHTML = Object.keys(groups)
      .map((g) => {
        const opts = groups[g]
          .map((o) => `<option value="${escapeAttr(o.type)}">${escapeHtml(o.type)}</option>`)
          .join("");
        return `<optgroup label="${escapeAttr(g)}">${opts}</optgroup>`;
      })
      .join("");
  }

  async function loadTemplates() {
    const sel = $("#tplSelect");
    if (!sel) return;
    try {
      const data = await api("/api/pipeline/templates");
      const list = data.templates || [];
      const groups = {};
      list.forEach((t) => {
        const g = t.group || "其他";
        if (!groups[g]) groups[g] = [];
        groups[g].push(t);
      });
      let html = `<option value="">选择案例加载…</option>`;
      Object.keys(groups).forEach((g) => {
        html += `<optgroup label="${escapeAttr("── " + g + " ──")}">`;
        groups[g].forEach((t) => {
          html += `<option value="${escapeAttr(t.name)}" title="${escapeAttr(
            t.desc || ""
          )}">${escapeHtml(t.name)}（${t.step_count || (t.steps || []).length}步）</option>`;
        });
        html += `</optgroup>`;
      });
      sel.innerHTML = html;
    } catch (e) {
      console.warn(e);
    }
  }

  function renderSteps() {
    const box = $("#stepsList");
    const count = $("#stepsCount");
    if (count) count.textContent = String(state.steps.length);
    if (!box) return;
    if (!state.steps.length) {
      box.innerHTML = `<div class="steps-empty">
        暂无步骤<br /><br />
        从上方选案例模板，或点「添加步骤」<br />
        也可在「请求解析」点击字段值配置加解密<br />
        右侧会实时生成插件代码
      </div>`;
      return;
    }
    box.innerHTML = state.steps
      .map((s, i) => {
        const op = state.ops.find((o) => o.type === s.type) || {};
        const schema = op.fields || [];
        const p = { ...(op.defaults || {}), ...(s.params || {}) };
        s.params = p;
        const used = new Set();
        let fields = schema
          .map((f) => {
            const label = Array.isArray(f) ? f[0] : f.label || f[0];
            const key = Array.isArray(f) ? f[1] : f.key || f[1];
            const choices = Array.isArray(f) ? f[2] : f.choices || f[2];
            used.add(key);
            return renderParamControl(i, label, key, p[key], choices);
          })
          .join("");
        // 兼容未在 schema 中的额外参数
        Object.keys(p).forEach((k) => {
          if (used.has(k) || k.startsWith("_")) return;
          fields += renderParamControl(i, k, k, p[k], null);
        });
        const summary = stepSummary(s.type, p);
        return `<div class="step-card" data-i="${i}">
          <div class="top">
            <div class="step-title">
              <span class="idx">${i + 1}</span>
              <strong title="${escapeAttr(summary)}">${escapeHtml(s.type)}</strong>
              <span class="muted tiny step-sum">${escapeHtml(summary)}</span>
            </div>
            <div class="row gap">
              <button type="button" class="btn" data-up="${i}" title="上移">↑</button>
              <button type="button" class="btn" data-down="${i}" title="下移">↓</button>
              <button type="button" class="btn ghost" data-del="${i}" title="删除">×</button>
            </div>
          </div>
          <div class="fields">${fields || '<span class="muted tiny">（无参数）</span>'}</div>
        </div>`;
      })
      .join("");

    const bindParam = (el) => {
      const apply = () => {
        const i = Number(el.dataset.i);
        const k = el.dataset.k;
        if (!state.steps[i]) return;
        state.steps[i].params[k] = el.value;
      };
      el.addEventListener("change", () => {
        apply();
        refreshPreview();
        schedulePipelineAutoSave(500);
      });
      if (el.tagName === "INPUT") {
        el.addEventListener("input", apply);
        el.addEventListener("blur", () => {
          refreshPreview();
          schedulePipelineAutoSave(400);
        });
      }
    };
    box.querySelectorAll("input[data-k], select[data-k]").forEach(bindParam);
    box.querySelectorAll("[data-del]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.steps.splice(Number(btn.dataset.del), 1);
        renderSteps();
        refreshPreview();
        schedulePipelineAutoSave(300);
      });
    });
    box.querySelectorAll("[data-up]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const i = Number(btn.dataset.up);
        if (i <= 0) return;
        [state.steps[i - 1], state.steps[i]] = [state.steps[i], state.steps[i - 1]];
        renderSteps();
        refreshPreview();
        schedulePipelineAutoSave(300);
      });
    });
    box.querySelectorAll("[data-down]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const i = Number(btn.dataset.down);
        if (i >= state.steps.length - 1) return;
        [state.steps[i + 1], state.steps[i]] = [state.steps[i], state.steps[i + 1]];
        renderSteps();
        refreshPreview();
        schedulePipelineAutoSave(300);
      });
    });
  }

  async function refreshPreview() {
    const el = $("#codePreview");
    const meta = $("#codePreviewMeta");
    try {
      const data = await api("/api/pipeline/preview", {
        method: "POST",
        body: JSON.stringify({
          steps: state.steps,
          body_format: state.bodyFormat || "json",
          profile_name: state.current || "",
        }),
      });
      const code = data.code || "";
      if (data.error && !code) {
        setHighlightedPy(el, `# 生成失败\n# ${data.error}`);
        setParserCodePreview("");
      } else {
        setHighlightedPy(el, code);
        setParserCodePreview(code);
      }
      if (meta) {
        meta.textContent = state.current
          ? `plugins/${state.current}/plugin.py · ${state.steps.length} 步`
          : `plugin.py · ${state.steps.length} 步`;
      }
    } catch (e) {
      setHighlightedPy(el, `# 预览错误\n# ${e.message || e}`);
    }
  }

  $("#btnAddOp").addEventListener("click", () => {
    const type = $("#addOpSelect").value;
    const op = state.ops.find((o) => o.type === type);
    if (!op) return;
    state.steps.push({ type: op.type, params: { ...op.defaults } });
    renderSteps();
    refreshPreview();
    schedulePipelineAutoSave(300);
  });

  $("#btnUndoBuilderStep") &&
    $("#btnUndoBuilderStep").addEventListener("click", () => {
      if (!state.steps.length) return;
      state.steps.pop();
      renderSteps();
      refreshPreview();
      schedulePipelineAutoSave(300);
      toast("已撤销最后一步");
    });

  $("#btnClearSteps") &&
    $("#btnClearSteps").addEventListener("click", () => {
      if (!state.steps.length) return;
      if (!confirm(`清空全部 ${state.steps.length} 个步骤？`)) return;
      state.steps = [];
      renderSteps();
      refreshPreview();
      schedulePipelineAutoSave(200);
      toast("已清空步骤");
    });

  $("#btnCopyBuilderCode") &&
    $("#btnCopyBuilderCode").addEventListener("click", async () => {
      const el = $("#codePreview");
      const text = (el && el.dataset.plain) || (el && el.textContent) || "";
      if (!text.trim()) {
        toast("暂无代码可复制");
        return;
      }
      try {
        await navigator.clipboard.writeText(text);
        toast("代码已复制到剪贴板");
      } catch (_) {
        toast("复制失败，请手动选择");
      }
    });

  $("#tplSelect") &&
    $("#tplSelect").addEventListener("change", async () => {
      const sel = $("#tplSelect");
      const name = sel.value;
      if (!name) return;
      const opt = sel.selectedOptions[0];
      const tip = (opt && opt.title) || "";
      const msg =
        (tip ? tip + "\n\n" : "") +
        `将加载「${name}」，并清空当前步骤。确认？`;
      sel.value = "";
      if (!confirm(msg)) return;
      try {
        const out = await api("/api/pipeline/templates/load", {
          method: "POST",
          body: JSON.stringify({ name }),
        });
        if (!out.ok) throw new Error(out.error || "加载失败");
        state.steps = out.steps || [];
        renderSteps();
        await refreshPreview();
        schedulePipelineAutoSave(200);
        const hint = $("#tplHint");
        if (hint) hint.textContent = `已加载「${out.name}」— ${out.desc || ""}`;
        toast(`已加载案例：${out.name}`);
      } catch (e) {
        showErr(e);
      }
    });

  $("#btnSavePipeline").addEventListener("click", async () => {
    if (!state.current) {
      alert("请先选择或新建项目");
      return;
    }
    try {
      const out = await persistPipelineState({ writePlugin: true, silent: false });
      if (!out) return;
      await loadProjects();
      await openProject(state.current);
    } catch (e) {
      showErr(e);
    }
  });

  async function restoreParserTreeFromRaw(raw) {
    const text = String(raw || "").trim();
    if (!text || !$("#parseTree")) return false;
    try {
      const data = await api("/api/http/parse", {
        method: "POST",
        body: JSON.stringify({
          raw: text,
          include_response: !!( $("#parseResp") && $("#parseResp").checked ),
        }),
      });
      if (!data.ok) return false;
      state.fields = data.fields || state.fields || {};
      state.bodyFormat = data.body_format || state.bodyFormat || "json";
      const n = Object.keys(state.fields).length;
      if ($("#parseMeta")) {
        $("#parseMeta").textContent = `${data.method || ""} ${data.url || data.path || ""} · ${n} 字段 · ${
          data.body_format || "-"
        } · 已恢复`;
      }
      renderTree(data.tree || [], $("#parseTree"));
      if ($("#fieldActions")) {
        $("#fieldActions").textContent =
          n > 0 ? `已恢复字段树 · 共 ${state.steps.length} 步` : "已恢复报文，未识别到字段";
      }
      return true;
    } catch (e) {
      console.warn("restore parse tree", e);
      return false;
    }
  }

  async function loadPipelineFromProject() {
    const draft = readPipelineDraft();
    try {
      let st = {};
      let pluginCode = "";
      if (state.current) {
        const data = await api(`/api/projects/${encodeURIComponent(state.current)}`);
        st = data.state || {};
        pluginCode = data.plugin_code || "";
      }
      const diskSteps = Array.isArray(st.steps) ? st.steps : [];
      const diskRaw = st.raw_http || st.raw_input || "";
      const draftSteps = draft && Array.isArray(draft.steps) ? draft.steps : [];
      const draftRaw = (draft && draft.rawHttp) || "";
      const draftFresh = !!(draft && draft.ts && Date.now() - draft.ts < 10 * 60 * 1000);
      // 磁盘空而草稿有内容，或草稿很新且步骤更多 → 用草稿
      const preferDraft =
        draftFresh &&
        ((draftSteps.length > diskSteps.length) ||
          (!diskSteps.length && draftSteps.length) ||
          (!String(diskRaw).trim() && String(draftRaw).trim()));

      if (preferDraft && draftSteps.length) {
        state.steps = draftSteps;
      } else if (diskSteps.length) {
        state.steps = diskSteps;
      } else if (pluginCode) {
        const rev = await api("/api/pipeline/reverse", {
          method: "POST",
          body: JSON.stringify({ code: pluginCode }),
        });
        state.steps = rev.steps || [];
      } else if (draftSteps.length) {
        state.steps = draftSteps;
      } else {
        state.steps = [];
      }

      if (preferDraft && draft && draft.fields) state.fields = draft.fields;
      else if (st.parsed_fields) state.fields = st.parsed_fields;

      if (preferDraft && draft && draft.bodyFormat) state.bodyFormat = draft.bodyFormat;
      else if (st.body_format) state.bodyFormat = st.body_format;

      // GUI: raw_input；Web: raw_http
      const raw = (preferDraft && draftRaw) || diskRaw || draftRaw || "";
      if (raw) {
        state.rawHttp = raw;
        if ($("#rawHttp")) $("#rawHttp").value = raw;
        if (typeof syncRawHttpHighlight === "function") syncRawHttpHighlight();
        await restoreParserTreeFromRaw(raw);
      }

      renderSteps();
      await refreshPreview();
      state._pipelineDirty = false;
      if (preferDraft && state.current) {
        schedulePipelineAutoSave(800);
      }
    } catch (e) {
      console.warn(e);
      // 磁盘失败时仍尝试草稿
      if (draft) {
        if (Array.isArray(draft.steps)) state.steps = draft.steps;
        if (draft.fields) state.fields = draft.fields;
        if (draft.rawHttp && $("#rawHttp")) {
          state.rawHttp = draft.rawHttp;
          $("#rawHttp").value = draft.rawHttp;
          syncRawHttpHighlight();
          await restoreParserTreeFromRaw(draft.rawHttp);
        }
        renderSteps();
        await refreshPreview();
      }
    }
  }

  // ── 加解密 ────────────────────────────────────────
  let cryptoMode = "analyze";
  let _cryptoLastText = "";

  function setCryptoMeta(text) {
    const el = $("#cryptoOutMeta");
    if (el) el.textContent = text || "";
  }

  function formatCryptoResult(data) {
    if (data == null) return "";
    if (typeof data === "string") return data;
    // 优先展示主结果字段，完整 JSON 附后
    const primary =
      data.result ??
      data.output ??
      data.text ??
      data.plain ??
      data.ciphertext ??
      data.hash ??
      data.decoded ??
      data.encoded;
    if (primary != null && (typeof primary === "string" || typeof primary === "number")) {
      const rest = { ...data };
      delete rest.result;
      delete rest.output;
      delete rest.ok;
      const extra = Object.keys(rest).length
        ? "\n\n——\n" + JSON.stringify(rest, null, 2)
        : "";
      return String(primary) + extra;
    }
    return JSON.stringify(data, null, 2);
  }

  function renderCryptoForm() {
    const box = $("#cryptoForm");
    if (!box) return;
    if (cryptoMode === "analyze") {
      box.innerHTML = `<label class="span2 grow-area">密文 / 文本
        <textarea id="c_text" placeholder="粘贴 Base64 / Hex / JWT / 可疑密文…"></textarea>
      </label>`;
    } else if (cryptoMode === "aes") {
      box.innerHTML = `
        <label>操作<select id="c_op"><option value="decrypt">解密</option><option value="encrypt">加密</option></select></label>
        <label>模式<select id="c_mode"><option>ECB</option><option>CBC</option><option>GCM</option></select></label>
        <label>格式<select id="c_fmt"><option value="base64">base64</option><option value="hex">hex</option></select></label>
        <label>Padding<select id="c_pad"><option>PKCS7</option><option>ZERO</option></select></label>
        <label>密钥<input id="c_key" placeholder="16/24/32 字节" /></label>
        <label>IV<input id="c_iv" placeholder="CBC/GCM 需要" /></label>
        <label class="span2 grow-area">数据
          <textarea id="c_data" placeholder="明文或密文"></textarea>
        </label>`;
    } else if (cryptoMode === "hash") {
      box.innerHTML = `
        <label>算法<select id="c_algo"><option>MD5</option><option>SHA256</option><option>SM3</option><option>HMAC-SHA256</option></select></label>
        <label>HMAC Key<input id="c_key" placeholder="仅 HMAC 需要" /></label>
        <label class="span2 grow-area">数据
          <textarea id="c_data" placeholder="待哈希文本"></textarea>
        </label>`;
    } else {
      box.innerHTML = `
        <label class="span2">操作<select id="c_op">
          <option value="b64_encode">Base64 编码</option>
          <option value="b64_decode">Base64 解码</option>
          <option value="hex_encode">Hex 编码</option>
          <option value="hex_decode">Hex 解码</option>
          <option value="url_encode">URL 编码</option>
          <option value="url_decode">URL 解码</option>
        </select></label>
        <label class="span2 grow-area">数据
          <textarea id="c_data" placeholder="待编解码文本"></textarea>
        </label>`;
    }
  }

  $$("#cryptoMode button").forEach((btn) => {
    btn.addEventListener("click", () => {
      cryptoMode = btn.dataset.mode;
      $$("#cryptoMode button").forEach((b) => b.classList.toggle("active", b === btn));
      renderCryptoForm();
      setCryptoMeta(
        ({ analyze: "识别", aes: "AES", hash: "Hash", encode: "编码" }[cryptoMode] || "") +
          " · 等待运行"
      );
    });
  });
  renderCryptoForm();

  $("#btnCryptoCopy") &&
    $("#btnCryptoCopy").addEventListener("click", async () => {
      const text = _cryptoLastText || ($("#cryptoOut") && $("#cryptoOut").textContent) || "";
      if (!text) return;
      try {
        await navigator.clipboard.writeText(text);
        toast("已复制结果");
      } catch {
        toast("复制失败");
      }
    });

  $("#btnCryptoRun").addEventListener("click", async () => {
    const out = $("#cryptoOut");
    const copyBtn = $("#btnCryptoCopy");
    if (copyBtn) copyBtn.disabled = true;
    out.textContent = "运行中…";
    setCryptoMeta("运行中…");
    try {
      let data;
      if (cryptoMode === "analyze") {
        data = await api("/api/crypto/analyze", {
          method: "POST",
          body: JSON.stringify({ text: $("#c_text").value }),
        });
      } else if (cryptoMode === "aes") {
        data = await api("/api/crypto/aes", {
          method: "POST",
          body: JSON.stringify({
            op: $("#c_op").value,
            data: $("#c_data").value,
            key: $("#c_key").value,
            mode: $("#c_mode").value,
            padding: $("#c_pad").value,
            iv: $("#c_iv").value,
            fmt: $("#c_fmt").value,
          }),
        });
      } else if (cryptoMode === "hash") {
        data = await api("/api/crypto/hash", {
          method: "POST",
          body: JSON.stringify({
            algo: $("#c_algo").value,
            data: $("#c_data").value,
            key: $("#c_key").value,
          }),
        });
      } else {
        data = await api("/api/crypto/encode", {
          method: "POST",
          body: JSON.stringify({ op: $("#c_op").value, data: $("#c_data").value }),
        });
      }
      _cryptoLastText = formatCryptoResult(data);
      out.textContent = _cryptoLastText;
      if (copyBtn) copyBtn.disabled = !_cryptoLastText;
      const modeLab = { analyze: "识别", aes: "AES", hash: "Hash", encode: "编码" }[cryptoMode];
      setCryptoMeta(`${modeLab} · 完成 · ${_cryptoLastText.length} 字符`);
    } catch (e) {
      _cryptoLastText = String(e.message || e);
      out.textContent = _cryptoLastText;
      setCryptoMeta("失败");
      if (copyBtn) copyBtn.disabled = false;
    }
  });

  // ── 代理 ──────────────────────────────────────────
  function setProxyOutMeta(text) {
    const el = $("#proxyOutMeta");
    if (el) el.textContent = text || "";
  }

  function appendProxyOut(text, { replace = false } = {}) {
    const el = $("#proxyOut");
    if (!el) return;
    const t = String(text || "");
    if (replace || !el.textContent) el.textContent = t;
    else el.textContent = el.textContent + (el.textContent.endsWith("\n") ? "" : "\n") + t;
  }

  async function loadProxy() {
    const st = await api("/api/proxy/status");
    const allow = !!st.allow_proxy_ctrl;
    const decOn = !!st.decrypt_running;
    const encOn = !!st.encrypt_running;
    const cards = $("#proxyCards");
    if (cards) {
      cards.innerHTML = [
        {
          k: "授权",
          v: allow ? "已授权" : "未授权",
          s: allow ? "可启停代理" : "设置 CB_WEB_ALLOW_PROXY=1",
          state: allow ? "on" : "deny",
        },
        {
          k: "解密端",
          v: decOn ? "运行中" : "已停止",
          s: decOn ? `pid=${st.decrypt_pid || "-"}` : "默认端口 8083",
          state: decOn ? "on" : "off",
        },
        {
          k: "加密端",
          v: encOn ? "运行中" : "已停止",
          s: encOn ? `pid=${st.encrypt_pid || "-"}` : "默认端口 8081",
          state: encOn ? "on" : "off",
        },
      ]
        .map(
          (c) => `<div class="proxy-stat" data-state="${c.state}">
            <div class="k">${escapeHtml(c.k)}</div>
            <div class="v">${escapeHtml(c.v)}</div>
            <div class="s">${escapeHtml(c.s)}</div>
          </div>`
        )
        .join("");
    }
    const hint = $("#proxyAuthHint");
    if (hint) {
      hint.textContent = allow
        ? "已授权：选择项目与角色后可启动 / 停止。"
        : "未授权：只能查看状态。启动 Web 前设置环境变量 CB_WEB_ALLOW_PROXY=1（或 CB_MCP_ALLOW_PROXY=1）。";
    }
    const topo = $("#proxyTopo");
    if (topo) {
      const burp = ($("#proxyBurp") && $("#proxyBurp").value) || "8080";
      topo.textContent = `浏览器 / APP → 解密代理(:8083) → Burp(:${burp}) → 加密代理(:8081) → 服务器`;
    }
    if (st.hint && $("#proxyOut") && !$("#proxyOut").textContent) {
      appendProxyOut(st.hint, { replace: true });
    }
    setProxyOutMeta(allow ? "已授权" : "未授权 · 只读");
    // 无授权时禁用启停
    ["#btnProxyStart", "#btnProxyStop"].forEach((sel) => {
      const b = $(sel);
      if (b) b.disabled = !allow;
    });
    return st;
  }
  $("#btnProxyRefresh").addEventListener("click", () =>
    loadProxy()
      .then(() => toast("状态已刷新"))
      .catch(showErr)
  );
  $("#btnProxyStart").addEventListener("click", async () => {
    const role = $("#proxyRole").value;
    const port = Number($("#proxyPort").value || (role === "encrypt" ? 8081 : 8083));
    const project = $("#proxyProject").value || state.current;
    if (!project) {
      toast("请先选择项目");
      return;
    }
    setProxyOutMeta("启动中…");
    try {
      const data = await api("/api/proxy/start", {
        method: "POST",
        body: JSON.stringify({
          project,
          role,
          port,
          burp_port: Number($("#proxyBurp").value || 8080),
        }),
      });
      appendProxyOut(
        `启动 ${role} · ${project} :${port}\n` + JSON.stringify(data, null, 2),
        { replace: true }
      );
      await loadProxy();
      toast(role === "encrypt" ? "加密端已启动" : "解密端已启动");
    } catch (e) {
      appendProxyOut(String(e.message || e), { replace: true });
      setProxyOutMeta("启动失败");
    }
  });
  $("#btnProxyStop").addEventListener("click", async () => {
    const role = $("#proxyRole").value;
    setProxyOutMeta("停止中…");
    try {
      const data = await api("/api/proxy/stop", {
        method: "POST",
        body: JSON.stringify({ role }),
      });
      appendProxyOut(`停止 ${role}\n` + JSON.stringify(data, null, 2), { replace: true });
      await loadProxy();
      toast(role === "encrypt" ? "加密端已停止" : "解密端已停止");
    } catch (e) {
      appendProxyOut(String(e.message || e), { replace: true });
      setProxyOutMeta("停止失败");
    }
  });
  $("#proxyRole").addEventListener("change", () => {
    const role = $("#proxyRole").value;
    if (role === "encrypt" && Number($("#proxyPort").value) === 8083) $("#proxyPort").value = 8081;
    if (role === "decrypt" && Number($("#proxyPort").value) === 8081) $("#proxyPort").value = 8083;
  });

  // ── 设置 / 主题 ───────────────────────────────────
  function normalizeTheme(t) {
    return t === "dark" ? "dark" : "light";
  }
  function applyTheme(theme) {
    const t = normalizeTheme(theme);
    document.documentElement.setAttribute("data-theme", t);
    try {
      localStorage.setItem("cb_theme", t);
    } catch (_) {}
    const sel = $("#setTheme");
    if (sel && sel.value !== t) sel.value = t;
  }
  async function loadSettings() {
    const data = await api("/api/settings");
    const gui = (data.settings && data.settings.gui) || {};
    const theme = normalizeTheme(gui.theme || localStorage.getItem("cb_theme") || "light");
    $("#setTheme").value = theme;
    applyTheme(theme);
    $("#settingsOut").textContent = JSON.stringify(data.settings || {}, null, 2);
  }
  $("#setTheme").addEventListener("change", () => applyTheme($("#setTheme").value));
  $("#btnSaveSettings").addEventListener("click", async () => {
    try {
      const theme = normalizeTheme($("#setTheme").value);
      applyTheme(theme);
      const data = await api("/api/settings", {
        method: "PUT",
        body: JSON.stringify({ settings: { gui: { theme } } }),
      });
      $("#settingsOut").textContent = JSON.stringify(data.settings || {}, null, 2);
      toast(theme === "dark" ? "已保存 · 深色主题" : "已保存 · 浅色主题");
    } catch (e) {
      showErr(e);
    }
  });

  // ── AI 分析 ───────────────────────────────────────
  let aiDefaults = {};
  let aiModes = [];
  let fieldPickModes = new Set(["recognize", "generate", "generate_encrypt", "analyze_key"]);
  let aiMat = "http";
  let aiPoll = null;
  let aiOut = "log";
  let _aiCtxEntries = [];
  let _verifyShownKey = "";
  let _verifyReport = null;
  let _verifyIo = { req: "after", resp: "after" };
  let _genOpts = null;
  let capPoll = null;
  let lastFlows = [];
  let lastScripts = [];
  let lastFieldTargets = null;
  // 勾选送 AI：undefined=默认勾选；false=用户取消
  let flowCheckMap = {};
  let scriptCheckMap = {};
  let jsFilterText = "";
  // 字段选择弹窗状态
  let ftData = [];
  let ftFlowIdx = 0;
  let ftSide = "request";
  let ftRole = "decrypt";
  let ftPicked = {}; // key -> item
  let ftResolve = null;

  function renderAiSession(sum) {
    const fs = sum.flows_selected != null ? sum.flows_selected : sum.flows || 0;
    const ss = sum.scripts_selected != null ? sum.scripts_selected : sum.scripts || 0;
    const items = [
      ["流量", `${fs}/${sum.flows || 0}`],
      ["JS", `${ss}/${sum.scripts || 0}`],
      ["Hook", sum.hooks || 0],
    ];
    const el = $("#aiSessionCards");
    if (!el) return;
    el.innerHTML = items
      .map(
        ([k, v]) =>
          `<span class="chip${v && String(v) !== "0" && String(v) !== "0/0" ? " on" : ""}">${escapeHtml(
            k
          )} ${escapeHtml(String(v))}</span>`
      )
      .join("");
  }

  function setAiCfgHint(c) {
    const model = c.model || "-";
    const key = c.api_key_set ? "密钥已配置" : "未配置密钥";
    const tip = `· ${model} · ${key}`;
    if ($("#aiCfgHint")) $("#aiCfgHint").textContent = tip;
    if ($("#btnAiCfg")) $("#btnAiCfg").title = `模型配置 ${tip}`;
  }

  function openCfgFloat() {
    $("#cfgFloatMask").hidden = false;
  }
  function closeCfgFloat() {
    $("#cfgFloatMask").hidden = true;
  }
  $("#btnAiCfg").addEventListener("click", openCfgFloat);
  $("#btnCfgFloatClose").addEventListener("click", closeCfgFloat);
  $("#cfgFloatMask").addEventListener("click", (e) => {
    if (e.target === $("#cfgFloatMask")) closeCfgFloat();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    if ($("#bypassMask") && !$("#bypassMask").hidden) {
      if (!_bypassBusy) closeBypassFloat();
      return;
    }
    if (!$("#cfgFloatMask").hidden) closeCfgFloat();
  });


  async function loadAiConfig() {
    const data = await api("/api/ai/config");
    const c = data.config || {};
    const b = c.browser || {};
    $("#aiKey").value = c.api_key || "";
    $("#aiKey").placeholder = c.api_key_set ? "已配置，不改可留掩码" : "填写 API Key";
    $("#aiModel").value = c.model || "";
    $("#aiBase").value = c.base_url || "";
    $("#aiFmt").value = c.api_format || "deepseek";
    $("#aiSteps").value = c.agent_max_steps || 50;
    $("#aiUseProxy").checked = !!c.use_http_proxy;
    $("#aiProxy").value = c.http_proxy || "";
    if ($("#aiHook")) $("#aiHook").checked = b.hook_enabled !== false;
    if ($("#aiAnti")) $("#aiAnti").checked = !!b.anti_debug;
    if ($("#aiMitm")) $("#aiMitm").checked = !!b.use_mitm_proxy;
    if ($("#aiVm")) $("#aiVm").checked = b.load_violentmonkey !== false;
    if ($("#aiReres")) $("#aiReres").checked = b.load_reres !== false;
    if ($("#aiCbHook")) $("#aiCbHook").checked = b.load_cb_hook !== false;
    if ($("#aiCdpSkip")) $("#aiCdpSkip").checked = !!b.cdp_skip_pauses;
    if ($("#aiRewrite")) {
      const io = b.inject_opts || {};
      $("#aiRewrite").checked = !!io.rewriteResponse;
    }
    if ($("#aiRecord")) $("#aiRecord").checked = b.record_mode !== false;
    if ($("#aiUrl") && b.last_url && !$("#aiUrl").value) $("#aiUrl").value = b.last_url;
    // 浏览器引擎
    const ch = b.browser_channel || "chromium";
    $$('input[name="aiChannel"]').forEach((r) => {
      r.checked = r.value === ch;
    });
    // 真实浏览器 / CDP（互斥，CDP 优先）
    const cdpOn = !!b.cdp_attach;
    const cdpBr =
      cdpOn && (b.cdp_browser || b.browser_channel) === "chrome" ? "chrome" : cdpOn ? "msedge" : "";
    $$('input[name="aiCdpMode"]').forEach((r) => {
      r.checked = r.value === cdpBr;
    });
    if ($("#aiRealBrowser")) {
      $("#aiRealBrowser").checked = !cdpOn && !!(b.real_browser || b.proxy_only);
    }
    syncBrowserModeUi();
    setAiCfgHint(c);
  }

  function modeLabel(id) {
    const m = aiModes.find((x) => x.id === id);
    return (m && m.label) || id || "";
  }

  function selectAiMode(id) {
    $("#aiMode").value = id;
    $$("#aiModeGrid .mode-card").forEach((b) =>
      b.classList.toggle("active", b.dataset.id === id)
    );
    const m = aiModes.find((x) => x.id === id);
    const descEl = $("#aiModeDesc");
    if (descEl) {
      descEl.textContent = m
        ? `当前：${m.label} · ${m.desc || ""}（点「开始」运行）`
        : "先选模式，再点「开始」";
    }
    const goalEl = $("#aiGoal");
    if (goalEl && !goalEl.value.trim()) {
      goalEl.placeholder = "留空 = 使用「" + ((m && m.label) || id) + "」默认任务";
    }
    const chatIn = $("#aiChatInput");
    if (chatIn) {
      chatIn.placeholder = m
        ? `【${m.label}】输入追问或自定义目标，回车发送…`
        : "输入任务，回车发送…";
    }
    // 顶部主按钮始终对应「当前选中模式」
    const lab = $("#btnAnalyzeCryptoLabel");
    const btn = $("#btnAnalyzeCrypto");
    if (lab && btn) {
      if (fieldPickModes.has(id)) {
        lab.textContent = id === "recognize" ? "识别" : "分析";
        btn.title = `按当前模式启动：${(m && m.label) || id}（先选字段）`;
      } else if (id === "bot_bypass") {
        lab.textContent = "开始";
        btn.title = "打开 AI 绕过悬浮窗（同 GUI 独立窗口）";
      } else {
        lab.textContent = "开始";
        btn.title = `按当前模式启动：${(m && m.label) || id}`;
      }
    }
    // 同步过程区对话模式下拉（对齐 GUI）
    const chat = $("#aiChatMode");
    if (chat) {
      const map = {
        chat: "chat",
        recognize: "chat",
        generate: "chat",
        analyze_key: "chat",
        generate_encrypt: "chat",
        anti_debug: "anti_debug",
        bot_bypass: "bot_bypass",
        fingerprint_hook: "fingerprint_hook",
        js_reverse: "js_reverse",
        js_deobfuscate: "js_deobfuscate",
        hash_hook: "hash_hook",
      };
      const v = map[id] || "chat";
      if ([...chat.options].some((o) => o.value === v)) chat.value = v;
    }
  }

  let bypassPoll = null;
  let _bypassLogLen = 0;
  let _bypassBusy = false;

  function stopBypassPoll() {
    if (bypassPoll) {
      clearInterval(bypassPoll);
      bypassPoll = null;
    }
  }

  function bypassStatusLabel(parsed, reason) {
    const p = parsed && typeof parsed === "object" ? parsed : {};
    let sweep = p.strategy_sweep;
    if (p.mode === "strategy_sweep") sweep = p;
    const best = sweep && typeof sweep === "object" ? sweep.best : null;
    if (best && best.label) return String(best.label);
    if (p.launch && p.launch.label) return String(p.launch.label);
    const m = String(reason || "").match(/「([^」]{1,20})」/);
    return m ? m[1] : "";
  }

  function setBypassStatus(text, kind) {
    const el = $("#bypassStatus");
    if (!el) return;
    let msg = String(text || "就绪").trim() || "就绪";
    if (msg.length > 42) msg = msg.slice(0, 42) + "…";
    const txt = el.querySelector(".bypass-status-text");
    if (txt) txt.textContent = msg;
    else el.textContent = msg;
    el.removeAttribute("data-busy");
    el.removeAttribute("data-ok");
    el.removeAttribute("data-err");
    let k = kind || "idle";
    if (!kind) {
      const low = String(msg).toLowerCase();
      if (low.includes("soft_pass") || msg.includes("建议人工")) k = "warn";
      else if (msg.includes("通关成功") || msg.includes("完成")) k = "ok";
      else if (msg.includes("失败") || msg.includes("未达成") || msg.includes("未通关") || msg.includes("取消")) k = "err";
      else if (msg.includes("中") || msg.includes("运行")) k = "busy";
      else k = "idle";
    }
    el.setAttribute("data-kind", k);
    if (k === "busy") el.setAttribute("data-busy", "1");
    else if (k === "ok") el.setAttribute("data-ok", "1");
    else if (k === "err") el.setAttribute("data-err", "1");
  }

  function setBypassBusy(on) {
    _bypassBusy = !!on;
    const start = $("#btnBypassStart");
    const sweep = $("#btnBypassSweepOnly");
    const stop = $("#btnBypassStop");
    const follow = $("#btnBypassFollow");
    if (start) start.disabled = !!on;
    if (sweep) sweep.disabled = !!on;
    if (stop) {
      stop.disabled = !on;
      stop.textContent = on ? "停止" : "停止";
    }
    if (follow) follow.disabled = !!on;
  }

  function appendBypassLog(text) {
    const el = $("#bypassLog");
    if (!el || !text) return;
    el.textContent = (el.textContent || "") + (el.textContent ? "\n" : "") + text;
    el.scrollTop = el.scrollHeight;
  }

  function extractJsonLoose(text) {
    const s = String(text || "");
    const start = s.indexOf("{");
    if (start < 0) return null;
    let depth = 0;
    for (let i = start; i < s.length; i++) {
      const ch = s[i];
      if (ch === "{") depth++;
      else if (ch === "}") {
        depth--;
        if (depth === 0) {
          try {
            return JSON.parse(s.slice(start, i + 1));
          } catch (e) {
            return null;
          }
        }
      }
    }
    return null;
  }

  function bypassVerdictZh(v) {
    return (
      { pass: "通过", soft_pass: "勉强可用", fail: "失败", error: "出错" }[
        String(v || "").toLowerCase()
      ] || v || "未知"
    );
  }

  function bypassLaunchLine(launch) {
    if (!launch || typeof launch !== "object") return "";
    const bits = [];
    if (launch.cdp_attach) {
      const ch = String(launch.browser_channel || "msedge").toLowerCase();
      const zh = { msedge: "Edge", chrome: "Chrome" }[ch] || ch;
      bits.push(`系统浏览器 + CDP（${zh}）`);
    } else if (launch.use_stealth === false) {
      bits.push("真实浏览器");
    } else {
      const label = String(launch.label || "").trim();
      const mode = String(launch.mode || "").toLowerCase();
      if (label) bits.push(label);
      else if (!mode || mode.includes("stealth") || mode.includes("拟真"))
        bits.push("拟真注入（Chromium 内置）");
      else bits.push(mode || "拟真浏览器");
    }
    if ("neutralize_devtools" in launch) {
      bits.push(launch.neutralize_devtools ? "反调试中和·开" : "反调试中和·关");
    }
    return bits.join(" · ");
  }

  function showBypassParsed(parsed, raw) {
    const summary = $("#bypassSummary");
    const jsonEl = $("#bypassJson");
    const hookEl = $("#bypassHook");
    if (!parsed || typeof parsed !== "object") {
      if (summary) summary.textContent = raw || "(无内容)";
      if (jsonEl) jsonEl.textContent = raw || "";
      if (hookEl) hookEl.textContent = "";
      return;
    }
    const bits = [];
    if (parsed.reached === true) bits.push("结果：已通关");
    else if (parsed.reached === false) bits.push("结果：未通关");
    let goal = String(parsed.goal || "").trim();
    if (goal) {
      goal = goal
        .replace(/^全量策略扫描目标页[:：]\s*/, "")
        .replace(/^扫描目标页能否正常打开[:：]\s*/, "");
      if (goal) bits.push("目标：" + goal);
    }
    if (parsed.reason) {
      bits.push("", "说明", String(parsed.reason));
    }
    if (parsed.evidence) {
      bits.push("", "依据", String(parsed.evidence));
    }
    const sweep =
      parsed.mode === "strategy_sweep"
        ? parsed
        : parsed.strategy_sweep && typeof parsed.strategy_sweep === "object"
          ? parsed.strategy_sweep
          : null;
    if (sweep) {
      bits.push("", `策略试跑 · 共 ${sweep.total ?? "?"} 组`);
      for (const r of sweep.results || []) {
        if (!r || typeof r !== "object") continue;
        const scoreBit = r.score != null ? ` · 匹配 ${r.score}` : "";
        bits.push(
          `  · ${r.label || "-"} — ${bypassVerdictZh(r.verdict)}${scoreBit} · 标题 ${r.title || "—"}`
        );
      }
      if (sweep.best && typeof sweep.best === "object") {
        bits.push(
          "",
          `推荐：${sweep.best.label || "-"}（${bypassVerdictZh(sweep.best.verdict)}）`
        );
        const bl = bypassLaunchLine(sweep.best.launch);
        if (bl) bits.push("启动方式：" + bl);
      }
    }
    if (parsed.summary && !(sweep && parsed.summary === sweep.summary)) {
      bits.push("", String(parsed.summary));
    }
    if (parsed.advice) bits.push("", "建议", String(parsed.advice));
    const launchLine = bypassLaunchLine(parsed.launch);
    if (launchLine && !sweep) bits.push("", "启动方式：" + launchLine);
    const hookJs = String(parsed.hook_js || "").trim();
    if (hookJs) bits.push("", `Hook 脚本：约 ${hookJs.length} 字（见 hook 页）`);
    if (summary) summary.textContent = bits.filter((x, i) => !(x === "" && i === 0)).join("\n") || "(空)";
    if (jsonEl) jsonEl.textContent = JSON.stringify(parsed, null, 2);
    if (hookEl) hookEl.textContent = hookJs || "（无 Hook 脚本）";
  }

  function syncBypassTab(tab) {
    const t = tab || "summary";
    $$("#bypassTabs button").forEach((b) => {
      b.classList.toggle("active", b.dataset.btab === t);
    });
    const map = {
      summary: $("#bypassSummary"),
      json: $("#bypassJson"),
      hook: $("#bypassHook"),
    };
    Object.keys(map).forEach((k) => {
      if (map[k]) map[k].hidden = k !== t;
    });
  }

  function openBypassFloat(opts) {
    const o = opts || {};
    const mask = $("#bypassMask");
    if (!mask) return;
    const mainUrl = (($("#aiUrl") && $("#aiUrl").value) || "").trim();
    const bu = $("#bypassUrl");
    if (bu && (!bu.value || o.syncUrl !== false)) {
      if (mainUrl) bu.value = mainUrl;
    }
    // 首次打开时从实验室勾选同步
    if (o.syncOpts !== false) {
      const mitm = $("#bypassMitm");
      const stealth = $("#bypassStealth");
      if (mitm && $("#aiMitm")) mitm.checked = !!$("#aiMitm").checked;
      if (stealth) {
        const launch = typeof launchOptsFromUi === "function" ? launchOptsFromUi() : {};
        stealth.checked = !launch.real_browser && !launch.cdp_attach;
      }
    }
    mask.hidden = false;
    selectAiMode("bot_bypass");
    if (!_bypassBusy) {
      setBypassStatus("就绪 · 填写 URL 后开始通关或只扫策略", "idle");
    }
    if (o.autoStart) {
      startLiveBypassFromFloat({ sweepThenAgent: true });
    }
  }

  function closeBypassFloat() {
    const mask = $("#bypassMask");
    if (mask) mask.hidden = true;
  }

  async function pollBypassLive() {
    try {
      const st = await api("/api/browser/bypass/live");
      const logs = st.logs || [];
      if (logs.length > _bypassLogLen) {
        const add = logs.slice(_bypassLogLen).join("\n");
        _bypassLogLen = logs.length;
        appendBypassLog(add);
        // 同步一份到主过程区，方便回看
        const el = $("#aiLog");
        if (el) {
          el.textContent = (el.textContent || "") + (el.textContent ? "\n" : "") + add;
          el.scrollTop = el.scrollHeight;
        }
      }
      if (st.status === "running") {
        setBypassStatus("运行中…", "busy");
        return;
      }
      stopBypassPoll();
      setBypassBusy(false);
      const raw = st.result || "";
      if (raw && $("#aiResult")) {
        $("#aiResult").textContent = raw;
      }
      let parsed = extractJsonLoose(raw);
      if (parsed && st.launch && typeof st.launch === "object" && !parsed.launch) {
        parsed = Object.assign({}, parsed, { launch: st.launch });
      }
      showBypassParsed(parsed, raw);
      if (st.status === "ok") {
        const reached = parsed && parsed.reached;
        const reason = (parsed && (parsed.reason || parsed.summary)) || "";
        const soft =
          String(reason).toLowerCase().includes("soft_pass") ||
          String(reason).includes("建议人工") ||
          (parsed && String(parsed.verdict || "").toLowerCase() === "soft_pass");
        const lab = bypassStatusLabel(parsed, reason);
        if (reached === true && !soft) {
          setBypassStatus(lab ? "通关成功 · " + lab : "通关成功", "ok");
        } else if (soft || (reached !== false && String(reason).includes("soft"))) {
          setBypassStatus(lab ? "勉强可用 · " + lab : "勉强可用 · 建议人工确认", "warn");
        } else if (reached === false) {
          setBypassStatus(lab ? "未通关 · " + lab : "未通关", "err");
        } else {
          setBypassStatus(lab || "环境绕过完成", "ok");
        }
        toast("环境绕过完成");
        syncBypassTab("summary");
      } else if (st.status === "cancelled") {
        setBypassStatus("已取消", "err");
        toast("已取消");
      } else {
        setBypassStatus(st.error || "环境绕过失败", "err");
        toast(st.error || "环境绕过失败");
      }
    } catch (e) {
      stopBypassPoll();
      setBypassBusy(false);
      setBypassStatus(String(e.message || e), "err");
      showErr(e);
    }
  }

  /** GUI 同款：从悬浮窗启动策略扫描 + 实时通关 */
  async function startLiveBypassFromFloat(opts) {
    const o = opts || {};
    if (_bypassBusy) {
      appendBypassLog("已在运行中…");
      return;
    }
    const url = (($("#bypassUrl") && $("#bypassUrl").value) || ($("#aiUrl") && $("#aiUrl").value) || "").trim();
    if (!url) {
      alert("请先填写目标 URL");
      return;
    }
    if ($("#aiUrl")) $("#aiUrl").value = url;
    try {
      await saveAiConfigSilent();
    } catch (e) {
      /* ignore */
    }
    const launch = typeof launchOptsFromUi === "function" ? launchOptsFromUi() : {};
    const anti = !!($("#aiAnti") && $("#aiAnti").checked);
    const headless = !!($("#bypassHeadless") && $("#bypassHeadless").checked);
    const stealth = $("#bypassStealth") ? !!$("#bypassStealth").checked : true;
    const mitm = $("#bypassMitm") ? !!$("#bypassMitm").checked : !!($("#aiMitm") && $("#aiMitm").checked);
    const sweep = $("#bypassSweep") ? !!$("#bypassSweep").checked : true;
    const sweepThenAgent = o.sweepThenAgent !== false;
    const goal =
      (o.goal != null ? o.goal : "") ||
      (($("#bypassFollow") && $("#bypassFollow").value) || "").trim() ||
      (($("#aiGoal") && $("#aiGoal").value) || "").trim();

    if ($("#bypassLog")) $("#bypassLog").textContent = "";
    if ($("#bypassSummary")) $("#bypassSummary").textContent = "";
    if ($("#bypassJson")) $("#bypassJson").textContent = "";
    if ($("#bypassHook")) $("#bypassHook").textContent = "";
    syncBypassTab("summary");
    _bypassLogLen = 0;
    stopBypassPoll();
    stopAiPoll();
    setBypassBusy(true);
    setBypassStatus(sweepThenAgent ? "通关中…" : "策略扫描中…", "busy");
    toast(sweepThenAgent ? "启动环境绕过…" : "只扫策略…");
    try {
      await api("/api/browser/bypass/live", {
        method: "POST",
        body: JSON.stringify({
          url,
          goal,
          strategy_sweep: !!sweep || !sweepThenAgent,
          sweep_then_agent: !!sweepThenAgent,
          headless,
          use_stealth: stealth && !launch.cdp_attach,
          neutralize_devtools: anti,
          browser_channel: launch.cdp_attach
            ? launch.cdp_browser || "msedge"
            : launch.real_browser
              ? "chrome"
              : undefined,
          cdp_attach: !!launch.cdp_attach,
          use_proxy: mitm,
          proxy: "",
        }),
      });
      bypassPoll = setInterval(pollBypassLive, 800);
      pollBypassLive();
    } catch (e) {
      setBypassBusy(false);
      setBypassStatus(String(e.message || e), "err");
      throw e;
    }
  }

  /** 兼容旧调用名：打开悬浮窗并自动开始 */
  async function startLiveBypass() {
    openBypassFloat({ autoStart: true, syncUrl: true });
  }

  /** 点「开始」：按当前选中模式开跑（卡片只负责选中；AI绕过开悬浮窗） */
  async function runSelectedMode(id) {
    const mode = id || ($("#aiMode") && $("#aiMode").value) || "generate";
    selectAiMode(mode);
    try {
      await saveAiConfigSilent();
    } catch (e) {
      /* ignore */
    }
    if (fieldPickModes.has(mode)) {
      await runWithFieldPick(mode);
      return;
    }
    if (mode === "bot_bypass") {
      openBypassFloat({ autoStart: true, syncUrl: true });
      return;
    }
    aiOut = "log";
    syncAiOutPanes();
    toast(`启动：${modeLabel(mode)}`);
    await startAiJob(mode, ($("#aiGoal").value || "").trim(), lastFieldTargets || null);
  }

  function wrapComposerGoal(mode, goal) {
    const g = (goal || "").trim();
    if (!g) return g;
    const low = g.toLowerCase();
    if (mode === "anti_debug") {
      if (!low.includes("debugger") && !g.includes("反调试") && !g.includes("注入")) {
        return (
          "【反调试模式】只分析无限 debugger / 反调试与 inject_opts，" +
          `禁止输出加解密 steps。用户说：${g}`
        );
      }
    } else if (mode === "bot_bypass") {
      if (
        !low.includes("webdriver") &&
        !g.includes("绕过") &&
        !g.includes("指纹") &&
        !low.includes("bot") &&
        !g.includes("挑战")
      ) {
        return (
          "【绕过检查模式】只分析浏览器环境检测 / Bot / JS 挑战，" +
          `输出 browser_opts + hook_js，禁止加解密 steps。用户说：${g}`
        );
      }
    } else if (mode === "fingerprint_hook") {
      if (
        !g.includes("指纹") &&
        !low.includes("fingerprint") &&
        !low.includes("canvas") &&
        !low.includes("webgl") &&
        !low.includes("hook")
      ) {
        return (
          "【指纹绕过 HOOK 模式】只分析浏览器指纹采集 / FingerprintJS，" +
          `输出 detections + hook_js，禁止加解密 steps。用户说：${g}`
        );
      }
    } else if (mode === "js_reverse") {
      if (
        !g.includes("逆向") &&
        !low.includes("encrypt") &&
        !low.includes("decrypt") &&
        !low.includes("aes") &&
        !g.includes("签名") &&
        !g.includes("加密")
      ) {
        return (
          "【JS逆向模式】只定位加解密/签名业务函数与字段，" +
          `输出 findings/code_locations，禁止 steps。用户说：${g}`
        );
      }
    } else if (mode === "js_deobfuscate") {
      if (
        !g.includes("混淆") &&
        !g.includes("解混淆") &&
        !g.includes("解密") &&
        !low.includes("sojson") &&
        !low.includes("_0x") &&
        !low.includes("obfuscat")
      ) {
        return (
          "【JS解密模式】只做解混淆/还原加解密相关可读片段，" +
          `输出 snippets/deobfuscated_js，禁止 steps。用户说：${g}`
        );
      }
    } else if (mode === "hash_hook") {
      if (
        !low.includes("hash") &&
        !g.includes("签名") &&
        !g.includes("哈希") &&
        !low.includes("md5") &&
        !low.includes("sha")
      ) {
        return (
          "【Hash Hook 模式】只分析哈希/签名路径并给出 Hook 建议，" +
          `禁止输出加解密 steps。用户说：${g}`
        );
      }
    }
    return g;
  }

  async function sendAiComposer() {
    const input = $("#aiChatInput");
    const mode = ($("#aiChatMode") && $("#aiChatMode").value) || "chat";
    let goal = (input && input.value) || "";
    goal = goal.trim();
    if (!goal) {
      toast("请输入任务");
      return;
    }
    if (input) input.value = "";
    goal = wrapComposerGoal(mode, goal);
    aiOut = "log";
    syncAiOutPanes();
    await startAiJob(mode, goal, lastFieldTargets || null);
  }

  async function stopAiJob() {
    stopBypassPoll();
    try {
      await api("/api/browser/bypass/live/stop", { method: "POST" });
    } catch (e) {
      /* ignore */
    }
    if (_bypassBusy) {
      setBypassBusy(false);
      setBypassStatus("停止中…", "busy");
      appendBypassLog("（正在停止…）");
    }
    renderAiJob(await api("/api/ai/stop", { method: "POST" }));
  }

  async function loadAiModes() {
    const data = await api("/api/ai/modes");
    aiDefaults = data.defaults || {};
    aiModes = data.modes || [];
    if (Array.isArray(data.field_pick_modes)) {
      fieldPickModes = new Set(data.field_pick_modes);
    }
    $("#aiMode").innerHTML = aiModes
      .map((m) => `<option value="${escapeAttr(m.id)}">${escapeHtml(m.label)}</option>`)
      .join("");
    $("#aiModeGrid").innerHTML = aiModes
      .map(
        (m) =>
          `<button type="button" class="mode-card" data-id="${escapeAttr(m.id)}">
            <div class="t">${escapeHtml(m.label)}</div>
            <div class="d">${escapeHtml(m.desc || "")}</div>
          </button>`
      )
      .join("");
    $$("#aiModeGrid .mode-card").forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = btn.dataset.id;
        selectAiMode(id);
        // AI 绕过：同 GUI，点卡片即打开独立悬浮窗（不自动开跑，由窗内「开始通关」）
        if (id === "bot_bypass") {
          openBypassFloat({ autoStart: false, syncUrl: true });
        }
      });
    });
    selectAiMode("generate");
    $("#aiGoal").value = "";
  }

  function ftKey(role, it) {
    return `${role}|${it.seq}|${it.scope}|${it.path}`;
  }

  function ftRoleLabel(role) {
    if (role === "encrypt") return "加密";
    if (role === "resp_decrypt") return "响应解密";
    return "解密";
  }

  function syncFtRoleTip() {
    /* GUI 用 tooltip；Web 按钮 title 已带说明 */
  }

  function ftScopeLabel(scope) {
    const s = String(scope || "");
    if (s.includes("Header")) return "Header";
    if (s.includes("Query")) return "Query";
    if (s.includes("Form")) return "Body (Form)";
    if (s.includes("JSON")) return "Body (JSON)";
    if (s.includes("Response")) return "Response";
    if (s.includes("Body")) return "Body";
    return s.replace(/^📋\s*/, "") || "其它";
  }

  function refreshFtPickedUi() {
    const keys = Object.keys(ftPicked);
    const box = $("#ftPicked");
    const st = $("#ftStatus");
    if ($("#ftSkip").checked) {
      st.textContent = "盲目分析";
      box.textContent = "已跳过字段指定";
      return;
    }
    if (!keys.length) {
      box.textContent = "";
      st.textContent = "尚未选字段";
      return;
    }
    box.innerHTML = keys
      .map((k) => {
        const it = ftPicked[k];
        return `<div class="ft-picked-item" data-key="${escapeAttr(k)}" title="双击移除">[${ftRoleLabel(
          it.role
        )}]  #${it.seq}  ${escapeHtml(it.path)}  ·  ${escapeHtml(
          (it.preview || "").slice(0, 40)
        )}</div>`;
      })
      .join("");
    box.querySelectorAll(".ft-picked-item").forEach((el) => {
      el.addEventListener("dblclick", () => {
        delete ftPicked[el.dataset.key];
        refreshFtPickedUi();
        renderFtFields();
      });
    });
    st.textContent = `已选 ${keys.length} 个字段`;
  }

  let ftCollapsed = {};

  function renderFtFields() {
    const flow = ftData[ftFlowIdx];
    const list = $("#ftFieldList");
    if (!list) return;
    if (!flow) {
      list.innerHTML = `<div class="muted" style="padding:12px">（请先在左侧选择请求）</div>`;
      return;
    }
    const fields = (ftSide === "response" ? flow.response : flow.request) || [];
    if (!fields.length) {
      list.innerHTML = `<div class="muted" style="padding:12px">${
        ftSide === "response" ? "暂无响应体" : "暂无可解析字段"
      }</div>`;
      return;
    }
    const groups = {};
    const order = [];
    fields.forEach((it, i) => {
      const g = ftScopeLabel(it.scope);
      if (!groups[g]) {
        groups[g] = [];
        order.push(g);
      }
      groups[g].push({ it, i });
    });
    list.innerHTML = order
      .map((g) => {
        const collapsed = !!ftCollapsed[g];
        const rows = collapsed
          ? ""
          : groups[g]
              .map(({ it, i }) => {
                const key = ftKey(ftRole, it);
                const on = !!ftPicked[key];
                return `<button type="button" class="ft-row${on ? " on" : ""}" data-i="${i}">
                  <span class="ck">${on ? "✓" : ""}</span>
                  <span class="name" title="${escapeAttr(it.path || "")}">${escapeHtml(
                  it.path || ""
                )}</span>
                  <span class="val" title="${escapeAttr(String(it.preview || ""))}">${escapeHtml(
                  String(it.preview || "").slice(0, 100)
                )}</span>
                </button>`;
              })
              .join("");
        return `<div class="ft-group" data-g="${escapeAttr(g)}"><span class="twist">${
          collapsed ? "▶" : "▼"
        }</span>${escapeHtml(g)}</div>${rows}`;
      })
      .join("");
    list.querySelectorAll(".ft-group").forEach((el) => {
      el.addEventListener("click", () => {
        const g = el.dataset.g;
        ftCollapsed[g] = !ftCollapsed[g];
        renderFtFields();
      });
    });
    list.querySelectorAll("button.ft-row").forEach((btn) => {
      btn.addEventListener("click", () => {
        if ($("#ftSkip").checked) return;
        let role = ftRole;
        if (ftSide === "response" && role === "decrypt") {
          role = "resp_decrypt";
          ftRole = role;
          $$("#ftRole button").forEach((b) =>
            b.classList.toggle("active", b.dataset.role === role)
          );
        }
        const it = fields[Number(btn.dataset.i)];
        if (!it) return;
        const item = { ...it, role };
        const key = ftKey(role, item);
        if (ftPicked[key]) delete ftPicked[key];
        else ftPicked[key] = item;
        renderFtFields();
        refreshFtPickedUi();
      });
    });
  }

  function ftSortedIndices() {
    const idxs = ftData.map((_, i) => i);
    const mode = ($("#ftSort") && $("#ftSort").value) || "seq_asc";
    const seq = (i) => Number(ftData[i].seq) || i + 1;
    if (mode === "seq_desc") idxs.sort((a, b) => seq(b) - seq(a));
    else if (mode === "url")
      idxs.sort((a, b) => String(ftData[a].url || "").localeCompare(String(ftData[b].url || "")));
    else if (mode === "method")
      idxs.sort((a, b) => {
        const m = String(ftData[a].method || "").localeCompare(String(ftData[b].method || ""));
        return m || String(ftData[a].url || "").localeCompare(String(ftData[b].url || ""));
      });
    else idxs.sort((a, b) => seq(a) - seq(b));
    return idxs;
  }

  function renderFtFlows() {
    const fl = $("#ftFlowList");
    const count = $("#ftFlowCount");
    if (count) count.textContent = `共 ${ftData.length} 条`;
    if (!fl) return;
    if (!ftData.length) {
      fl.innerHTML = `<div class="muted" style="padding:12px">暂无流量</div>`;
      return;
    }
    const order = ftSortedIndices();
    // 若当前选中因排序变化，保持选中 index
    fl.innerHTML = order
      .map((i) => {
        const f = ftData[i];
        const path = String(f.url || "");
        let short = path;
        try {
          const u = new URL(path);
          short = u.pathname + (u.search || "");
        } catch (_) {}
        return `<button type="button" data-i="${i}" class="${i === ftFlowIdx ? "active" : ""}">
            <div>#${f.seq} ${escapeHtml(f.method || "")} [${escapeHtml(
              String(f.status ?? "")
            )}] ${escapeHtml(short.slice(0, 42))}</div>
            <div class="sub">${escapeHtml(path)}</div>
          </button>`;
      })
      .join("");
    fl.querySelectorAll("button").forEach((btn) => {
      btn.addEventListener("click", () => {
        ftFlowIdx = Number(btn.dataset.i) || 0;
        renderFtFlows();
        renderFtFields();
      });
    });
  }

  function buildFieldTargetsFromUi() {
    if ($("#ftSkip").checked) {
      return {
        unrestricted: true,
        decrypt: [],
        encrypt: [],
        resp_decrypt: [],
        analysis_role: ftRole === "encrypt" ? "encrypt" : "decrypt",
      };
    }
    const decrypt = [];
    const encrypt = [];
    const resp = [];
    Object.values(ftPicked).forEach((it) => {
      const clean = {
        path: it.path,
        preview: it.preview || "",
        scope: it.scope || "",
        flow_i: it.flow_i,
        seq: it.seq,
        side: it.side,
      };
      if (it.role === "encrypt") encrypt.push(clean);
      else if (it.role === "resp_decrypt") resp.push(clean);
      else decrypt.push(clean);
    });
    let analysis_role = "decrypt";
    if (ftRole === "encrypt") analysis_role = "encrypt";
    else if (encrypt.length && !decrypt.length && !resp.length) analysis_role = "encrypt";
    return {
      unrestricted: false,
      decrypt,
      encrypt,
      resp_decrypt: resp,
      analysis_role,
    };
  }

  function closeFtDialog(result) {
    $("#ftMask").hidden = true;
    const r = ftResolve;
    ftResolve = null;
    if (r) r(result);
  }

  async function openFieldTargetDialog(defaultRole) {
    const encryptOnly = defaultRole === "encrypt";
    const allowedRoles = encryptOnly
      ? ["encrypt"]
      : ["decrypt", "resp_decrypt"];
    ftRole = encryptOnly ? "encrypt" : "decrypt";
    ftSide = "request";
    ftFlowIdx = 0;
    ftPicked = {};
    $("#ftSkip").checked = false;
    $("#ftContent") && $("#ftContent").classList.remove("disabled");
    $$("#ftSide button").forEach((b) =>
      b.classList.toggle("active", b.dataset.side === "request")
    );
    // 分析解密：隐藏「加密」；分析加密：只留「加密」
    $$("#ftRole button").forEach((b) => {
      const role = b.dataset.role;
      const ok = allowedRoles.includes(role);
      b.hidden = !ok;
      b.classList.toggle("active", ok && role === ftRole);
    });
    syncFtRoleTip();
    try {
      const data = await api("/api/ai/field-options");
      ftData = data.flows || [];
    } catch (e) {
      ftData = [];
      console.warn(e);
    }
    const empty = $("#ftEmpty");
    if (empty) empty.hidden = ftData.length > 0;
    // 恢复上次选择（仅当前分析方向允许的角色）
    if (lastFieldTargets && !lastFieldTargets.unrestricted) {
      allowedRoles.forEach((role) => {
        (lastFieldTargets[role] || []).forEach((it) => {
          const item = { ...it, role };
          ftPicked[ftKey(role, item)] = item;
        });
      });
    }
    // 默认选中更可能有 Body 的 POST
    const postIdx = ftData.findIndex((f) => String(f.method || "").toUpperCase() === "POST");
    if (postIdx >= 0) ftFlowIdx = postIdx;
    if ($("#ftSort")) $("#ftSort").value = "seq_asc";
    ftCollapsed = {};
    renderFtFlows();
    renderFtFields();
    refreshFtPickedUi();
    $("#ftMask").hidden = false;
    return new Promise((resolve) => {
      ftResolve = resolve;
    });
  }

  $("#ftSort") &&
    $("#ftSort").addEventListener("change", () => {
      renderFtFlows();
    });

  $$("#ftSide button").forEach((btn) => {
    btn.addEventListener("click", () => {
      ftSide = btn.dataset.side || "request";
      $$("#ftSide button").forEach((b) => b.classList.toggle("active", b === btn));
      // 对齐 GUI：切到响应 → 自动点亮响应解密（若可见）；切回请求则恢复解密/加密
      const respBtn = $$("#ftRole button").find((b) => b.dataset.role === "resp_decrypt");
      const encBtn = $$("#ftRole button").find((b) => b.dataset.role === "encrypt");
      const decBtn = $$("#ftRole button").find((b) => b.dataset.role === "decrypt");
      if (ftSide === "response" && respBtn && !respBtn.hidden) {
        ftRole = "resp_decrypt";
      } else if (ftRole === "resp_decrypt") {
        if (encBtn && !encBtn.hidden && (!decBtn || decBtn.hidden)) {
          ftRole = "encrypt";
        } else {
          ftRole = "decrypt";
        }
      }
      $$("#ftRole button").forEach((b) =>
        b.classList.toggle("active", !b.hidden && b.dataset.role === ftRole)
      );
      syncFtRoleTip();
      renderFtFields();
    });
  });
  $$("#ftRole button").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (btn.hidden) return;
      ftRole = btn.dataset.role || "decrypt";
      $$("#ftRole button").forEach((b) =>
        b.classList.toggle("active", !b.hidden && b === btn)
      );
      if (ftRole === "resp_decrypt" && ftSide !== "response") {
        ftSide = "response";
        $$("#ftSide button").forEach((b) =>
          b.classList.toggle("active", b.dataset.side === "response")
        );
      }
      if ((ftRole === "decrypt" || ftRole === "encrypt") && ftSide === "response") {
        ftSide = "request";
        $$("#ftSide button").forEach((b) =>
          b.classList.toggle("active", b.dataset.side === "request")
        );
      }
      syncFtRoleTip();
      renderFtFields();
      refreshFtPickedUi();
    });
  });
  $("#ftSkip").addEventListener("change", () => {
    const on = $("#ftSkip").checked;
    $("#ftContent") && $("#ftContent").classList.toggle("disabled", on);
    refreshFtPickedUi();
  });
  $("#btnFtClear").addEventListener("click", () => {
    ftPicked = {};
    refreshFtPickedUi();
    renderFtFields();
  });
  $("#btnFtCancel").addEventListener("click", () => closeFtDialog(null));
  $("#btnFtOk").addEventListener("click", () => {
    if (!$("#ftSkip").checked && !Object.keys(ftPicked).length && ftData.length) {
      if (!confirm("尚未勾选字段，是否跳过指定继续盲目分析？")) return;
      $("#ftSkip").checked = true;
    }
    closeFtDialog(buildFieldTargetsFromUi());
  });
  $("#ftMask").addEventListener("click", (e) => {
    if (e.target === $("#ftMask")) closeFtDialog(null);
  });

  async function refreshAiSession() {
    const data = await api("/api/ai/session");
    renderAiSession(data);
  }

  function syncMaterialUi() {
    const isJs = aiMat === "js";
    $("#aiScriptUrl").hidden = !isJs;
    $("#aiMaterial").placeholder = isJs
      ? "粘贴 JS 源码…"
      : "粘贴完整 HTTP 请求（可带响应）…";
  }

  $$("#aiMaterialMode button").forEach((btn) => {
    btn.addEventListener("click", () => {
      aiMat = btn.dataset.mat;
      $$("#aiMaterialMode button").forEach((b) => b.classList.toggle("active", b === btn));
      syncMaterialUi();
    });
  });
  syncMaterialUi();

  function syncAiOutPanes() {
    const map = {
      log: "#aiLog",
      ctx: "#aiCtx",
      result: "#aiResult",
      code: "#aiCodeLoc",
      hook: "#aiHookOut",
      plugin: "#aiPluginOut",
    };
    Object.entries(map).forEach(([k, sel]) => {
      const el = $(sel);
      if (el) el.hidden = aiOut !== k;
    });
    $$("#aiOutTabs button").forEach((b) =>
      b.classList.toggle("active", b.dataset.out === aiOut)
    );
  }

  function ctxSizeLabel(text) {
    const n = (text || "").length;
    if (n <= 0) return "—";
    if (n < 1000) return String(n);
    if (n < 10000) return (n / 1000).toFixed(1) + "k";
    return Math.floor(n / 1000) + "k";
  }

  function ctxToolZh(name) {
    const m = {
      flow: "流量",
      hook: "Hook 日志",
      script: "脚本",
      browser: "浏览器",
      crypto: "加解密试算",
      project: "项目",
      http: "HTTP",
      search: "搜索",
    };
    const k = String(name || "").trim().toLowerCase();
    return m[k] || String(name || "工具").trim() || "工具";
  }

  function ctxRoleZh(role) {
    return (
      { system: "系统", user: "用户指令", assistant: "本轮分析", tool: "工具回传" }[
        String(role || "").toLowerCase()
      ] || role || "?"
    );
  }

  function ctxParseContentBlocks(text) {
    if (!text) return [];
    const m = text.match(/——\s*content\s*——\s*(\[[\s\S]*?\])\s*(?:\n\s*stop_reason:|\n\s*usage:|$)/);
    let raw = m && m[1];
    const tryParse = (s) => {
      try {
        const obj = JSON.parse(s);
        return Array.isArray(obj) ? obj.filter((x) => x && typeof x === "object") : [];
      } catch (_) {
        return null;
      }
    };
    if (raw) {
      const got = tryParse(raw);
      if (got) return got;
    }
    let i = text.indexOf("[");
    while (i >= 0) {
      let depth = 0;
      let end = -1;
      for (let j = i; j < text.length; j++) {
        const ch = text[j];
        if (ch === "[") depth++;
        else if (ch === "]") {
          depth--;
          if (depth === 0) {
            end = j + 1;
            break;
          }
        }
      }
      if (end > i) {
        const got = tryParse(text.slice(i, end));
        if (got && got.length) return got;
      }
      i = text.indexOf("[", i + 1);
    }
    return [];
  }

  function ctxResponseSummary(text) {
    if (!String(text || "").trim()) return "等待中…";
    const parts = [];
    const blocks = ctxParseContentBlocks(text);
    const texts = [];
    const tools = [];
    for (const b of blocks) {
      const t = String(b.type || "");
      if (t === "text") {
        const s = String(b.text || "").replace(/\s+/g, " ").trim();
        if (s) texts.push(s);
      } else if (t === "tool_use") {
        const name = String(b.name || "").trim();
        if (name) tools.push(ctxToolZh(name));
      } else if (t === "thinking") {
        const th = String(b.thinking || b.text || "").replace(/\s+/g, " ").trim();
        if (th) texts.push(`（分析）${th}`);
      }
    }
    if (texts.length) {
      const one = texts[0];
      parts.push(one.length > 56 ? one.slice(0, 56) + "…" : one);
    }
    if (tools.length) {
      let shown = tools.slice(0, 3).join("、");
      if (tools.length > 3) shown += "…";
      parts.push(`操作 ${shown}`);
    }
    const stop = String(text).match(/stop_reason:\s*(\S+)/);
    if (stop) {
      const zh = {
        tool_use: "需继续操作",
        end_turn: "本轮结束",
        max_tokens: "长度截断",
      };
      parts.push(zh[stop[1]] || stop[1]);
    }
    return parts.length ? parts.join(" · ") : "—";
  }

  function ctxRequestSummary(text) {
    if (!String(text || "").trim()) return "—";
    const parts = [];
    const tm = String(text).match(/tools:\s*(\d+)/);
    if (tm) parts.push(`可用工具 ${tm[1]} 个`);
    const roles = [...String(text).matchAll(/messages\[\d+\]\s+role=(\w+)/g)].map((x) => x[1]);
    if (roles.length) parts.push(`对话 ${roles.length} 条`);
    if (String(text).includes("—— system ——")) parts.push("含系统提示（已折叠）");
    return parts.length ? parts.join(" · ") : "—";
  }

  function ctxRowSummary(entry) {
    const title = entry.title || "";
    const req = entry.request || "";
    const resp = entry.response || "";
    if (/任务/.test(title)) return ctxRequestSummary(req);
    if (/最终/.test(title))
      return resp.trim() ? ctxResponseSummary(resp) : ctxRequestSummary(req);
    if (resp.trim()) return ctxResponseSummary(resp);
    return ctxRequestSummary(req);
  }

  function ctxToolLine(name, inp) {
    const zh = ctxToolZh(name);
    const action = String((inp && (inp.action || inp.op)) || "")
      .trim()
      .toLowerCase();
    const az = {
      list: "列出",
      get: "查看详情",
      read: "读取",
      search: "搜索",
      run: "执行",
      eval: "执行表达式",
      set: "设置",
      write: "写入",
      decrypt: "解密试算",
      encrypt: "加密试算",
      analyze: "分析",
    }[action];
    return az ? `${zh} · ${az}` : zh;
  }

  function ctxHumanizeRequest(text) {
    const raw = String(text || "").trim();
    if (!raw) return "（无发送内容）";
    const lines = [];
    const tm = raw.match(/tools:\s*(\d+)/);
    if (tm) {
      lines.push(`可用工具：${tm[1]} 个`, "");
    }
    const sysM = raw.match(/——\s*system\s*——\s*\n?([\s\S]*?)(?=\n——\s*messages\[|$)/i);
    if (sysM && String(sysM[1] || "").trim()) {
      lines.push("── 系统提示 ──", String(sysM[1]).trim(), "");
    }
    const re = /—— messages\[(\d+)\] role=(\w+) ——\n?/g;
    const matches = [...raw.matchAll(re)];
    if (matches.length) {
      for (let i = 0; i < matches.length; i++) {
        const m = matches[i];
        const start = m.index + m[0].length;
        const end = i + 1 < matches.length ? matches[i + 1].index : raw.length;
        let body = raw.slice(start, end).trim();
        if (!body) continue;
        let preview = body;
        if (body.startsWith("{") || body.startsWith("[")) {
          try {
            const obj = JSON.parse(body);
            if (Array.isArray(obj)) {
              const bits = [];
              for (const it of obj) {
                if (!it || typeof it !== "object") continue;
                const tt = String(it.type || "");
                if (tt === "tool_result") {
                  const c =
                    typeof it.content === "string"
                      ? it.content
                      : JSON.stringify(it.content, null, 2);
                  bits.push(`工具回传 ${it.tool_use_id || ""}\n${c || ""}`);
                } else if (tt === "text") bits.push(String(it.text || ""));
                else if (tt === "tool_use")
                  bits.push(`拟调用 ${ctxToolLine(it.name, it.input || {})}`);
              }
              if (bits.length) preview = bits.join("\n");
              else preview = JSON.stringify(obj, null, 2);
            } else if (obj && typeof obj === "object") {
              preview = JSON.stringify(obj, null, 2);
            }
          } catch (_) {}
        }
        lines.push(`── ${ctxRoleZh(m[2])} · 第 ${Number(m[1]) + 1} 条 ──`);
        lines.push(preview, "");
      }
    } else if (!lines.length) {
      lines.push(...raw.split(/\r?\n/).filter(Boolean));
    }
    return lines.join("\n").replace(/\s+$/, "") + "\n";
  }

  function ctxHumanizeResponse(text) {
    const raw = String(text || "").trim();
    if (!raw) return "（无响应内容）";
    const lines = [];
    const blocks = ctxParseContentBlocks(raw);
    if (blocks.length) {
      let toolI = 0;
      for (const b of blocks) {
        const t = String(b.type || "");
        if (t === "thinking") {
          const th = String(b.thinking || b.text || "").trim();
          if (th) lines.push("分析过程", th, "");
        } else if (t === "text") {
          const msg = String(b.text || "").trim();
          if (msg) lines.push("说明", msg, "");
        } else if (t === "tool_use") {
          toolI += 1;
          const name = String(b.name || "tool").trim();
          const inp = b.input && typeof b.input === "object" ? b.input : {};
          lines.push(`操作 ${toolI}：${ctxToolLine(name, inp)}`);
          const bits = [];
          for (const [k, v] of Object.entries(inp)) {
            if (k === "action" || k === "op") continue;
            if (v == null || v === "" || (Array.isArray(v) && !v.length)) continue;
            if (typeof v === "object") {
              bits.push(`  · ${k}:\n${JSON.stringify(v, null, 2)}`);
            } else {
              bits.push(`  · ${k}: ${v}`);
            }
          }
          if (bits.length) lines.push(bits.join("\n"));
          lines.push("");
        }
      }
    } else {
      for (const line of raw.split(/\r?\n/)) {
        const s = line.trim();
        if (!s || s.startsWith("{") || s.startsWith("[")) continue;
        if (s.startsWith("========") || (s.startsWith("——") && s.endsWith("——"))) continue;
        lines.push(s);
      }
    }
    const stop = raw.match(/stop_reason:\s*(\S+)/);
    if (stop) {
      const zh = {
        tool_use: "需要继续调用工具",
        end_turn: "本轮结束",
        max_tokens: "输出长度达到上限",
      };
      lines.push(`状态：${zh[stop[1]] || stop[1]}`);
    }
    const um = raw.match(
      /"?(?:input_tokens|prompt_tokens)"?\s*[:=]\s*(\d+)[\s\S]*?"?(?:output_tokens|completion_tokens)"?\s*[:=]\s*(\d+)/
    );
    if (um) lines.push(`用量：输入 ${um[1]} · 输出 ${um[2]}`);
    if (lines.length <= 1) return raw;
    return lines.join("\n").replace(/\s+$/, "") + "\n";
  }

  function ctxPrettyText(text) {
    const raw = String(text || "");
    // 尝试美化 content JSON 块
    const m = raw.match(/——\s*content\s*——\s*(\[[\s\S]*?\])(\s*(?:\n\s*stop_reason:|\n\s*usage:|$))/);
    if (m) {
      try {
        const pretty = JSON.stringify(JSON.parse(m[1]), null, 2);
        return raw.slice(0, m.index) + "—— content ——\n" + pretty + m[2];
      } catch (_) {}
    }
    return raw;
  }

  function renderAiCtxTable(entries) {
    _aiCtxEntries = Array.isArray(entries) ? entries : [];
    const tb = $("#aiCtxBody");
    if (!tb) return;
    if (!_aiCtxEntries.length) {
      tb.innerHTML =
        '<tr><td colspan="5" class="muted">（暂无上下文；Agent 运行时记录 LLM 请求/响应）</td></tr>';
      return;
    }
    tb.innerHTML = _aiCtxEntries
      .map((e, i) => {
        const req = e.request || "";
        const resp = e.response || "";
        const title = e.title || `#${i + 1}`;
        return `<tr data-i="${i}" title="双击查看该轮请求/响应">
          <td>${i + 1}</td>
          <td>${escapeHtml(title)}</td>
          <td class="ctx-sum">${escapeHtml(ctxRowSummary(e))}</td>
          <td>${escapeHtml(ctxSizeLabel(req))}</td>
          <td>${escapeHtml(resp.trim() ? ctxSizeLabel(resp) : "…")}</td>
        </tr>`;
      })
      .join("");
  }

  $$("#aiOutTabs button").forEach((btn) => {
    btn.addEventListener("click", () => {
      aiOut = btn.dataset.out || "log";
      syncAiOutPanes();
    });
  });

  const aiCtxBody = $("#aiCtxBody");
  if (aiCtxBody) {
    aiCtxBody.addEventListener("dblclick", (ev) => {
      const tr = ev.target.closest("tr[data-i]");
      if (!tr) return;
      const i = Number(tr.dataset.i);
      const e = _aiCtxEntries[i];
      if (!e) return;
      const reqRaw = e.request || "";
      const respRaw = e.response || "";
      openFloat(
        `上下文 · ${e.title || "#" + (i + 1)}`,
        "",
        {
          req: reqRaw.trim() ? ctxHumanizeRequest(reqRaw) : "（无请求）",
          resp: respRaw.trim() ? ctxHumanizeResponse(respRaw) : "（无响应）",
          raw: [reqRaw, respRaw].filter(Boolean).join("\n\n——\n\n"),
        },
        "llm"
      );
    });
  }

  function _checkedRadio(name, fallback) {
    const el = document.querySelector(`input[name="${name}"]:checked`);
    return el ? el.value : fallback;
  }

  function isCleanBrowserMode() {
    const cdp = _checkedRadio("aiCdpMode", "") !== "";
    const real = !!($("#aiRealBrowser") && $("#aiRealBrowser").checked);
    return cdp || real;
  }

  function syncBrowserModeUi() {
    const clean = isCleanBrowserMode();
    const wrap = $("#injectMenuWrap");
    if (wrap) wrap.classList.toggle("is-clean", clean);
    const locked = $("#injectLocked");
    if (locked) locked.hidden = !clean;
    const cdp = _checkedRadio("aiCdpMode", "");
    const real = !!($("#aiRealBrowser") && $("#aiRealBrowser").checked);
    const hint = $("#browserModeHint");
    const moreBtn = $("#btnMoreMenu");
    const injBtn = $("#btnInjectMenu");
    if (cdp) {
      const lab = cdp === "chrome" ? "Chrome" : "Edge";
      if (hint) hint.textContent = `CDP·${lab}`;
      if (moreBtn) moreBtn.textContent = `CDP·${lab} ▾`;
      if (injBtn) injBtn.textContent = "注入(关) ▾";
    } else if (real) {
      if (hint) hint.textContent = "真实浏览器";
      if (moreBtn) moreBtn.textContent = "真实 ▾";
      if (injBtn) injBtn.textContent = "注入(关) ▾";
    } else {
      if (hint) hint.textContent = "";
      if (moreBtn) moreBtn.textContent = "更多 ▾";
      if (injBtn) injBtn.textContent = "注入 ▾";
    }
    // CDP 与真实浏览器互斥
    if (cdp && $("#aiRealBrowser") && $("#aiRealBrowser").checked) {
      $("#aiRealBrowser").checked = false;
    }
  }

  function launchOptsFromUi() {
    const cdpBr = _checkedRadio("aiCdpMode", "");
    const cdp = !!cdpBr;
    const real = !cdp && !!($("#aiRealBrowser") && $("#aiRealBrowser").checked);
    const clean = real || cdp;
    const channel = clean
      ? cdp
        ? cdpBr === "chrome"
          ? "chrome"
          : "msedge"
        : _checkedRadio("aiChannel", "chrome") === "chromium"
          ? "chrome"
          : _checkedRadio("aiChannel", "chrome")
      : _checkedRadio("aiChannel", "chromium");
    return {
      real_browser: real,
      cdp_attach: cdp,
      cdp_browser: cdp ? (cdpBr === "chrome" ? "chrome" : "msedge") : "",
      browser_channel: channel,
      hook_enabled: !clean && !!($("#aiHook") && $("#aiHook").checked),
      anti_debug: !clean && !!($("#aiAnti") && $("#aiAnti").checked),
      cdp_skip_pauses: !clean && !!($("#aiCdpSkip") && $("#aiCdpSkip").checked),
      use_mitm_proxy: !!($("#aiMitm") && $("#aiMitm").checked),
      load_violentmonkey: !clean && !!($("#aiVm") && $("#aiVm").checked),
      load_reres: !clean && !!($("#aiReres") && $("#aiReres").checked),
      load_cb_hook: !clean && !!($("#aiCbHook") && $("#aiCbHook").checked),
      record_mode: !!($("#aiRecord") && $("#aiRecord").checked),
      inject_opts: {
        functionHook: true,
        evalHook: true,
        timerHook: true,
        timerNuke: false,
        consoleClear: true,
        sizeSpoof: true,
        rewriteResponse: !clean && !!($("#aiRewrite") && $("#aiRewrite").checked),
      },
    };
  }

  async function saveAiConfigSilent() {
    const launch = launchOptsFromUi();
    await api("/api/ai/config", {
      method: "PUT",
      body: JSON.stringify({
        config: {
          api_key: $("#aiKey").value,
          model: $("#aiModel").value,
          base_url: $("#aiBase").value,
          api_format: $("#aiFmt").value,
          agent_max_steps: Number($("#aiSteps").value || 50),
          use_http_proxy: $("#aiUseProxy").checked,
          http_proxy: $("#aiProxy").value,
          browser: {
            ...launch,
            last_url: ($("#aiUrl") && $("#aiUrl").value) || "",
          },
        },
      }),
    });
  }

  function closeAllBbMenus() {
    ["#injectMenu", "#moreMenu"].forEach((sel) => {
      const el = $(sel);
      if (el) el.hidden = true;
    });
    $$(".bb-sub-pop").forEach((p) => {
      p.hidden = true;
    });
    $$(".bb-sub").forEach((s) => s.classList.remove("open"));
  }

  function bindBrowserMenus() {
    const togglePop = (btnId, popId) => {
      const btn = $(btnId);
      const pop = $(popId);
      if (!btn || !pop) return;
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const willOpen = pop.hidden;
        closeAllBbMenus();
        pop.hidden = !willOpen;
      });
    };
    togglePop("#btnInjectMenu", "#injectMenu");
    togglePop("#btnMoreMenu", "#moreMenu");

    $$(".bb-sub-btn").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const sub = btn.closest(".bb-sub");
        const pop = sub && sub.querySelector(".bb-sub-pop");
        if (!pop) return;
        const open = pop.hidden;
        // 同级子菜单互斥
        const root = btn.closest(".bb-pop");
        if (root) {
          root.querySelectorAll(".bb-sub-pop").forEach((p) => {
            p.hidden = true;
          });
          root.querySelectorAll(".bb-sub").forEach((s) => s.classList.remove("open"));
        }
        pop.hidden = !open;
        if (sub) sub.classList.toggle("open", open);
      });
    });

    document.addEventListener("click", (e) => {
      if (e.target.closest && e.target.closest(".bb-menu")) return;
      closeAllBbMenus();
    });

    // 模式互斥 + 提示
    if ($("#aiRealBrowser")) {
      $("#aiRealBrowser").addEventListener("change", () => {
        if ($("#aiRealBrowser").checked) {
          $$('input[name="aiCdpMode"]').forEach((r) => {
            r.checked = r.value === "";
          });
        }
        syncBrowserModeUi();
        saveAiConfigSilent().catch(() => {});
      });
    }
    $$('input[name="aiCdpMode"]').forEach((r) => {
      r.addEventListener("change", () => {
        if (r.checked && r.value && $("#aiRealBrowser")) {
          $("#aiRealBrowser").checked = false;
        }
        syncBrowserModeUi();
        saveAiConfigSilent().catch(() => {});
      });
    });
    [
      "#aiHook",
      "#aiAnti",
      "#aiCdpSkip",
      "#aiRewrite",
      "#aiVm",
      "#aiReres",
      "#aiCbHook",
      "#aiRecord",
      "#aiMitm",
    ].forEach((sel) => {
      const el = $(sel);
      if (el) el.addEventListener("change", () => saveAiConfigSilent().catch(() => {}));
    });
    $$('input[name="aiChannel"]').forEach((r) => {
      r.addEventListener("change", () => saveAiConfigSilent().catch(() => {}));
    });

    syncBrowserModeUi();
  }

  function setBrowserDot(on) {
    const d = $("#browserDot");
    if (d) d.classList.toggle("on", !!on);
  }

  let _floatText = "";
  let _floatParts = null; // {req, resp, raw} for Burp tabs
  let _floatTab = "req";
  let _floatHighlight = false;

  /** Burp 风格 HTTP 报文高亮 */
  function highlightHttp(raw) {
    const text = String(raw || "");
    if (!text.trim()) return "";
    const parts = text.split(/\r?\n\r?\n/);
    const head = parts[0] || "";
    const body = parts.slice(1).join("\n\n");
    const lines = head.split(/\r?\n/);
    const out = [];
    lines.forEach((line, i) => {
      if (i === 0) {
        // 请求行 / 状态行
        const req = line.match(/^([A-Z]+)\s+(\S+)\s+(HTTP\/[\d.]+)\s*$/i);
        const res = line.match(/^(HTTP\/[\d.]+)\s+(\d{3})(?:\s+(.*))?$/i);
        if (req) {
          out.push(
            `<span class="hk-method">${escapeHtml(req[1])}</span> ` +
              `<span class="hk-path">${escapeHtml(req[2])}</span> ` +
              `<span class="hk-ver">${escapeHtml(req[3])}</span>`
          );
        } else if (res) {
          const code = Number(res[2]);
          const cls =
            code >= 500 ? "hk-status-err" : code >= 400 ? "hk-status-warn" : "hk-status-ok";
          out.push(
            `<span class="hk-ver">${escapeHtml(res[1])}</span> ` +
              `<span class="${cls}">${escapeHtml(res[2])}</span>` +
              (res[3] ? ` <span class="hk-reason">${escapeHtml(res[3])}</span>` : "")
          );
        } else {
          out.push(escapeHtml(line));
        }
        return;
      }
      if (!line) {
        out.push("");
        return;
      }
      const colon = line.indexOf(":");
      if (colon > 0) {
        const name = line.slice(0, colon);
        const val = line.slice(colon + 1);
        out.push(
          `<span class="hk-hname">${escapeHtml(name)}</span><span class="hk-colon">:</span>` +
            `<span class="hk-hval">${escapeHtml(val)}</span>`
        );
      } else {
        out.push(escapeHtml(line));
      }
    });
    let html = out.join("\n");
    if (body !== undefined && parts.length > 1) {
      html += "\n\n" + highlightBody(body);
    }
    return html;
  }

  function highlightBody(body) {
    const b = String(body || "");
    const t = b.trim();
    if (!t) return "";
    // 过大正文只做轻量高亮，避免卡顿
    const heavy = b.length > 200000;
    // JSON
    if (t[0] === "{" || t[0] === "[") {
      try {
        const obj = JSON.parse(t);
        const pretty = JSON.stringify(obj, null, 2);
        return pretty
          .split("\n")
          .map((line) => {
            const m = line.match(/^(\s*)"([^"\\]*(?:\\.[^"\\]*)*)"(\s*:)(.*)$/);
            if (m) {
              return (
                escapeHtml(m[1]) +
                `<span class="hk-jkey">"${escapeHtml(m[2])}"</span>` +
                `<span class="hk-colon">${escapeHtml(m[3])}</span>` +
                highlightJsonValue(m[4])
              );
            }
            return highlightJsonValue(line);
          })
          .join("\n");
      } catch (_) {
        /* fallthrough */
      }
    }
    // HTML / XML
    if (/^<!doctype\s+html/i.test(t) || /^<[a-z!/?]/i.test(t)) {
      return highlightHtml(b, heavy);
    }
    // JS
    if (
      /^(?:\/\/|\/\*|'use strict'|"use strict"|import\s|export\s|function\s|const\s|let\s|var\s|class\s|\(function)/.test(
        t
      ) ||
      (t.includes("function") && t.includes("{") && !t.includes("<html"))
    ) {
      return highlightJs(b, heavy);
    }
    // form urlencoded
    if (t.includes("=") && !t.includes("\n") && t.length < 8000) {
      return t
        .split("&")
        .map((pair, i) => {
          const eq = pair.indexOf("=");
          const prefix = i ? `<span class="hk-amp">&amp;</span>` : "";
          if (eq < 0) return prefix + escapeHtml(pair);
          return (
            prefix +
            `<span class="hk-jkey">${escapeHtml(pair.slice(0, eq))}</span>` +
            `<span class="hk-colon">=</span>` +
            `<span class="hk-str">${escapeHtml(pair.slice(eq + 1))}</span>`
          );
        })
        .join("");
    }
    // 兜底：尽量按 JS 着色（很多接口返回半截脚本）
    if (t.includes(";") && (t.includes("=") || t.includes("{"))) {
      return highlightJs(b, heavy);
    }
    return `<span class="hk-body">${escapeHtml(b)}</span>`;
  }

  function highlightJsonValue(seg) {
    const s = String(seg);
    const re =
      /("(?:\\.|[^"\\])*")|\b(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\b|\b(true|false|null)\b|(\s+|.)/g;
    let out = "";
    let m;
    while ((m = re.exec(s))) {
      if (m[1]) out += `<span class="hk-str">${escapeHtml(m[1])}</span>`;
      else if (m[2]) out += `<span class="hk-num">${escapeHtml(m[2])}</span>`;
      else if (m[3]) out += `<span class="hk-bool">${escapeHtml(m[3])}</span>`;
      else out += escapeHtml(m[4] || "");
    }
    return out;
  }

  function highlightHtml(src, heavy) {
    const s = String(src);
    let out = "";
    let i = 0;
    const n = s.length;
    const limit = heavy ? Math.min(n, 120000) : n;
    while (i < limit) {
      if (s.startsWith("<!--", i)) {
        const end = s.indexOf("-->", i + 4);
        const j = end < 0 ? limit : end + 3;
        out += `<span class="hk-comment">${escapeHtml(s.slice(i, j))}</span>`;
        i = j;
        continue;
      }
      if (s[i] === "<") {
        const end = s.indexOf(">", i + 1);
        if (end < 0) {
          out += escapeHtml(s.slice(i, limit));
          break;
        }
        const tag = s.slice(i, end + 1);
        const low = tag.toLowerCase();
        out += colorHtmlTag(tag);
        i = end + 1;
        // <script>...</script>
        if (/^<script(\s|>)/i.test(low) && !/^<script[^>]*\/>/i.test(low)) {
          const close = s.toLowerCase().indexOf("</script>", i);
          const j = close < 0 ? limit : close;
          out += highlightJs(s.slice(i, j), heavy);
          if (close >= 0) {
            out += colorHtmlTag(s.slice(close, close + 9));
            i = close + 9;
          } else i = j;
        } else if (/^<style(\s|>)/i.test(low)) {
          const close = s.toLowerCase().indexOf("</style>", i);
          const j = close < 0 ? limit : close;
          out += highlightCss(s.slice(i, j));
          if (close >= 0) {
            out += colorHtmlTag(s.slice(close, close + 8));
            i = close + 8;
          } else i = j;
        }
        continue;
      }
      // 文本节点攒一段
      let j = i + 1;
      while (j < limit && s[j] !== "<") j++;
      out += `<span class="hk-text">${escapeHtml(s.slice(i, j))}</span>`;
      i = j;
    }
    if (limit < n) {
      out += `<span class="hk-muted">\n…(正文过长，已截断高亮 ${limit}/${n})</span>`;
      out += escapeHtml(s.slice(limit, Math.min(n, limit + 2000)));
    }
    return out;
  }

  function colorHtmlTag(tag) {
    if (/^<!/.test(tag) || /^<\?/.test(tag)) {
      return `<span class="hk-doctype">${escapeHtml(tag)}</span>`;
    }
    const m = String(tag).match(/^(<\/?)([a-zA-Z0-9:-]+)([\s\S]*?)(\/?\>)$/);
    if (!m) return escapeHtml(tag);
    const [, open, name, rest, close] = m;
    let attrs = "";
    const ar =
      /([:\w-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
    let am;
    while ((am = ar.exec(String(rest)))) {
      const an = am[1];
      if (am[2] !== undefined) {
        attrs +=
          ` <span class="hk-attr">${escapeHtml(an)}</span>=` +
          `<span class="hk-str">"${escapeHtml(am[2])}"</span>`;
      } else if (am[3] !== undefined) {
        attrs +=
          ` <span class="hk-attr">${escapeHtml(an)}</span>=` +
          `<span class="hk-str">'${escapeHtml(am[3])}'</span>`;
      } else if (am[4] !== undefined) {
        attrs +=
          ` <span class="hk-attr">${escapeHtml(an)}</span>=` +
          `<span class="hk-str">${escapeHtml(am[4])}</span>`;
      } else {
        attrs += ` <span class="hk-attr">${escapeHtml(an)}</span>`;
      }
    }
    return (
      `<span class="hk-tag">${escapeHtml(open)}</span>` +
      `<span class="hk-tagname">${escapeHtml(name)}</span>` +
      attrs +
      `<span class="hk-tag">${escapeHtml(close)}</span>`
    );
  }

  function highlightJs(src, heavy) {
    const s = String(src);
    const n = heavy ? Math.min(s.length, 100000) : s.length;
    const chunk = s.slice(0, n);
    const kw =
      "break|case|catch|class|const|continue|debugger|default|delete|do|else|export|extends|finally|for|function|if|import|in|instanceof|let|new|return|super|switch|this|throw|try|typeof|var|void|while|with|yield|async|await|of|from|as|static|get|set";
    const re = new RegExp(
      String.raw`(\/\/[^\n]*|\/\*[\s\S]*?\*\/)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|` +
        "`(?:\\\\.|[^`\\\\])*`" +
        String.raw`)|(\/(?:\\\/|[^\/\n])+\/[gimsuy]*)|\b(${kw})\b|\b(true|false|null|undefined|NaN|Infinity)\b|\b(0x[0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\b|([{}()\[\];,.]=?|=>|[+\-*/%&|^!~<>?:]+)|(\s+)|([A-Za-z_$][\w$]*)`,
      "g"
    );
    let out = "";
    let m;
    while ((m = re.exec(chunk))) {
      if (m[1]) out += `<span class="hk-comment">${escapeHtml(m[1])}</span>`;
      else if (m[2]) out += `<span class="hk-str">${escapeHtml(m[2])}</span>`;
      else if (m[3]) out += `<span class="hk-regex">${escapeHtml(m[3])}</span>`;
      else if (m[4]) out += `<span class="hk-kw">${escapeHtml(m[4])}</span>`;
      else if (m[5]) out += `<span class="hk-bool">${escapeHtml(m[5])}</span>`;
      else if (m[6]) out += `<span class="hk-num">${escapeHtml(m[6])}</span>`;
      else if (m[7]) out += `<span class="hk-op">${escapeHtml(m[7])}</span>`;
      else if (m[8]) out += escapeHtml(m[8]);
      else if (m[9]) out += `<span class="hk-ident">${escapeHtml(m[9])}</span>`;
    }
    if (n < s.length) {
      out += `<span class="hk-muted">\n…(JS 过长，已截断高亮)</span>`;
    }
    return out;
  }

  function highlightCss(src) {
    const s = String(src);
    return s.replace(
      /(\/\*[\s\S]*?\*\/)|([.#]?[a-zA-Z_][\w-]*)|(:[a-zA-Z-]+)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|([{};:,])|(\s+)|([^/\s"'.#:;{},]+)/g,
      (m, cmt, sel, pseudo, str, punct, sp, other) => {
        if (cmt) return `<span class="hk-comment">${escapeHtml(cmt)}</span>`;
        if (str) return `<span class="hk-str">${escapeHtml(str)}</span>`;
        if (sel) return `<span class="hk-tagname">${escapeHtml(sel)}</span>`;
        if (pseudo) return `<span class="hk-attr">${escapeHtml(pseudo)}</span>`;
        if (punct) return `<span class="hk-op">${escapeHtml(punct)}</span>`;
        if (sp) return escapeHtml(sp);
        return `<span class="hk-body">${escapeHtml(other || m)}</span>`;
      }
    );
  }

  function setFloatBodyHtml(text, highlight, mode) {
    _floatText = text || "";
    const el = $("#floatBody");
    if (!el) return;
    el.classList.toggle("burp", !!highlight);
    if (!highlight) {
      el.textContent = _floatText;
      return;
    }
    if (mode === "js") {
      el.innerHTML = highlightJs(_floatText) || "&nbsp;";
    } else if (mode === "html") {
      el.innerHTML = highlightHtml(_floatText) || "&nbsp;";
    } else if (mode === "json") {
      el.innerHTML = highlightBody(_floatText) || "&nbsp;";
    } else if (mode === "llm") {
      el.innerHTML = highlightAgentText(_floatText, "result") || "&nbsp;";
    } else {
      el.innerHTML = highlightHttp(_floatText) || "&nbsp;";
    }
  }

  let _floatMode = "http"; // http | js | html | json | llm | plain

  function _showFloatBody() {
    if (_floatParts) {
      const map = { req: _floatParts.req, resp: _floatParts.resp, raw: _floatParts.raw };
      _floatText = map[_floatTab] || "";
      setFloatBodyHtml(_floatText, true, _floatMode === "llm" ? "llm" : "http");
    } else {
      setFloatBodyHtml(_floatText, _floatHighlight, _floatMode);
    }
  }

  function openFloat(title, text, parts, mode) {
    _floatParts = parts || null;
    _floatTab = "req";
    _floatMode = mode || (parts ? "http" : "plain");
    _floatHighlight = !!parts || (_floatMode !== "plain" && _floatMode !== false);
    if (mode === false) _floatHighlight = false;
    $("#floatTitle").textContent = title || "详情";
    if (_floatParts) {
      $("#floatTabs").hidden = false;
      const isLlm = _floatMode === "llm";
      $$("#floatTabs button").forEach((b) => {
        b.classList.toggle("active", b.dataset.ftab === "req");
        if (isLlm) {
          if (b.dataset.ftab === "req") b.textContent = "发送";
          else if (b.dataset.ftab === "resp") b.textContent = "回复";
          else if (b.dataset.ftab === "raw") b.textContent = "原文拼接";
        } else {
          if (b.dataset.ftab === "req") b.textContent = "Request";
          else if (b.dataset.ftab === "resp") b.textContent = "Response";
          else if (b.dataset.ftab === "raw") b.textContent = "Raw";
        }
      });
      _showFloatBody();
    } else {
      $("#floatTabs").hidden = true;
      // 自动识别 JS / HTML / JSON（加载中等短文不着色）
      const t = String(text || "").trim();
      let m = _floatMode;
      if (m === "plain" || m === true) {
        if (t[0] === "{" || t[0] === "[") m = "json";
        else if (/^<!doctype\s+html/i.test(t) || /^<html[\s>]/i.test(t)) m = "html";
        else if (
          t.length > 40 &&
          (/^(?:\/\/|\/\*|'use strict'|"use strict"|function\s|const\s|let\s|var\s|import\s)/.test(
            t
          ) ||
            (t.includes("function") && t.includes("{")))
        )
          m = "js";
        else m = "plain";
        _floatMode = m;
        _floatHighlight = m !== "plain";
      }
      setFloatBodyHtml(text || "", _floatHighlight, _floatMode);
    }
    $("#floatMask").hidden = false;
  }
  function closeFloat() {
    $("#floatMask").hidden = true;
    _floatParts = null;
  }
  $("#btnFloatClose").addEventListener("click", closeFloat);
  $("#floatMask").addEventListener("click", (e) => {
    if (e.target === $("#floatMask")) closeFloat();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    if ($("#fieldOpMask") && !$("#fieldOpMask").hidden) {
      closeFieldOpDialog();
      return;
    }
    if ($("#bypassMask") && !$("#bypassMask").hidden) {
      if (!_bypassBusy) closeBypassFloat();
      return;
    }
    if ($("#ftMask") && !$("#ftMask").hidden) {
      closeFtDialog(null);
      return;
    }
    if ($("#genMask") && !$("#genMask").hidden) {
      closeGenerateDialog();
      return;
    }
    if ($("#verifyMask") && !$("#verifyMask").hidden) {
      closeVerifyDialog();
      return;
    }
    if (!$("#floatMask").hidden) closeFloat();
  });
  $("#btnFloatCopy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(_floatText || "");
      toast("已复制");
    } catch {
      toast("复制失败");
    }
  });
  $$("#floatTabs button").forEach((btn) => {
    btn.addEventListener("click", () => {
      _floatTab = btn.dataset.ftab || "req";
      $$("#floatTabs button").forEach((b) =>
        b.classList.toggle("active", b === btn)
      );
      _showFloatBody();
    });
  });

  function isFlowChecked(i, serverChecked) {
    if (Object.prototype.hasOwnProperty.call(flowCheckMap, i)) return !!flowCheckMap[i];
    return serverChecked !== false;
  }
  function isScriptChecked(url, serverChecked) {
    if (Object.prototype.hasOwnProperty.call(scriptCheckMap, url)) return !!scriptCheckMap[url];
    return serverChecked !== false;
  }

  function collectFlowSelection() {
    return lastFlows
      .map((f, i) => (isFlowChecked(i, f.checked) ? i : -1))
      .filter((i) => i >= 0);
  }
  function collectScriptSelection() {
    return lastScripts
      .filter((s) => isScriptChecked(s.url, s.checked))
      .map((s) => s.url);
  }

  async function syncMaterialSelection() {
    const flow_indices = collectFlowSelection();
    const script_urls = collectScriptSelection();
    return api("/api/ai/session/selection", {
      method: "PUT",
      body: JSON.stringify({ flow_indices, script_urls }),
    });
  }

  function renderCapture(data) {
    const counts = data.counts || {};
    const nFlowSel = counts.flows_selected != null ? counts.flows_selected : counts.flows || 0;
    const nJsSel = counts.scripts_selected != null ? counts.scripts_selected : counts.scripts || 0;
    $("#capNFlow").textContent = `${nFlowSel}/${counts.flows || 0}`;
    $("#capNJs").textContent = `${nJsSel}/${counts.scripts || 0}`;
    $("#capNHook").textContent = counts.hooks || 0;
    setBrowserDot(data.browser && data.browser.running);
    lastFlows = data.flows || [];
    lastScripts = data.scripts || [];

    const fl = $("#flowList");
    if (fl) {
      fl.innerHTML = lastFlows.length
        ? lastFlows
            .map((f, i) => {
              const seq = f.seq || i + 1;
              const kind = f.kind ? `<span class="cap-tag">[${escapeHtml(f.kind)}]</span>` : "";
              const checked = isFlowChecked(i, f.checked);
              return `<div class="cap-row" data-i="${i}">
                <input type="checkbox" class="cap-check" data-i="${i}" ${checked ? "checked" : ""} title="勾选送入 AI" />
                <div class="cap-main">
                  <div>#${seq} [${escapeHtml(String(f.status ?? ""))}] ${kind}${escapeHtml(
                f.method || ""
              )} ${escapeHtml(String(f.url || "").slice(0, 90))}</div>
                  <div class="sub">${escapeHtml(f.source || "")} · req ${
                f.req_len || 0
              } / resp ${f.resp_len || 0}</div>
                </div>
              </div>`;
            })
            .join("")
        : `<div class="muted" style="padding:12px">暂无流量。启动浏览器操作页面，或粘贴导入。</div>`;
      fl.querySelectorAll(".cap-check").forEach((ck) => {
        ck.addEventListener("click", (e) => e.stopPropagation());
        ck.addEventListener("change", () => {
          flowCheckMap[Number(ck.dataset.i)] = !!ck.checked;
          updateCapCounts();
          syncMaterialSelection().catch(() => {});
        });
      });
      fl.querySelectorAll(".cap-row").forEach((row) => {
        row.addEventListener("click", async (e) => {
          if (e.target && e.target.classList && e.target.classList.contains("cap-check")) return;
          fl.querySelectorAll(".cap-row").forEach((b) => b.classList.remove("active"));
          row.classList.add("active");
          openFloat("加载中…", "正在拉取请求详情…");
          try {
            const d = await api(`/api/browser/capture/flow/${row.dataset.i}`);
            const flow = d.flow || {};
            const title = `${flow.method || ""} [${flow.status ?? ""}] ${String(
              flow.url || ""
            ).slice(0, 120)}`;
            openFloat(title, "", {
              req: d.request_raw || "(无请求)",
              resp: d.response_raw || "(无响应)",
              raw: d.raw || "",
            });
          } catch (err) {
            openFloat("加载失败", String(err.message || err));
          }
        });
      });
    }

    const jl = $("#jsList");
    if (jl) {
      const q = (jsFilterText || "").trim().toLowerCase();
      const shown = lastScripts.filter((s) => {
        if (!q) return true;
        return String(s.url || "").toLowerCase().includes(q);
      });
      jl.innerHTML = shown.length
        ? shown
            .map((s) => {
              const checked = isScriptChecked(s.url, s.checked);
              // 加载顺序：用原始捕获序号（过滤后不重编号）
              const ord =
                Number(s.order || s.seq) ||
                lastScripts.findIndex((x) => x.url === s.url) + 1 ||
                0;
              const ordLabel = ord > 0 ? `#${ord}` : "#?";
              return `<div class="cap-row" data-url="${escapeAttr(s.url)}" title="加载顺序 ${ordLabel}">
                <input type="checkbox" class="cap-check" data-url="${escapeAttr(
                  s.url
                )}" ${checked ? "checked" : ""} title="勾选送入 AI" />
                <div class="cap-main">
                  <div><span class="cap-ord">${ordLabel}</span> ${escapeHtml(
                String(s.url || "").slice(0, 96)
              )}</div>
                  <div class="sub">加载顺序 ${ordLabel} · ${s.size || 0} bytes</div>
                </div>
              </div>`;
            })
            .join("")
        : `<div class="muted" style="padding:12px">${
            lastScripts.length ? "无匹配的 JS" : "暂无 JS"
          }</div>`;
      jl.querySelectorAll(".cap-check").forEach((ck) => {
        ck.addEventListener("click", (e) => e.stopPropagation());
        ck.addEventListener("change", () => {
          scriptCheckMap[ck.dataset.url] = !!ck.checked;
          updateCapCounts();
          syncMaterialSelection().catch(() => {});
        });
      });
      jl.querySelectorAll(".cap-row").forEach((row) => {
        row.addEventListener("click", async (e) => {
          if (e.target && e.target.classList && e.target.classList.contains("cap-check")) return;
          jl.querySelectorAll(".cap-row").forEach((b) => b.classList.remove("active"));
          row.classList.add("active");
          openFloat("加载中…", "正在拉取脚本…");
          try {
            const d = await api(
              `/api/browser/capture/script?url=${encodeURIComponent(row.dataset.url)}`
            );
            const code = d.code || "";
            const body =
              code.length > 200000 ? code.slice(0, 200000) + "\n…(已截断)" : code;
            const ord =
              Number(
                (lastScripts.find((x) => x.url === row.dataset.url) || {}).order ||
                  (lastScripts.find((x) => x.url === row.dataset.url) || {}).seq
              ) || 0;
            const title =
              (ord > 0 ? `#${ord} ` : "") + String(d.url || "JS");
            openFloat(title, body, null, "js");
          } catch (err) {
            openFloat("加载失败", String(err.message || err));
          }
        });
      });
    }

    if ($("#hookView")) {
      $("#hookView").textContent = (data.hooks || []).join("\n") || "（暂无 Hook）";
    }
    if ($("#browserLog") && data.browser) {
      $("#browserLog").textContent = (data.browser.logs_tail || []).join("\n") || "（暂无日志）";
    }
    updateCapCounts();
    renderAiSession({
      flows: counts.flows || 0,
      scripts: counts.scripts || 0,
      hooks: counts.hooks || 0,
      flows_selected: collectFlowSelection().length,
      scripts_selected: collectScriptSelection().length,
    });
  }

  function updateCapCounts() {
    const nf = lastFlows.length;
    const ns = lastScripts.length;
    const nfc = collectFlowSelection().length;
    const nsc = collectScriptSelection().length;
    if ($("#capNFlow")) $("#capNFlow").textContent = nf ? `${nfc}/${nf}` : "0";
    if ($("#capNJs")) $("#capNJs").textContent = ns ? `${nsc}/${ns}` : "0";
  }

  async function refreshCapture() {
    try {
      renderCapture(await api("/api/browser/capture"));
    } catch (e) {
      console.warn(e);
    }
  }

  function startCapPoll() {
    if (capPoll) return;
    capPoll = setInterval(refreshCapture, 1200);
  }

  function showSource(src) {
    $$("#sourceTabs button").forEach((b) =>
      b.classList.toggle("active", b.dataset.src === src)
    );
    $$(".source-pane").forEach((p) =>
      p.classList.toggle("active", p.id === `src-${src}`)
    );
    if (src === "mini") refreshMiniList();
    if (src === "app") refreshAppTools();
  }
  $$("#sourceTabs button").forEach((btn) => {
    btn.addEventListener("click", () => showSource(btn.dataset.src || "web"));
  });

  $$("#captureTabs button").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.dataset.cap;
      $$("#captureTabs button").forEach((b) => b.classList.toggle("active", b === btn));
      $$("#src-web .cap-pane").forEach((p) =>
        p.classList.toggle("active", p.id === `cap-${id}`)
      );
    });
  });

  function setAllFlowChecked(on) {
    lastFlows.forEach((_, i) => {
      flowCheckMap[i] = !!on;
    });
    $$("#flowList .cap-check").forEach((ck) => {
      ck.checked = !!on;
    });
    updateCapCounts();
    syncMaterialSelection().catch(() => {});
  }
  function setAllScriptChecked(on) {
    lastScripts.forEach((s) => {
      scriptCheckMap[s.url] = !!on;
    });
    $$("#jsList .cap-check").forEach((ck) => {
      ck.checked = !!on;
    });
    updateCapCounts();
    syncMaterialSelection().catch(() => {});
  }
  $("#btnFlowCheckAll") &&
    $("#btnFlowCheckAll").addEventListener("click", () => setAllFlowChecked(true));
  $("#btnFlowCheckNone") &&
    $("#btnFlowCheckNone").addEventListener("click", () => setAllFlowChecked(false));
  $("#btnJsCheckAll") &&
    $("#btnJsCheckAll").addEventListener("click", () => setAllScriptChecked(true));
  $("#btnJsCheckNone") &&
    $("#btnJsCheckNone").addEventListener("click", () => setAllScriptChecked(false));
  $("#jsFilter") &&
    $("#jsFilter").addEventListener("input", () => {
      jsFilterText = $("#jsFilter").value || "";
      // 仅重绘 JS 列表：用缓存 data
      renderCapture({
        flows: lastFlows,
        scripts: lastScripts,
        hooks: ($("#hookView") && $("#hookView").textContent
          ? $("#hookView").textContent.split("\n").filter((x) => x && x !== "（暂无 Hook）")
          : []),
        counts: {
          flows: lastFlows.length,
          scripts: lastScripts.length,
          hooks: 0,
          flows_selected: collectFlowSelection().length,
          scripts_selected: collectScriptSelection().length,
        },
        browser: { running: !!( $("#browserDot") && $("#browserDot").classList.contains("on") ), logs_tail: [] },
      });
    });

  $$("#miniSubTabs button").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.dataset.msub;
      $$("#miniSubTabs button").forEach((b) => b.classList.toggle("active", b === btn));
      $$(".mini-sub").forEach((p) => p.classList.toggle("active", p.id === `msub-${id}`));
    });
  });
  $$("#appSubTabs button").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.dataset.asub;
      $$("#appSubTabs button").forEach((b) => b.classList.toggle("active", b === btn));
      $$(".app-sub").forEach((p) => p.classList.toggle("active", p.id === `asub-${id}`));
    });
  });

  $("#btnBrowserStart").addEventListener("click", async () => {
    const url = ($("#aiUrl") && $("#aiUrl").value.trim()) || "";
    if (!url) {
      alert("请填写目标 URL");
      return;
    }
    try {
      await saveAiConfigSilent();
      const opts = launchOptsFromUi();
      const out = await api("/api/browser/start", {
        method: "POST",
        body: JSON.stringify({ url, clear_session: false, ...opts }),
      });
      setBrowserDot(true);
      startCapPoll();
      toast("浏览器已启动 · " + (out.opts && out.opts.cdp_attach ? "CDP" : out.opts && out.opts.real_browser ? "真实" : "注入"));
      await refreshCapture();
    } catch (e) {
      showErr(e);
    }
  });

  $("#btnBrowserStop").addEventListener("click", async () => {
    try {
      await api("/api/browser/stop", { method: "POST" });
      toast("正在停止浏览器");
      await refreshCapture();
    } catch (e) {
      showErr(e);
    }
  });

  $("#btnAiSaveCfg").addEventListener("click", async () => {
    try {
      await saveAiConfigSilent();
      await loadAiConfig();
      toast("配置已保存");
      closeCfgFloat();
    } catch (e) {
      showErr(e);
    }
  });

  $("#btnAiAddMaterial").addEventListener("click", async () => {
    const text = $("#aiMaterial").value;
    if (!text.trim()) {
      alert("先粘贴内容再点加入");
      return;
    }
    try {
      if (aiMat === "js") {
        await api("/api/ai/session/script", {
          method: "POST",
          body: JSON.stringify({ url: $("#aiScriptUrl").value || "", code: text }),
        });
      } else {
        await api("/api/ai/session/http", {
          method: "POST",
          body: JSON.stringify({ raw: text }),
        });
      }
      $("#aiMaterial").value = "";
      await refreshAiSession();
      toast("素材已加入");
    } catch (e) {
      showErr(e);
    }
  });

  $("#btnAiClearSession").addEventListener("click", async () => {
    if (!confirm("清空全部素材？")) return;
    await api("/api/ai/session", { method: "DELETE" });
    await refreshAiSession();
  });

  $("#btnAiImportParser").addEventListener("click", async () => {
    const raw = $("#rawHttp").value || state.rawHttp;
    if (!raw.trim()) {
      alert("解析器还没有报文");
      showTab("parser");
      return;
    }
    try {
      await api("/api/ai/session/http", {
        method: "POST",
        body: JSON.stringify({ raw }),
      });
      await refreshAiSession();
      toast("已导入解析器报文");
      showTab("ailab");
    } catch (e) {
      showErr(e);
    }
  });

  const _aiOutCache = { log: "", result: "", code: "", hook: "", plugin: "" };

  function tryParseJsonSpan(lines, start) {
    const first = (lines[start] || "").trim();
    if (!first || (first[0] !== "{" && first[0] !== "[")) return null;
    let chunk = lines[start];
    for (let j = start; j < lines.length && chunk.length < 180000; j++) {
      if (j > start) chunk += "\n" + lines[j];
      try {
        const obj = JSON.parse(chunk);
        return { end: j, html: highlightBody(JSON.stringify(obj, null, 2)) };
      } catch (_) {
        /* keep growing */
      }
    }
    return null;
  }

  function highlightLlmIoLine(line) {
    if (/^={3,}.*={3,}\s*$/.test(line)) {
      return `<span class="hk-banner">${escapeHtml(line)}</span>`;
    }
    if (/^——.+——\s*$/.test(line) || /^—{2,}.+—{2,}\s*$/.test(line)) {
      return `<span class="hk-section">${escapeHtml(line)}</span>`;
    }
    let m = line.match(/^(\[step\s+\d+\])(\s*)([\w.-]+)?(.*)$/i);
    if (m) {
      return (
        `<span class="hk-step">${escapeHtml(m[1])}</span>` +
        escapeHtml(m[2] || "") +
        (m[3] ? `<span class="hk-tool">${escapeHtml(m[3])}</span>` : "") +
        highlightInlineSoft(m[4] || "")
      );
    }
    if (/^(✅|✔|完成|Confirmed)/.test(line.trim()) || /\bok\b/i.test(line) && /成功|完成|Confirmed/.test(line)) {
      return `<span class="hk-ok">${escapeHtml(line)}</span>`;
    }
    if (/^(❌|失败|错误|Error|Traceback)/i.test(line.trim())) {
      return `<span class="hk-err">${escapeHtml(line)}</span>`;
    }
    m = line.match(
      /^((?:tools|stop_reason|usage|mode|模型|Agent 端点|代理|素材|目标字段|提示)\s*[:：])/
    );
    if (m) {
      return (
        `<span class="hk-meta">${escapeHtml(m[1])}</span>` +
        highlightInlineSoft(line.slice(m[1].length))
      );
    }
    if (/^\s*URL:\s*/i.test(line)) {
      return line.replace(/^(.*URL:\s*)(.+)$/i, (_, a, b) => {
        return escapeHtml(a) + `<span class="hk-url">${escapeHtml(b)}</span>`;
      });
    }
    if (/^\s*\d+\.\s+/.test(line)) {
      return line.replace(/^(\s*\d+\.\s+)(.*)$/, (_, a, b) => {
        return `<span class="hk-step">${escapeHtml(a)}</span>` + highlightInlineSoft(b);
      });
    }
    return highlightInlineSoft(line);
  }

  function highlightInlineSoft(seg) {
    const s = String(seg);
    if (!s) return "";
    // URL
    const urlRe = /(https?:\/\/[^\s"'<>]+)/g;
    let out = "";
    let last = 0;
    let m;
    while ((m = urlRe.exec(s))) {
      out += highlightJsonValue(s.slice(last, m.index));
      out += `<span class="hk-url">${escapeHtml(m[1])}</span>`;
      last = m.index + m[1].length;
    }
    out += highlightJsonValue(s.slice(last));
    return out;
  }

  function highlightLlmIo(text) {
    const lines = String(text || "").split("\n");
    const out = [];
    for (let i = 0; i < lines.length; ) {
      const span = tryParseJsonSpan(lines, i);
      if (span) {
        out.push(span.html);
        i = span.end + 1;
        continue;
      }
      out.push(highlightLlmIoLine(lines[i]));
      i += 1;
    }
    return out.join("\n");
  }

  function highlightCodeLocations(text) {
    return String(text || "")
      .split("\n")
      .map((line) => {
        if (/^\s*URL:\s*/i.test(line)) {
          return line.replace(/^(.*URL:\s*)(.+)$/i, (_, a, b) => {
            return escapeHtml(a) + `<span class="hk-url">${escapeHtml(b)}</span>`;
          });
        }
        if (/^\s*\d+\.\s*/.test(line)) {
          return line.replace(/^(\s*\d+\.\s*)(.*)$/, (_, a, b) => {
            return `<span class="hk-step">${escapeHtml(a)}</span><span class="hk-ident">${escapeHtml(b)}</span>`;
          });
        }
        if (/片段:/.test(line)) {
          const i = line.indexOf("片段:");
          return (
            escapeHtml(line.slice(0, i)) +
            `<span class="hk-meta">片段:</span>` +
            `<span class="hk-str">${escapeHtml(line.slice(i + 3))}</span>`
          );
        }
        if (/约第|offset=/.test(line)) {
          return `<span class="hk-meta">${escapeHtml(line)}</span>`;
        }
        return highlightInlineSoft(line);
      })
      .join("\n");
  }

  function highlightAgentText(raw, kind) {
    const text = String(raw ?? "");
    if (!text.trim()) {
      return `<span class="hk-muted">${escapeHtml(text || "（空）")}</span>`;
    }
    // 运行中日志过长时截断高亮尾部，避免卡顿
    let src = text;
    let note = "";
    if ((kind === "log" || kind === "result") && src.length > 120000) {
      note = `<span class="hk-muted">…(前文已省略高亮 ${src.length - 100000} 字符)\n</span>`;
      src = src.slice(-100000);
    }
    if (kind === "hook") {
      const t = src.trim();
      if (t[0] === "{" || t[0] === "[") return note + highlightBody(src);
      return note + (highlightJs(src) || `<span class="hk-body">${escapeHtml(src)}</span>`);
    }
    if (kind === "plugin" || kind === "result") {
      const t = src.trim();
      if (t[0] === "{" || t[0] === "[") return note + highlightBody(src);
      return note + highlightLlmIo(src);
    }
    if (kind === "code") return note + highlightCodeLocations(src);
    return note + highlightLlmIo(src);
  }

  function setAiOutHighlighted(el, text, kind, cacheKey) {
    if (!el) return;
    const plain = text == null ? "" : String(text);
    if (_aiOutCache[cacheKey] === plain && el.dataset.hl === "1") return;
    _aiOutCache[cacheKey] = plain;
    el.classList.add("burp");
    el.dataset.hl = "1";
    el.innerHTML = highlightAgentText(plain, kind) || "&nbsp;";
  }

  function renderAiJob(job) {
    const st = job.status || "idle";
    const pill = $("#aiJobMeta");
    if (pill) {
      pill.classList.remove("busy", "ok", "err");
      const label =
        st === "running"
          ? "分析中…"
          : st === "ok"
            ? "完成"
            : st === "failed"
              ? "失败"
              : st === "cancelled"
                ? "已停止"
                : "就绪";
      pill.textContent = job.mode ? `${label} · ${job.mode}` : label;
      if (st === "running") pill.classList.add("busy");
      if (st === "ok") pill.classList.add("ok");
      if (st === "failed") pill.classList.add("err");
    }
    const logText = (job.logs || []).join("\n") || "（暂无日志）";
    const resultText = job.result || job.error || "（暂无结果）";
    setAiOutHighlighted($("#aiLog"), logText, "log", "log");
    setAiOutHighlighted($("#aiResult"), resultText, "result", "result");
    renderAiCtxTable(job.context || []);
    setAiOutHighlighted(
      $("#aiCodeLoc"),
      job.code_locations || "（暂无源码位置；逆向/识别结果含 code_locations 时显示）",
      "code",
      "code"
    );
    setAiOutHighlighted(
      $("#aiHookOut"),
      job.hook || "（暂无 Hook 脚本 / 日志）",
      "hook",
      "hook"
    );
    setAiOutHighlighted(
      $("#aiPluginOut"),
      job.plugin || "（暂无 steps；分析加解密成功后显示步骤预览）",
      "plugin",
      "plugin"
    );
    if (st === "running") {
      const logEl = $("#aiLog");
      if (logEl) logEl.scrollTop = logEl.scrollHeight;
      if (aiOut !== "log") aiOut = "log";
      // 验证进行中：日志里会出现「自动验证」
      if ((job.logs || []).some((x) => String(x).includes("自动验证"))) {
        pill && (pill.textContent = job.mode ? `验证中… · ${job.mode}` : "验证中…");
      }
    }
    if (st === "ok" && aiOut === "log") {
      aiOut = job.verify ? "plugin" : "result";
    }
    syncAiOutPanes();
    if (st === "ok" && job.verify) {
      const key = `${job.id || ""}:${(job.verify && job.verify.attempt) || 0}:${
        job.verify.overall_ok ? 1 : 0
      }`;
      if (key !== _verifyShownKey) {
        _verifyShownKey = key;
        showVerifyDialog(job.verify);
      }
    }
  }

  function renderVerifyFields(tbody, fields) {
    if (!tbody) return;
    const list = Array.isArray(fields) ? fields : [];
    if (!list.length) {
      tbody.innerHTML =
        '<tr><td colspan="5" class="muted">（无字段验证项）</td></tr>';
      return;
    }
    tbody.innerHTML = list
      .map((f) => {
        const preview = String(f.after || f.before || "").slice(0, 200);
        const method = String(f.method || "—");
        return `<tr>
          <td>${escapeHtml(f.field || "")}</td>
          <td class="${f.ok ? "ok" : "bad"}"><span class="verify-ico ${f.ok ? "ok" : "bad"}" title="${f.ok ? "通过" : "未通过"}" aria-label="${f.ok ? "通过" : "未通过"}"></span></td>
          <td class="verify-method" title="${escapeAttr(method)}">${escapeHtml(method)}</td>
          <td>${escapeHtml(f.message || "")}</td>
          <td title="${escapeAttr(preview)}">${escapeHtml(preview)}</td>
        </tr>`;
      })
      .join("");
  }

  function syncVerifyIo(side) {
    const report = _verifyReport || {};
    const s = side === "resp" ? report.response || {} : report.request || {};
    const which = _verifyIo[side] || "after";
    const el = side === "resp" ? $("#verifyRespIo") : $("#verifyReqIo");
    if (el) el.textContent = (which === "before" ? s.before : s.after) || "(空)";
    $$(`.verify-io-tabs[data-for="${side}"] button`).forEach((b) =>
      b.classList.toggle("active", b.dataset.vio === which)
    );
  }

  function fillVerifySide(sideKey, side) {
    const s = side || {};
    const msgEl = sideKey === "resp" ? $("#verifyRespMsg") : $("#verifyReqMsg");
    const tb = sideKey === "resp" ? $("#verifyRespFields") : $("#verifyReqFields");
    if (msgEl) msgEl.textContent = s.message || "";
    renderVerifyFields(tb, s.fields || []);
    const preferAfter = !!(s.after && s.after !== s.before);
    _verifyIo[sideKey] = preferAfter ? "after" : "before";
    syncVerifyIo(sideKey);
  }

  let _verifyEncryptOk = false;

  function showVerifyDialog(report, opts) {
    const mask = $("#verifyMask");
    if (!mask || !report) return;
    _verifyReport = report;
    const keepEncrypt = !!(opts && opts.keepEncrypt);
    if (!keepEncrypt) _verifyEncryptOk = false;
    const ok = !!report.overall_ok;
    const attempt = report.attempt || 1;
    const maxA = report.max_attempts || 5;
    const role = String(report.role || "decrypt").toLowerCase();
    const title = $("#verifyTitle");
    if (title) {
      title.textContent = ok
        ? _verifyEncryptOk
          ? `加解密自动验证 — 解密+加密通过（第 ${attempt}/${maxA} 次）`
          : `加解密自动验证 — 通过（第 ${attempt}/${maxA} 次）`
        : `加解密自动验证 — 未通过（第 ${attempt}/${maxA} 次）`;
    }
    const tip = $("#verifyTip");
    if (tip) {
      if (!ok) {
        tip.hidden = false;
        tip.textContent =
          attempt >= maxA
            ? `已连续验证 ${maxA} 次仍未通过。可取消，或仍强制继续写入。`
            : "验证未通过。后台已尽量自动修正；仍可强制继续生成，或取消。";
      } else if (_verifyEncryptOk) {
        tip.hidden = false;
        tip.textContent =
          "加密分析通过：重加密与原密文一致。确认后将生成解密 + 加密代码。";
      } else {
        tip.hidden = true;
        tip.textContent = "";
      }
    }
    const sum = $("#verifySummary");
    if (sum) {
      sum.textContent = report.summary || (ok ? "验证通过" : "验证未通过");
      sum.classList.toggle("ok", ok);
      sum.classList.toggle("err", !ok);
    }
    const meta = $("#verifyMeta");
    if (meta) {
      meta.textContent = [
        report.role ? `角色: ${report.role}` : "",
        report.plugin_notice ? String(report.plugin_notice) : "",
        report.error ? `错误: ${report.error}` : "",
      ]
        .filter(Boolean)
        .join(" · ");
    }

    fillVerifySide("req", report.request);
    fillVerifySide("resp", report.response);

    // 默认 Tab：有响应结论则切响应
    const preferResp =
      (report.request && report.request.ok == null) &&
      report.response &&
      report.response.ok != null;
    $$("#verifySideTabs button").forEach((b) =>
      b.classList.toggle("active", b.dataset.vside === (preferResp ? "resp" : "req"))
    );
    if ($("#verifySideReq")) $("#verifySideReq").hidden = !!preferResp;
    if ($("#verifySideResp")) $("#verifySideResp").hidden = !preferResp;

    const okBtn = $("#btnVerifyOk");
    const forceBtn = $("#btnVerifyForce");
    const analyzeBtn = $("#btnVerifyAnalyzeEncrypt");
    if (okBtn) {
      okBtn.hidden = !ok;
      okBtn.textContent = _verifyEncryptOk
        ? "验证通过、生成加解密代码"
        : "验证通过、生成解密代码";
    }
    if (forceBtn) forceBtn.hidden = ok;
    if (analyzeBtn) {
      const showAna = ok && role === "decrypt" && !_verifyEncryptOk;
      analyzeBtn.hidden = !showAna;
      analyzeBtn.disabled = false;
      analyzeBtn.textContent = "分析加密";
    }

    mask.hidden = false;
    if (!keepEncrypt) {
      toast(ok ? "加解密验证通过" : "加解密验证未通过，详见弹窗");
    }
  }

  async function analyzeEncryptFromVerify() {
    const analyzeBtn = $("#btnVerifyAnalyzeEncrypt");
    const okBtn = $("#btnVerifyOk");
    const tip = $("#verifyTip");
    try {
      if (analyzeBtn) analyzeBtn.disabled = true;
      const out = await api("/api/ai/analyze-encrypt", { method: "POST", body: "{}" });
      if (out.verify) {
        _verifyReport = out.verify;
        fillVerifySide("req", out.verify.request);
        fillVerifySide("resp", out.verify.response);
        const sum = $("#verifySummary");
        if (sum) {
          sum.textContent = out.verify.summary || "";
          sum.classList.toggle("ok", !!out.overall_ok);
          sum.classList.toggle("err", !out.overall_ok);
        }
      }
      if (out.overall_ok) {
        _verifyEncryptOk = true;
        if (okBtn) okBtn.textContent = "验证通过、生成加解密代码";
        if (analyzeBtn) {
          analyzeBtn.textContent = "加密已验证";
          analyzeBtn.hidden = true;
        }
        if (tip) {
          tip.hidden = false;
          tip.textContent =
            "加密分析通过：重加密与原密文一致。确认后将生成解密 + 加密代码。";
        }
        const title = $("#verifyTitle");
        if (title) title.textContent = "加解密自动验证 — 解密+加密通过";
        toast("加密回环验证通过");
      } else {
        _verifyEncryptOk = false;
        if (okBtn) okBtn.textContent = "验证通过、生成解密代码";
        if (analyzeBtn) analyzeBtn.disabled = false;
        if (tip) {
          tip.hidden = false;
          tip.textContent =
            (out.verify && out.verify.summary) ||
            "加密分析未通过，仍可只生成解密代码。";
        }
        toast("加密回环未通过");
      }
    } catch (e) {
      if (analyzeBtn) analyzeBtn.disabled = false;
      showErr(e);
    }
  }

  function closeVerifyDialog() {
    const mask = $("#verifyMask");
    if (mask) mask.hidden = true;
  }

  async function openGenerateDialog() {
    closeVerifyDialog();
    try {
      const opts = await api("/api/ai/generate-options");
      _genOpts = opts;
      const role = opts.code_role || "decrypt";
      const both = !!opts.both || _verifyEncryptOk;
      _genOpts.both = both;
      $("#genTitle").textContent = both
        ? "生成加解密代码"
        : role === "encrypt"
          ? "生成加密脚本"
          : "生成解密脚本";
      $("#genScriptType").textContent =
        opts.script_type ||
        (both ? "加解密脚本（解密 + 加密各一份）" : "解密脚本");
      const cur = ($("#globalProject") && $("#globalProject").value) || state.current || "";
      const base = cur || opts.name || "";
      const nameRow = $("#genNameRow");
      const decRow = $("#genDecNameRow");
      const encRow = $("#genEncNameRow");
      if (nameRow) nameRow.hidden = !!both;
      if (decRow) decRow.hidden = !both;
      if (encRow) encRow.hidden = !both;
      if (both) {
        if ($("#genDecryptName")) $("#genDecryptName").value = base;
        if ($("#genEncryptName")) {
          $("#genEncryptName").value = base ? `${base}_encrypt` : "";
        }
      } else if ($("#genProjectName")) {
        $("#genProjectName").value = base;
      }
      const m = opts.match || {};
      $("#genMatchRules").textContent = [
        `Host: ${(m.host || []).join(", ") || "*"}`,
        `Path: ${(m.path || []).join(", ") || "/*"}`,
        `Methods: ${(m.methods || []).join(", ") || "POST"}`,
      ].join("\n");
      $("#genMask").hidden = false;
      if (both && $("#genDecryptName")) $("#genDecryptName").focus();
      else if ($("#genProjectName")) $("#genProjectName").focus();
    } catch (e) {
      showErr(e);
    }
  }

  function closeGenerateDialog() {
    const mask = $("#genMask");
    if (mask) mask.hidden = true;
  }

  async function confirmGeneratePlugin() {
    const role = (_genOpts && _genOpts.code_role) || "decrypt";
    const both = !!(_genOpts && _genOpts.both);
    const match = (_genOpts && _genOpts.match) || null;
    let name = "";
    let encryptName = "";
    if (both) {
      name = (($("#genDecryptName") && $("#genDecryptName").value) || "").trim();
      encryptName = (
        ($("#genEncryptName") && $("#genEncryptName").value) ||
        ""
      ).trim();
      if (!name) {
        toast("请填写解密项目名称");
        return;
      }
      if (!encryptName) {
        toast("请填写加密项目名称");
        return;
      }
      if (name === encryptName) {
        toast("解密项目与加密项目不能同名");
        return;
      }
    } else {
      name = (($("#genProjectName") && $("#genProjectName").value) || "").trim();
      if (!name) {
        toast("请填写项目名称");
        return;
      }
    }
    try {
      // 已存在则确认覆盖
      const projects = state.projects || [];
      const exists = projects.some(
        (p) =>
          p.id === name ||
          p.name === name ||
          (both && (p.id === encryptName || p.name === encryptName))
      );
      if (exists && !confirm(`项目「${name}」已存在，是否覆盖？`)) return;

      const out = await api("/api/ai/apply-steps", {
        method: "POST",
        body: JSON.stringify({
          project: name,
          encrypt_project: both ? encryptName : "",
          create_if_missing: true,
          overwrite: true,
          roles: both ? ["decrypt"] : [role],
          code_role: role,
          both,
          match,
          result_text: ($("#aiResult") && $("#aiResult").textContent) || "",
        }),
      });
      closeGenerateDialog();
      state.current = out.project;
      await loadProjects();
      if ($("#globalProject")) $("#globalProject").value = state.current;
      await openProject(state.current);
      if (typeof loadPipelineFromProject === "function") {
        await loadPipelineFromProject();
      }
      if (out.encrypt_project) {
        toast(`已生成加解密：${out.project} + ${out.encrypt_project}`);
      } else {
        toast(`已生成${role === "encrypt" ? "加密" : "解密"}脚本 → ${out.project}`);
      }
      showTab("builder");
    } catch (e) {
      showErr(e);
    }
  }

  $("#btnVerifyClose") &&
    $("#btnVerifyClose").addEventListener("click", closeVerifyDialog);
  $("#btnVerifyCancel") &&
    $("#btnVerifyCancel").addEventListener("click", closeVerifyDialog);
  $("#btnVerifyOk") &&
    $("#btnVerifyOk").addEventListener("click", () => openGenerateDialog());
  $("#btnVerifyForce") &&
    $("#btnVerifyForce").addEventListener("click", () => openGenerateDialog());
  $("#btnVerifyAnalyzeEncrypt") &&
    $("#btnVerifyAnalyzeEncrypt").addEventListener("click", () => {
      analyzeEncryptFromVerify();
    });
  $("#verifyMask") &&
    $("#verifyMask").addEventListener("click", (e) => {
      if (e.target === $("#verifyMask")) closeVerifyDialog();
    });
  $$("#verifySideTabs button").forEach((btn) => {
    btn.addEventListener("click", () => {
      const side = btn.dataset.vside || "req";
      $$("#verifySideTabs button").forEach((b) =>
        b.classList.toggle("active", b === btn)
      );
      $("#verifySideReq").hidden = side !== "req";
      $("#verifySideResp").hidden = side !== "resp";
    });
  });
  $$(".verify-io-tabs button").forEach((btn) => {
    btn.addEventListener("click", () => {
      const side = btn.parentElement && btn.parentElement.dataset.for;
      if (!side) return;
      _verifyIo[side] = btn.dataset.vio || "after";
      syncVerifyIo(side);
    });
  });

  $("#btnGenClose") &&
    $("#btnGenClose").addEventListener("click", closeGenerateDialog);
  $("#btnGenCancel") &&
    $("#btnGenCancel").addEventListener("click", closeGenerateDialog);
  $("#btnGenOk") &&
    $("#btnGenOk").addEventListener("click", () => confirmGeneratePlugin());
  $("#genMask") &&
    $("#genMask").addEventListener("click", (e) => {
      if (e.target === $("#genMask")) closeGenerateDialog();
    });
  $("#genProjectName") &&
    $("#genProjectName").addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        confirmGeneratePlugin();
      }
    });

  function stopAiPoll() {
    if (aiPoll) {
      clearInterval(aiPoll);
      aiPoll = null;
    }
  }

  async function pollAiJob() {
    try {
      const job = await api("/api/ai/job");
      renderAiJob(job);
      if (job.status && job.status !== "running" && job.status !== "idle") {
        stopAiPoll();
        if (job.status === "ok" && !job.verify) toast("分析完成");
      }
    } catch (e) {
      stopAiPoll();
      console.warn(e);
    }
  }

  async function startAiJob(mode, goal, fieldTargets) {
    // 对齐 GUI：启动前同步勾选流量/JS
    try {
      await syncMaterialSelection();
    } catch (e) {
      console.warn(e);
    }
    const body = {
      mode: mode || "recognize",
      goal: goal || "",
    };
    if (fieldTargets) body.field_targets = fieldTargets;
    _verifyShownKey = "";
    const out = await api("/api/ai/run", {
      method: "POST",
      body: JSON.stringify(body),
    });
    renderAiJob(out);
    stopAiPoll();
    aiPoll = setInterval(pollAiJob, 800);
    toast(`已开始 · ${modeLabel(body.mode)}`);
  }

  function applyFieldHint(picked) {
    const hint = $("#aiFieldHint");
    if (!hint || !picked) return;
    const d = (picked.decrypt || []).map((x) => x.path).slice(0, 3).join(",");
    const e = (picked.encrypt || []).map((x) => x.path).slice(0, 3).join(",");
    hint.textContent = picked.unrestricted
      ? "未限定字段（盲目分析）"
      : `目标: ${d || e || "已选"} · ${picked.analysis_role === "encrypt" ? "加密" : "解密"}`;
  }

  /** 对齐 GUI：弹字段选择 → 确认后开跑 */
  async function runWithFieldPick(mode) {
    try {
      await saveAiConfigSilent();
      let runMode = mode || "generate";
      selectAiMode(runMode);
      const defaultRole = runMode === "generate_encrypt" ? "encrypt" : "decrypt";
      const picked = await openFieldTargetDialog(defaultRole);
      if (!picked) {
        toast("已取消字段选择");
        return;
      }
      lastFieldTargets = picked;
      applyFieldHint(picked);
      if (picked.analysis_role === "encrypt" && (runMode === "generate" || runMode === "recognize")) {
        // 识别仍用 recognize；分析加解密点加密则走生成加密
        if (runMode === "generate") runMode = "generate_encrypt";
      } else if (picked.analysis_role === "decrypt" && runMode === "generate_encrypt") {
        runMode = "generate";
      }
      const goal = ($("#aiGoal").value || "").trim();
      await startAiJob(runMode, goal, picked);
    } catch (e) {
      showErr(e);
    }
  }

  $("#btnAnalyzeCrypto") &&
    $("#btnAnalyzeCrypto").addEventListener("click", () => {
      const mode = ($("#aiMode") && $("#aiMode").value) || "generate";
      runSelectedMode(mode).catch(showErr);
    });
  $("#btnRecognize") &&
    $("#btnRecognize").addEventListener("click", () => {
      selectAiMode("recognize");
      runWithFieldPick("recognize").catch(showErr);
    });

  $("#btnAiRun").addEventListener("click", async () => {
    try {
      await runSelectedMode(($("#aiMode") && $("#aiMode").value) || "recognize");
    } catch (e) {
      showErr(e);
    }
  });

  // 底部对话模式下拉变更时，同步上方卡片选中态
  $("#aiChatMode") &&
    $("#aiChatMode").addEventListener("change", () => {
      const v = $("#aiChatMode").value || "chat";
      const mapBack = {
        chat: "generate",
        anti_debug: "anti_debug",
        bot_bypass: "bot_bypass",
        fingerprint_hook: "fingerprint_hook",
        js_reverse: "js_reverse",
        js_deobfuscate: "js_deobfuscate",
        hash_hook: "hash_hook",
      };
      const id = mapBack[v] || "generate";
      selectAiMode(id);
      if (id === "bot_bypass") openBypassFloat({ autoStart: false, syncUrl: true });
    });

  // ── 小程序 / App ─────────────────────────────────
  async function refreshMiniList() {
    const box = $("#miniList");
    const st = $("#miniStatus");
    if (!box) return;
    st.textContent = "扫描中…";
    box.innerHTML = `<div class="muted" style="padding:12px">扫描本机微信包目录…</div>`;
    try {
      const data = await api("/api/miniprogram/list");
      const apps = data.apps || [];
      st.textContent = apps.length
        ? `找到 ${apps.length} 个小程序`
        : "未找到，请先在微信打开目标小程序再刷新";
      box.innerHTML = apps.length
        ? apps
            .map(
              (a) =>
                `<button type="button" data-path="${escapeAttr(a.path)}" data-appid="${escapeAttr(
                  a.appid
                )}">
                  <div>${escapeHtml(a.display_name || a.appid)}</div>
                  <div class="sub">${escapeHtml(a.appid)} · ${a.pkg_count || 0} 包</div>
                </button>`
            )
            .join("")
        : `<div class="muted" style="padding:12px">未找到 wx***** 包。可确认微信已登录并打开过小程序。</div>`;
      box.querySelectorAll("button").forEach((btn) => {
        btn.addEventListener("click", () => decompileMini(btn.dataset.path, btn.dataset.appid));
      });
    } catch (e) {
      st.textContent = "扫描失败";
      box.innerHTML = `<div class="muted" style="padding:12px">${escapeHtml(
        String(e.message || e)
      )}</div>`;
    }
  }

  async function decompileMini(path, appid) {
    const log = $("#miniLog");
    const hits = $("#miniHits");
    log.textContent = `解包中…\n${path}`;
    hits.innerHTML = "";
    try {
      const out = await api("/api/miniprogram/decompile", {
        method: "POST",
        body: JSON.stringify({ path, appid, inject_session: true }),
      });
      const lines = (out.messages || []).concat([
        `输出: ${out.out_dir}`,
        `候选脚本: ${out.script_count || 0}`,
      ]);
      log.textContent = lines.join("\n");
      const list = out.hits || [];
      hits.innerHTML = list.length
        ? list
            .map(
              (h) =>
                `<button type="button" data-path="${escapeAttr(h.path)}">
                  <div>[${h.score}] ${escapeHtml(h.relpath || "")}</div>
                </button>`
            )
            .join("")
        : `<div class="muted" style="padding:8px">未筛到明显加解密关键字，脚本仍可能已注入会话</div>`;
      hits.querySelectorAll("button").forEach((btn) => {
        btn.addEventListener("click", async () => {
          try {
            const d = await api("/api/reverse/preview", {
              method: "POST",
              body: JSON.stringify({ path: btn.dataset.path }),
            });
            openFloat(btn.textContent.trim(), d.code || "", null, "js");
          } catch (e) {
            openFloat("预览失败", String(e.message || e));
          }
        });
      });
      await refreshCapture();
      // 切到候选 JS 子类
      $$("#miniSubTabs button").forEach((b) =>
        b.classList.toggle("active", b.dataset.msub === "hits")
      );
      $$(".mini-sub").forEach((p) =>
        p.classList.toggle("active", p.id === "msub-hits")
      );
      toast(`小程序已解包 · 注入 ${out.script_count || 0} 脚本`);
    } catch (e) {
      log.textContent = String(e.message || e);
      showErr(e);
    }
  }

  $("#btnMiniRefresh") &&
    $("#btnMiniRefresh").addEventListener("click", () => refreshMiniList());

  async function refreshAppTools() {
    const hint = $("#appToolsHint");
    if (!hint) return;
    try {
      const d = await api("/api/app/tools");
      const miss = d.missing || [];
      hint.textContent = miss.length
        ? `缺少: ${miss.join(", ")} — 请把工具放到 tools 目录`
        : `工具就绪 · 工作区 ${d.workspace || ""}`;
    } catch (e) {
      hint.textContent = String(e.message || e);
    }
  }

  $("#btnAppTools") &&
    $("#btnAppTools").addEventListener("click", async () => {
      await refreshAppTools();
      try {
        const d = await api("/api/app/tools");
        openFloat("App 逆向工具", d.message || JSON.stringify(d.tools || {}, null, 2));
      } catch (e) {
        showErr(e);
      }
    });

  $("#btnAppDecode") &&
    $("#btnAppDecode").addEventListener("click", async () => {
      const apk = ($("#apkPath") && $("#apkPath").value.trim()) || "";
      if (!apk) {
        alert("请填写本机 APK 绝对路径");
        return;
      }
      const log = $("#appLog");
      const hits = $("#appHits");
      log.textContent = "反编译中，请稍候…";
      hits.innerHTML = "";
      try {
        const out = await api("/api/app/decode", {
          method: "POST",
          body: JSON.stringify({ apk_path: apk, inject_session: true }),
        });
        const lines = (out.messages || []).concat([
          `包名: ${out.package || "-"}`,
          `输出: ${out.out_dir}`,
          `候选: ${out.script_count || 0}`,
        ]);
        log.textContent = lines.join("\n");
        const list = out.hits || [];
        hits.innerHTML = list.length
          ? list
              .map(
                (h) =>
                  `<button type="button" data-path="${escapeAttr(h.path)}">
                    <div>[${h.score}] ${escapeHtml(h.relpath || "")}</div>
                  </button>`
              )
              .join("")
          : `<div class="muted" style="padding:8px">未筛到候选，可检查 tools 或用 jadx 手工定位</div>`;
        hits.querySelectorAll("button").forEach((btn) => {
          btn.addEventListener("click", async () => {
            try {
              const d = await api("/api/reverse/preview", {
                method: "POST",
                body: JSON.stringify({ path: btn.dataset.path }),
              });
              openFloat(btn.textContent.trim(), d.code || "", null, "js");
            } catch (e) {
              openFloat("预览失败", String(e.message || e));
            }
          });
        });
        await refreshCapture();
        $$("#appSubTabs button").forEach((b) =>
          b.classList.toggle("active", b.dataset.asub === "hits")
        );
        $$(".app-sub").forEach((p) =>
          p.classList.toggle("active", p.id === "asub-hits")
        );
        toast(`APK 已扫描 · 注入 ${out.script_count || 0} 脚本`);
      } catch (e) {
        log.textContent = String(e.message || e);
        // 失败时也切到日志子类便于看错误
        $$("#appSubTabs button").forEach((b) =>
          b.classList.toggle("active", b.dataset.asub === "log")
        );
        $$(".app-sub").forEach((p) =>
          p.classList.toggle("active", p.id === "asub-log")
        );
        showErr(e);
      }
    });


  // ── AI 绕过悬浮窗 ─────────────────────────────────
  function bindBypassFloat() {
    const mask = $("#bypassMask");
    if (!mask) return;
    const close = () => closeBypassFloat();
    $("#btnBypassClose") && $("#btnBypassClose").addEventListener("click", close);
    $("#btnBypassClose2") && $("#btnBypassClose2").addEventListener("click", close);
    mask.addEventListener("click", (e) => {
      if (e.target === mask && !_bypassBusy) close();
    });
    $$("#bypassTabs button").forEach((btn) => {
      btn.addEventListener("click", () => syncBypassTab(btn.dataset.btab || "summary"));
    });
    $("#btnBypassStart") &&
      $("#btnBypassStart").addEventListener("click", () => {
        startLiveBypassFromFloat({ sweepThenAgent: true }).catch(showErr);
      });
    $("#btnBypassSweepOnly") &&
      $("#btnBypassSweepOnly").addEventListener("click", () => {
        const sweep = $("#bypassSweep");
        if (sweep) sweep.checked = true;
        startLiveBypassFromFloat({ sweepThenAgent: false }).catch(showErr);
      });
    $("#btnBypassStop") &&
      $("#btnBypassStop").addEventListener("click", () => {
        stopAiJob().catch(showErr);
      });
    const sendFollow = () => {
      const input = $("#bypassFollow");
      let goal = (input && input.value) || "";
      goal = goal.trim();
      if (!goal) {
        toast("请输入追问内容");
        return;
      }
      if (input) input.value = "";
      const url = (($("#bypassUrl") && $("#bypassUrl").value) || "").trim();
      if (url && !goal.includes(url)) goal = `${goal}\n目标地址: ${url}`;
      startLiveBypassFromFloat({ sweepThenAgent: true, goal }).catch(showErr);
    };
    $("#btnBypassFollow") && $("#btnBypassFollow").addEventListener("click", sendFollow);
    $("#bypassFollow") &&
      $("#bypassFollow").addEventListener("keydown", (e) => {
        if (e.key !== "Enter" || e.isComposing) return;
        e.preventDefault();
        sendFollow();
      });
  }
  bindBypassFloat();

  $("#btnAiStop").addEventListener("click", async () => {
    try {
      await stopAiJob();
    } catch (e) {
      showErr(e);
    }
  });

  $("#btnAiComposerStop") &&
    $("#btnAiComposerStop").addEventListener("click", async () => {
      try {
        await stopAiJob();
      } catch (e) {
        showErr(e);
      }
    });

  $("#btnAiSend") &&
    $("#btnAiSend").addEventListener("click", async () => {
      try {
        await saveAiConfigSilent();
        await sendAiComposer();
      } catch (e) {
        showErr(e);
      }
    });

  $("#aiChatInput") &&
    $("#aiChatInput").addEventListener("keydown", async (e) => {
      if (e.key !== "Enter" || e.isComposing) return;
      e.preventDefault();
      try {
        await saveAiConfigSilent();
        await sendAiComposer();
      } catch (err) {
        showErr(err);
      }
    });

  // ── init ──────────────────────────────────────────
  bindBrowserMenus();
  Promise.all([
    loadProjects(),
    loadOps(),
    loadTemplates(),
    loadProxy(),
    loadSettings(),
    loadAiConfig(),
    loadAiModes(),
    refreshAiSession(),
    refreshCapture(),
  ])
    .then(async () => {
      await loadHome();
      if (state.current) {
        await openProject(state.current);
        await loadPipelineFromProject();
      }
      renderSteps();
      await refreshPreview();
      const job = await api("/api/ai/job");
      renderAiJob(job);
      if (job.status === "running") aiPoll = setInterval(pollAiJob, 800);
      const st = await api("/api/browser/status");
      if (st.running) startCapPoll();
      syncBrowserModeUi();
    })
    .catch(showErr);
})();
