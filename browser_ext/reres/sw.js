/**
 * ReRes MV3 — 密桥内置（declarativeNetRequest）
 * 规则存在 chrome.storage.local.ReResMap
 * 项: { req: 正则字符串, res: 替换串(http/https), checked: bool }
 */
const RULE_ID_BASE = 1000;
const MAX_RULES = 50;

async function loadMap() {
  const data = await chrome.storage.local.get("ReResMap");
  const map = data.ReResMap;
  return Array.isArray(map) ? map : [];
}

async function syncRules() {
  const map = await loadMap();
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing.map((r) => r.id);
  const addRules = [];
  let i = 0;
  for (const item of map) {
    if (!item || !item.checked || !item.req || typeof item.res !== "string") continue;
    if (!/^https?:\/\//i.test(item.res) && !item.res.includes("$")) {
      // 仅支持 http(s) 替换或带捕获组的替换模板；file:// 请用密桥响应改写/本地代理
      continue;
    }
    if (i >= MAX_RULES) break;
    const id = RULE_ID_BASE + i;
    i += 1;
    // regexFilter 使用 RE2；用户规则按「匹配后整 URL 重写」简化为 redirect regexSubstitution
    try {
      addRules.push({
        id,
        priority: 1,
        action: {
          type: "redirect",
          redirect: { regexSubstitution: String(item.res) },
        },
        condition: {
          regexFilter: String(item.req),
          resourceTypes: [
            "main_frame",
            "sub_frame",
            "stylesheet",
            "script",
            "image",
            "font",
            "object",
            "xmlhttprequest",
            "ping",
            "csp_report",
            "media",
            "websocket",
            "other",
          ],
        },
      });
    } catch (e) {
      console.warn("[ReRes] skip rule", item, e);
    }
  }
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds,
    addRules,
  });
  console.log("[ReRes] rules synced:", addRules.length);
}

chrome.runtime.onInstalled.addListener(syncRules);
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.ReResMap) syncRules();
});
syncRules();
