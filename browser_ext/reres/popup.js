async function load() {
  const data = await chrome.storage.local.get("ReResMap");
  const map = Array.isArray(data.ReResMap) ? data.ReResMap : [];
  document.getElementById("rules").value = JSON.stringify(map, null, 2);
}

document.getElementById("save").addEventListener("click", async () => {
  const el = document.getElementById("msg");
  try {
    const map = JSON.parse(document.getElementById("rules").value || "[]");
    if (!Array.isArray(map)) throw new Error("必须是数组");
    await chrome.storage.local.set({ ReResMap: map });
    el.textContent = "已保存，规则已同步";
  } catch (e) {
    el.textContent = "保存失败: " + e.message;
    el.style.color = "#c00";
  }
});

load();
