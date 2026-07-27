// main.js — 入口：状态管理、渲染调度、事件绑定、轮询
import { $, $$, toast, copyText, btnLoading } from "./util.js";
import { apiGet, apiPost, apiText } from "./api.js";
import { renderSidebar, initSidebarEvents, showContextMenu, hideContextMenu } from "./sidebar.js";
import {
  fillForm, collectForm, applyCollectedData, renderStats, renderRoleTags,
  updateAllSubstoreUrls, updateSubstoreUrl, renderChecksTable, initFilterEvents,
} from "./sections.js";
import {
  renderSyncSteps, renderTaskLog, renderSyncTargets, selectedSyncTargetIds,
  closeSyncDrop, initSyncDropEvents,
} from "./sync.js";

let state = null;
let currentId = null;
let contextVpsId = null;
let checkFilter = "all";
let searchTerm = "";

function normalizeCurrent() {
  if (!state.vps.length) { currentId = null; return; }
  if (!state.vps.some((v) => v.id === currentId)) currentId = state.vps[0].id;
}

function current() {
  normalizeCurrent();
  return state.vps.find((v) => v.id === currentId) || state.vps[0];
}

// form=true 时才重填表单（轮询时不覆盖用户正在编辑的内容）
function render({ form = true } = {}) {
  if (!state || !state.vps.length) return;
  const c = current();
  $("#crumbCurrent").textContent = c.name;
  renderSidebar(state.vps, currentId, searchTerm);
  renderStats(state.checks, c);
  renderRoleTags(c);
  if (form) {
    fillForm(c);
    updateAllSubstoreUrls(c);
  }
  renderChecksTable(state.checks, c.id, checkFilter);
  renderSyncSteps(c.last_sync_status);
  renderTaskLog(state.tasks);
  renderSyncTargets(state.vps, c.id);
}

async function load({ form = true } = {}) {
  state = await apiGet("/api/state");
  normalizeCurrent();
  $("#userName").textContent = state.username;
  render({ form });
}

// 保存当前 VPS（保持选中），返回保存后的当前 VPS
async function saveCurrent() {
  const c = collectForm(current());
  currentId = c.id;
  await apiPost("/api/vps", c);
  await load();
  return current();
}

// ---- 通用复制按钮（data-copy 指向 input id）----
$$("[data-copy]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const input = $("#" + btn.dataset.copy);
    const value = input ? input.value : "";
    if (!value) { toast("无内容可复制", "err"); return; }
    const ok = await copyText(value);
    toast(ok ? "已复制到剪贴板" : "复制失败，请手动选择复制", ok ? "ok" : "err");
  });
});

// ---- 顶栏 ----
$("#logoutBtn").addEventListener("click", async () => {
  const reset = btnLoading($("#logoutBtn"), "退出中…");
  try {
    await fetch("/api/logout", { method: "POST" });
    location.href = "/login";
  } catch (e) {
    reset();
    toast("退出失败: " + e.message, "err");
  }
});
$("#menuBtn").addEventListener("click", () => $("#sidebar").classList.toggle("open"));

// ---- 侧栏 ----
initSidebarEvents({
  onSelect(id) {
    hideContextMenu();
    currentId = id;
    $("#sidebar").classList.remove("open");
    render();
  },
  onContext(id, x, y) {
    contextVpsId = id;
    currentId = id;
    render();
    showContextMenu(x, y);
  },
});
$("#vpsSearch").addEventListener("input", (e) => {
  searchTerm = e.target.value;
  renderSidebar(state ? state.vps : [], currentId, searchTerm);
});
$("#newVpsBtn").addEventListener("click", async () => {
  const name = prompt("新 VPS 名称", "新 VPS");
  if (name === null) return;
  const reset = btnLoading($("#newVpsBtn"), "创建中…");
  try {
    const res = await apiPost("/api/vps/new", { name });
    if (res.ok) {
      currentId = res.id;
      await load();
      toast(`已创建 VPS：${res.name}`, "ok");
      $("#editName").focus();
    } else {
      toast("创建失败: " + (res.error || "未知错误"), "err");
    }
  } catch (e) {
    toast("创建失败: " + e.message, "err");
  } finally {
    reset();
  }
});

// ---- 右键菜单 ----
$("#ctxEdit").addEventListener("click", () => {
  hideContextMenu();
  if (contextVpsId) {
    currentId = contextVpsId;
    render();
    $("#editName").focus();
  }
});
$("#ctxDelete").addEventListener("click", async () => {
  const v = state.vps.find((x) => x.id === contextVpsId);
  hideContextMenu();
  if (!v) return;
  if (!confirm(`删除 ${v.name}？这会删除这台 VPS 的检测记录。`)) return;
  try {
    const res = await apiPost("/api/vps/delete", { id: v.id });
    if (!res.ok) {
      toast(res.error === "last_vps" ? "至少保留一台 VPS" : "删除失败: " + (res.error || ""), "err");
      return;
    }
    currentId = null;
    contextVpsId = null;
    await load();
    toast(`已删除 VPS：${v.name}`, "ok");
  } catch (e) {
    toast("删除失败: " + e.message, "err");
  }
});
document.addEventListener("click", (e) => {
  if (!e.target.closest("#vpsContext")) hideContextMenu();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") hideContextMenu();
});

// ---- 保存 ----
async function handleSave(btn) {
  const reset = btnLoading(btn, "保存中…");
  try {
    const c = await saveCurrent();
    toast(`配置已保存：${c.name}`, "ok");
  } catch (e) {
    toast("保存失败: " + e.message, "err");
  } finally {
    reset();
  }
}
$("#saveBtn").addEventListener("click", () => handleSave($("#saveBtn")));
$("#saveInfoBtn").addEventListener("click", () => handleSave($("#saveInfoBtn")));

// ---- 优选 IP 源工具栏 ----
$("#dedupeBtn").addEventListener("click", () => {
  const before = $("#sources").value.split("\n").filter(Boolean).length;
  $("#sources").value = [...new Set($("#sources").value.split("\n").map((x) => x.trim()).filter(Boolean))].join("\n");
  const after = $("#sources").value.split("\n").filter(Boolean).length;
  toast(before > after ? `去重完成，删除 ${before - after} 个重复项` : "无重复项", "ok");
});

$("#validateBtn").addEventListener("click", async () => {
  const reset = btnLoading($("#validateBtn"), "检测中…");
  try {
    const c = await saveCurrent();
    const res = await apiPost("/api/check-ips", { vps_id: c.id });
    await load();
    if (res.ok) {
      toast(`IP 检测完成：共 ${res.total} 个，可用 ${res.usable} 个`, "ok");
    } else {
      toast("检测失败: " + (res.error || "未知错误"), "err");
    }
  } catch (e) {
    toast("检测失败: " + e.message, "err");
  } finally {
    reset();
  }
});

async function handleSubstoreVerify(btn) {
  const reset = btnLoading(btn, "验证中…");
  try {
    const c = await saveCurrent();
    const res = await apiPost("/api/substore/verify", { vps_id: c.id });
    await load();
    if (res.ok) {
      toast(`Sub-Store 验证成功：HTTP ${res.status}，${res.bytes} bytes，${res.lines} 行`, "ok");
    } else {
      toast("Sub-Store 验证失败: " + (res.error || `HTTP ${res.status || "?"}`), "err");
    }
  } catch (e) {
    toast("验证失败: " + e.message, "err");
  } finally {
    reset();
  }
}
$("#substoreBtn").addEventListener("click", () => handleSubstoreVerify($("#substoreBtn")));
$("#substoreVerifyBtn").addEventListener("click", () => handleSubstoreVerify($("#substoreVerifyBtn")));

// ---- 一键同步 ----
initSyncDropEvents();
$("#syncConfirmBtn").addEventListener("click", async () => {
  let ids = selectedSyncTargetIds();
  const reset = btnLoading($("#syncConfirmBtn"), "同步中…");
  try {
    const c = await saveCurrent();
    if (!ids.length) ids = state.vps.filter((v) => v.id !== c.id).map((v) => v.id);
    if (!ids.length) {
      toast("请至少勾选一个目标 VPS", "err");
      return;
    }
    const res = await apiPost("/api/sync-sources", { source_vps_id: c.id, target_vps_ids: ids });
    closeSyncDrop();
    await load();
    if (res.ok) {
      toast(`同步完成：已同步到 ${ids.length} 台 VPS`, "ok");
    } else {
      const detail = (res.results || []).filter((r) => !r.ok).map((r) => `${r.name}: ${r.message}`).join("\n");
      toast("同步失败" + (detail ? "：\n" + detail : (res.error ? ": " + res.error : "")), "err", 6000);
    }
  } catch (e) {
    toast("同步失败: " + e.message, "err");
  } finally {
    reset();
  }
});

// ---- SubStore 格式切换 + 上传 ----
$("#substoreXuiFormat").addEventListener("change", () => updateSubstoreUrl(current(), "xui"));
$("#substoreComboFormat").addEventListener("change", () => updateSubstoreUrl(current(), "combo"));
$("#substoreCdnFormat").addEventListener("change", () => updateSubstoreUrl(current(), "cdn"));

async function uploadToSubstore(type, btn) {
  const c = current();
  const sourceUrl = $("#" + type + "Url").value;
  if (!sourceUrl) { toast("请先填写订阅地址", "err"); return; }
  const reset = btnLoading(btn, "上传中…");
  try {
    const res = await apiPost("/api/substore/upload", {
      vps_id: c.id,
      vps_name: c.name,
      source_type: type,
      source_url: sourceUrl,
    });
    if (res.ok) {
      toast(`上传成功：已创建订阅项 ${res.item_name}，生成 4 种格式链接`, "ok");
      await load();
    } else {
      toast("上传失败: " + (res.error || "未知错误"), "err");
    }
  } catch (e) {
    toast("上传失败: " + e.message, "err");
  } finally {
    reset();
  }
}
$("#uploadXui").addEventListener("click", (e) => uploadToSubstore("xui", e.currentTarget));
$("#uploadCombo").addEventListener("click", (e) => uploadToSubstore("combo", e.currentTarget));
$("#uploadCdn").addEventListener("click", (e) => uploadToSubstore("cdn", e.currentTarget));

// ---- IP 明细筛选 ----
initFilterEvents((filter) => {
  checkFilter = filter;
  renderChecksTable(state.checks, current().id, checkFilter);
});

// ---- 远端采集 / 安装弹窗 ----
async function setRemoteTool(tool) {
  const isCollector = tool === "collector";
  $("#remoteCollectorPanel").hidden = !isCollector;
  $("#remoteInstallerPanel").hidden = isCollector;
  $("#remoteToolTitle").textContent = isCollector ? "远端采集" : "3x-ui-zane 一键安装";
  $("#remoteToolNote").textContent = isCollector
    ? "复制下面代码到新 VPS 执行，输出 JSON 后可粘贴到下方导入。"
    : "复制命令到其他 VPS 直接执行，无需记忆安装地址。";
  $$("[data-remote-tool]").forEach((btn) => btn.classList.toggle("active", btn.dataset.remoteTool === tool));
  if (isCollector && !$("#remoteCode").value) {
    try {
      $("#remoteCode").value = await apiText("/api/remote-code");
    } catch (e) {
      toast("获取采集代码失败: " + e.message, "err");
    }
  }
}

function openRemoteModal() {
  $("#remoteCodeModal").hidden = false;
  setRemoteTool("collector");
}
$("#remoteCodeBtn").addEventListener("click", openRemoteModal);
$("#remoteCodeBtn2").addEventListener("click", openRemoteModal);
$$("[data-remote-tool]").forEach((btn) => btn.addEventListener("click", () => setRemoteTool(btn.dataset.remoteTool)));
$("#closeRemoteCode").addEventListener("click", () => { $("#remoteCodeModal").hidden = true; });
$("#remoteCodeModal").addEventListener("click", (e) => {
  if (e.target.id === "remoteCodeModal") $("#remoteCodeModal").hidden = true;
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") $("#remoteCodeModal").hidden = true;
});

$("#copyRemoteCode").addEventListener("click", async () => {
  const value = $("#remoteCode").value;
  if (!value) { toast("代码尚未加载完成", "err"); return; }
  const ok = await copyText(value);
  toast(ok ? "采集代码已复制" : "复制失败，请手动选择复制", ok ? "ok" : "err");
});
$("#copyInstallerCode").addEventListener("click", async () => {
  const ok = await copyText($("#installerCode").value);
  toast(ok ? "安装命令已复制" : "复制失败，请手动选择复制", ok ? "ok" : "err");
});

function parseRemoteResult() {
  const raw = $("#remoteResult").value.trim();
  if (!raw) { toast("请先粘贴采集输出的 JSON", "err"); return null; }
  try {
    return JSON.parse(raw);
  } catch (e) {
    toast("JSON 解析失败: " + e.message + "\n请检查是否完整复制了脚本输出。", "err", 5000);
    return null;
  }
}

$("#applyRemoteResult").addEventListener("click", () => {
  const data = parseRemoteResult();
  if (!data) return;
  const result = applyCollectedData(data);
  if (result) {
    $("#remoteCodeModal").hidden = true;
    toast("远端数据已填入表单，确认无误后点击「保存信息」", "ok", 4500);
  }
});

$("#importRemoteResult").addEventListener("click", async () => {
  const data = parseRemoteResult();
  if (!data) return;
  const rows = Array.isArray(data) ? data : (Array.isArray(data.vps) ? data.vps : [data]);
  const reset = btnLoading($("#importRemoteResult"), "导入中…");
  try {
    const res = await apiPost("/api/import-inventory", { vps: rows });
    if (res.ok) {
      $("#remoteCodeModal").hidden = true;
      await load();
      toast(`清单已导入：${res.count} 台 VPS`, "ok");
    } else {
      toast("导入失败: " + (res.error || "未知错误"), "err");
    }
  } catch (e) {
    toast("导入失败: " + e.message, "err");
  } finally {
    reset();
  }
});

// ---- 启动 + 任务日志轮询（不重填表单，避免覆盖编辑内容）----
load().catch((e) => toast("加载失败: " + e.message, "err"));
setInterval(() => {
  load({ form: false }).catch(() => {});
}, 8000);
