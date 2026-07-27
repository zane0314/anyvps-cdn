// sync.js — 一键同步下拉、同步链路、任务日志
import { $, esc, fullTime } from "./util.js";
import { lineCount } from "./sidebar.js";

// ---- 同步链路（竖向步骤条，由 last_sync_status 文本驱动，与旧前端一致）----
const STEP_NAMES = ["管理页已同步", "远端已执行", "订阅已刷新", "Sub-Store已验证"];

export function renderSyncSteps(status) {
  const done = [false, false, false, false];
  if (status) {
    if (status.includes("管理页已同步")) done[0] = true;
    if (status.includes("远端已执行") || status.includes("远端执行器响应")) done[1] = true;
    if (status.includes("订阅已刷新")) done[2] = true;
    if (status.includes("Sub-Store已验证")) done[3] = true;
  }
  $("#syncSteps").innerHTML = STEP_NAMES.map((name, i) =>
    `<div class="step ${done[i] ? "done" : ""}"><div><div class="t">${esc(name)}</div></div></div>`
  ).join("");
}

// ---- 任务日志 ----
export function renderTaskLog(tasks) {
  const box = $("#taskLog");
  if (!tasks || !tasks.length) {
    box.innerHTML = `<div><span class="lt">--:--</span> 等待操作：保存配置后可执行 IP 检测或同步。</div>`;
    return;
  }
  box.innerHTML = tasks.map((t) => {
    const cls = t.status === "failed" ? "fail" : (t.status === "done" ? "ok" : "");
    const mark = t.status === "failed" ? "✗" : (t.status === "done" ? "✓" : "…");
    const time = t.created_at
      ? new Date(t.created_at * 1000).toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit", hour12: false })
      : "--:--";
    return `<div><span class="lt">${time}</span> <span class="${cls}">${mark}</span> ${esc(t.message)}</div>`;
  }).join("");
}

// ---- 一键同步下拉 ----
export function renderSyncTargets(vpsList, currentId) {
  const targets = vpsList.filter((v) => v.id !== currentId);
  const box = $("#syncTargets");
  // 保留用户已勾选项（轮询重渲染时不丢状态）
  const checked = new Set(selectedSyncTargetIds());
  if (!targets.length) {
    box.innerHTML = `<div class="sync-drop-empty">没有其他 VPS 可同步</div>`;
    return;
  }
  box.innerHTML = targets.map((v) => {
    const extra = (v.status === "异常" || (v.last_sync_status || "").includes("失败")) && v.last_sync_status
      ? ` · ${v.last_sync_status}`
      : "";
    return `<label class="sync-target">
      <input type="checkbox" value="${v.id}"${checked.has(v.id) ? " checked" : ""}>
      <span><b>${esc(v.name)}</b><small>源数量 ${lineCount(v.preferred_sources)} · ${esc(v.status || "")}${esc(extra)}</small></span>
    </label>`;
  }).join("");
}

export function selectedSyncTargetIds() {
  return [...document.querySelectorAll("#syncTargets input:checked")].map((x) => Number(x.value));
}

export function toggleSyncDrop(open) {
  const drop = $("#syncDrop");
  const next = open ?? drop.hidden;
  drop.hidden = !next;
  return next;
}

export function closeSyncDrop() {
  $("#syncDrop").hidden = true;
}

// 下拉 / 全选 / 外部点击关闭，初始化一次
export function initSyncDropEvents() {
  $("#syncDropBtn").addEventListener("click", (e) => {
    e.stopPropagation();
    toggleSyncDrop();
  });
  $("#syncDrop").addEventListener("click", (e) => e.stopPropagation());
  document.addEventListener("click", closeSyncDrop);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeSyncDrop();
  });
  $("#syncSelectAll").addEventListener("click", () => {
    const boxes = [...document.querySelectorAll("#syncTargets input[type=checkbox]")];
    const all = boxes.length > 0 && boxes.every((b) => b.checked);
    boxes.forEach((b) => { b.checked = !all; });
  });
}

export { fullTime };
