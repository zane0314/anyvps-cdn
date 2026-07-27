// sync.js — 一键同步下拉、同步链路、任务日志
import { $, esc, fullTime } from "./util.js";
import { lineCount } from "./sidebar.js";

// ---- 同步链路（竖向步骤条）----
// 通过哪一步哪一步亮绿灯；任一步失败亮红灯并阻断后续；Agent 待执行亮黄灯。
const STEP_NAMES = ["管理页已同步", "远端已执行", "订阅已刷新", "Sub-Store已验证"];

export function renderSyncSteps(status) {
  const text = status || "";
  const failed = /失败|failed|异常|HTTP [45]\d\d|exit [1-9]|超时|timeout/i.test(text);
  const pending = text.includes("等待执行");
  const ok = [
    Boolean(text), // 1. 管理页已同步：有任何同步记录
    /webhook HTTP [23]\d\d|command exit 0|Agent done|已回传|CDN已更新|CDN未探测到/.test(text), // 2. 远端已执行
    /刷新 exit 0|CDN已更新|验证 HTTP [23]\d\d/.test(text), // 3. 订阅已刷新
    /验证 HTTP [23]\d\d|Sub-Store已验证/.test(text), // 4. Sub-Store已验证
  ];
  // 递进亮灯：前一步未过则后续一律不亮
  const state = [];
  let blocked = false;
  for (let i = 0; i < 4; i++) {
    if (blocked) { state.push(""); continue; }
    if (ok[i]) { state.push("done"); continue; }
    if (failed && i > 0 && ok[i - 1]) state.push("fail");
    else if (pending && i === 1) state.push("pending");
    else state.push("");
    blocked = true;
  }
  $("#syncSteps").innerHTML = STEP_NAMES.map((name, i) =>
    `<div class="step ${state[i]}"><div><div class="t">${esc(name)}</div></div></div>`
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
