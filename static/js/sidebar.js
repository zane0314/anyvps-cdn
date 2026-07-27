// sidebar.js — VPS 列表卡、状态点、到期高亮、右键菜单
import { $, esc, shortTime } from "./util.js";

export function statusDotClass(v) {
  if (v.status === "异常") return "err";
  if (v.last_sync_at && v.last_sync_at > 0) return "";
  return "warn";
}

export function syncLabel(v) {
  if (!v.last_sync_at || v.last_sync_at <= 0) return "未同步";
  const status = v.last_sync_status || "";
  const prefix = status.includes("daily_0300") ? "回传" : (status.includes("manual_verify") ? "回传" : "同步");
  return `${prefix} ${shortTime(v.last_sync_at)}`;
}

export function money(v) {
  const symbol = v.currency === "CNY" ? "¥" : "$";
  const period = v.renewal_period === "yearly" ? "年" : "月";
  return `${symbol}${v.renewal_amount || "-"}/${period}`;
}

// 到期 ≤ 5 天（含已过期）橙色高亮
export function isDueSoon(v) {
  if (!v.expires_at) return false;
  const due = Date.parse(v.expires_at);
  if (Number.isNaN(due)) return false;
  const days = (due - Date.now()) / 86400000;
  return days <= 5;
}

export function lineCount(text) {
  return (text || "").split("\n").map((x) => x.trim()).filter(Boolean).length;
}

export function renderSidebar(vpsList, currentId, searchTerm) {
  $("#vpsCount").textContent = `VPS · ${vpsList.length}`;
  const term = (searchTerm || "").trim().toLowerCase();
  const shown = term ? vpsList.filter((v) => (v.name || "").toLowerCase().includes(term)) : vpsList;
  const list = $("#vpsList");
  if (!shown.length) {
    list.innerHTML = `<div class="sync-drop-empty">${term ? "没有匹配的 VPS" : "暂无 VPS，点击下方添加"}</div>`;
    return;
  }
  list.innerHTML = shown.map((v) => {
    const due = v.expires_at
      ? `<span class="${isDueSoon(v) ? "due" : ""}">${esc(v.expires_at)}</span>`
      : "-";
    return `<button class="vps-card ${v.id === currentId ? "active" : ""}" data-id="${v.id}">
      <div class="r1"><span class="dot ${statusDotClass(v)}"></span><span class="name">${esc(v.name)}</span><span class="hb">${esc(syncLabel(v))}</span></div>
      <div class="r2">到期 ${due} · 续费 ${esc(money(v))} · ${esc(v.monthly_traffic || "-")}</div>
    </button>`;
  }).join("");
}

// 事件委托：点击选中 + 右键菜单，只需初始化一次
export function initSidebarEvents({ onSelect, onContext }) {
  const list = $("#vpsList");
  list.addEventListener("click", (e) => {
    const card = e.target.closest(".vps-card");
    if (card) onSelect(Number(card.dataset.id));
  });
  list.addEventListener("contextmenu", (e) => {
    const card = e.target.closest(".vps-card");
    if (!card) return;
    e.preventDefault();
    onContext(Number(card.dataset.id), e.clientX, e.clientY);
  });
}

export function showContextMenu(x, y) {
  const menu = $("#vpsContext");
  menu.hidden = false;
  menu.style.left = `${Math.min(x, innerWidth - 170)}px`;
  menu.style.top = `${Math.min(y, innerHeight - 100)}px`;
}

export function hideContextMenu() {
  const menu = $("#vpsContext");
  if (menu) menu.hidden = true;
}
