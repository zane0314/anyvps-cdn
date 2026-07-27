// sections.js — 主区：统计卡、信息表单、订阅地址、SubStore、IP 明细表
import { $, esc, relTime, fullTime } from "./util.js";

const FORM_IDS = {
  name: "editName",
  role: "editRole",
  expires_at: "editExpires",
  renewal_amount: "editRenewal",
  currency: "editCurrency",
  renewal_period: "editRenewalPeriod",
  bandwidth: "editBandwidth",
  monthly_traffic: "editTraffic",
  status: "editStatus",
  admin_url: "editAdmin",
  health_url: "editHealth",
  sync_webhook_url: "editWebhookUrl",
  xui_sub_url: "xuiUrl",
  combo_sub_url: "comboUrl",
  cdn_sub_url: "cdnUrl",
  preferred_sources: "sources",
};

export function fillForm(c) {
  for (const [key, id] of Object.entries(FORM_IDS)) {
    const el = $("#" + id);
    if (el) el.value = c[key] || (key === "currency" ? "USD" : key === "renewal_period" ? "monthly" : "");
  }
}

export function collectForm(c) {
  const out = { ...c };
  for (const [key, id] of Object.entries(FORM_IDS)) {
    const el = $("#" + id);
    if (el) out[key] = el.value;
  }
  return out;
}

// 远端采集 JSON 填入表单（不覆盖已有非空值之外的字段，preferred_sources 有旧值时需确认）
export function applyCollectedData(data) {
  if (!data || typeof data !== "object") return false;
  const mapping = {
    name: "editName",
    role: "editRole",
    status: "editStatus",
    admin_url: "editAdmin",
    health_url: "editHealth",
    xui_sub_url: "xuiUrl",
    combo_sub_url: "comboUrl",
    cdn_sub_url: "cdnUrl",
  };
  for (const [key, id] of Object.entries(mapping)) {
    if (data[key]) $("#" + id).value = data[key];
  }
  if (data.preferred_sources) {
    const existing = $("#sources").value.trim();
    const incoming = String(data.preferred_sources).trim();
    if (existing && incoming &&
        !confirm("当前已有优选源配置，是否替换为远端采集的源？\n\n点击「确定」替换，点击「取消」保留现有配置。")) {
      return "skipped-sources";
    }
    $("#sources").value = incoming;
  }
  return true;
}

export function renderStats(checks, current) {
  const mine = checks.filter((x) => x.vps_id === current.id);
  const ok = mine.filter((x) => x.status === "可用" || x.status === "慢").length;
  const bad = mine.length - ok;
  $("#ipTotal").textContent = mine.length || "-";
  $("#ipOk").textContent = mine.length ? ok : "-";
  $("#ipBad").textContent = mine.length ? bad : "-";
  $("#lastSync").textContent = current.last_sync_at > 0 ? relTime(current.last_sync_at) : "-";
}

export function renderRoleTags(c) {
  $("#roleTags").innerHTML = (c.role || "")
    .split("·")
    .map((x) => x.trim())
    .filter(Boolean)
    .map((x) => `<span class="chip">${esc(x)}</span>`)
    .join("");
}

// ---- SubStore 转换订阅（3 行 × 4 格式）----
export function updateSubstoreUrl(c, type) {
  const format = $("#substore" + cap(type) + "Format").value;
  const url = c[`substore_${type}_${format}_url`] || "";
  const input = $("#substore" + cap(type) + "Url");
  input.value = url;
  input.placeholder = url ? "" : "请先上传原始订阅";
}

export function updateAllSubstoreUrls(c) {
  for (const type of ["xui", "combo", "cdn"]) updateSubstoreUrl(c, type);
}

function cap(s) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// ---- 源内 IP 明细检测表 ----
export function filterChecks(checks, filter) {
  if (filter === "ok") return checks.filter((x) => x.status === "可用" || x.status === "慢");
  if (filter === "fast") {
    return checks.filter((x) => (x.status === "可用" || x.status === "慢") && x.latency_ms != null && x.latency_ms < 100);
  }
  if (filter === "bad") return checks.filter((x) => x.status !== "可用" && x.status !== "慢");
  return checks;
}

function badgeClass(status) {
  if (status === "可用") return "ok";
  if (status === "慢") return "slow";
  return "bad";
}

export function renderChecksTable(checks, vpsId, filter) {
  const mine = filterChecks(checks.filter((x) => x.vps_id === vpsId), filter);
  const tbody = $("#checkRows");
  if (!mine.length) {
    tbody.innerHTML = `<tr><td class="table-empty" colspan="6">暂无检测记录，点击「解析并检测 IP」开始</td></tr>`;
    return;
  }
  tbody.innerHTML = mine.map((x) => `<tr>
    <td class="mono">${esc(x.endpoint)}</td>
    <td>${esc(x.source || "-")}</td>
    <td>${esc(x.region || "-")}</td>
    <td class="mono">${x.latency_ms ? esc(x.latency_ms) + "ms" : "--"}</td>
    <td><span class="badge ${badgeClass(x.status)}">${esc(x.status)}</span></td>
    <td class="mono">${esc(fullTime(x.checked_at))}</td>
  </tr>`).join("");
}

export function initFilterEvents(onChange) {
  $("#checkFilters").addEventListener("click", (e) => {
    const btn = e.target.closest(".filter");
    if (!btn) return;
    document.querySelectorAll("#checkFilters .filter").forEach((el) => el.classList.toggle("active", el === btn));
    onChange(btn.dataset.filter);
  });
}
