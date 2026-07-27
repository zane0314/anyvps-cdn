// api.js — fetch 封装：GET/POST JSON、错误处理、401 回登录页
async function handleResponse(resp) {
  if (resp.status === 401 || resp.status === 403) {
    location.href = "/login";
    throw new Error("登录已失效");
  }
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

export async function apiGet(path) {
  const resp = await fetch(path, { headers: { Accept: "application/json" } });
  return handleResponse(resp);
}

export async function apiPost(path, body) {
  const resp = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  return handleResponse(resp);
}

export async function apiText(path) {
  const resp = await fetch(path);
  if (resp.status === 401 || resp.status === 403) {
    location.href = "/login";
    throw new Error("登录已失效");
  }
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.text();
}
