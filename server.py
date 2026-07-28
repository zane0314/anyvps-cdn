import json
import secrets
import sqlite3
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from config import HOST, PASSWORD, PORT, PUBLIC_URL
from db import get_conn, init_db
from embedded import INSTALL_SCRIPT, REMOTE_COLLECTOR_SCRIPT, ROBOTS_TXT, WEBHOOK_RECEIVER_SCRIPT
from security import (
    LOGIN_FAILURES,
    hash_agent_token,
    json_dumps,
    login_limited,
    make_session,
    now_ts,
    read_session,
    record_login_failure,
    verify_agent_token,
    verify_password,
)
from sources import (
    check_vps_sources,
    clean_text,
    collect_ip_check_rows,
    upsert_inventory_rows,
    write_ip_check_rows,
)
from state import collect_state
from substore import add_no_cache_param, substore_verify_url, upload_to_substore, verify_subscription
from sync import sync_sources

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_MIME = {
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".woff2": "font/woff2",
}

class Handler(BaseHTTPRequestHandler):
    server_version = "AnyVPS/0.1"

    def log_message(self, fmt, *args):
        print("%s - - [%s] %s" % (self.client_address[0], self.log_date_time_string(), fmt % args))

    def end_headers(self):
        self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        )
        super().end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/healthz":
            return self.send_text("ok\n", "text/plain")
        if path == "/robots.txt":
            return self.send_text(ROBOTS_TXT, "text/plain")
        if path == "/install.sh":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            payload = INSTALL_SCRIPT.encode()
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if path == "/vps-webhook-receiver.py":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            payload = WEBHOOK_RECEIVER_SCRIPT.encode()
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if path == "/install-webhook.sh":
            install_webhook_script = r"""#!/bin/bash
# AnyVPS Webhook 接收器部署脚本
set -e
echo "==> 部署 AnyVPS Webhook 接收器..."
curl -fsSL -o /usr/local/bin/anyvps-webhook-receiver.py __PUBLIC_URL__/vps-webhook-receiver.py
chmod +x /usr/local/bin/anyvps-webhook-receiver.py
cat > /etc/systemd/system/anyvps-webhook.service <<'EOF'
[Unit]
Description=AnyVPS Webhook Receiver
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/anyvps-webhook-receiver.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable anyvps-webhook
systemctl restart anyvps-webhook
if systemctl is-active --quiet anyvps-webhook; then
    echo "✓ Webhook 接收器已启动"
    echo "监听端口: 18964"
    echo "查看日志: journalctl -u anyvps-webhook -f"
else
    echo "✗ 服务启动失败"
    exit 1
fi
""".replace("__PUBLIC_URL__", PUBLIC_URL)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            payload = install_webhook_script.encode()
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if path == "/login":
            return self.send_static("login.html")
        if path.startswith("/static/"):
            return self.send_static(unquote(path[len("/static/"):]))
        username = self.current_user()
        if not username:
            return self.redirect("/login")
        if path == "/":
            return self.send_static("index.html")
        if path == "/api/state":
            return self.send_json(collect_state())
        if path == "/api/remote-code":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            payload = REMOTE_COLLECTOR_SCRIPT.encode()
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        return self.send_error(HTTPStatus.NOT_FOUND)

    def do_HEAD(self):
        path = urlparse(self.path).path
        if path == "/healthz":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "3")
            self.end_headers()
            return
        return self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self):
        path = urlparse(self.path).path
        # Agent API - 不需要登录
        if path == "/api/register-vps":
            return self.handle_register_vps()
        if path == "/api/set-webhook":
            return self.handle_set_webhook()
        if path == "/api/agent/heartbeat":
            return self.handle_agent_heartbeat()
        if path == "/api/agent/snapshot":
            return self.handle_agent_snapshot()
        if path == "/api/agent/poll":
            return self.handle_agent_poll()
        if path == "/api/agent/report":
            return self.handle_agent_report()
        # 用户 API - 需要登录
        if path == "/api/login":
            data = self.read_form()
            return self.handle_login(data)
        username = self.current_user()
        if not username:
            return self.send_error(HTTPStatus.UNAUTHORIZED)
        if path == "/api/logout":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("Set-Cookie", "anyvps_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
            self.end_headers()
            return
        if path == "/api/vps":
            return self.handle_save_vps()
        if path == "/api/vps/new":
            return self.handle_new_vps()
        if path == "/api/vps/delete":
            return self.handle_delete_vps()
        if path == "/api/import-inventory":
            return self.handle_import_inventory()
        if path == "/api/check-ips":
            return self.handle_check_ips()
        if path == "/api/sync-sources":
            return self.handle_sync_sources()
        if path == "/api/substore/verify":
            return self.handle_substore_verify()
        if path == "/api/substore/upload":
            return self.handle_substore_upload()
        if path == "/api/task":
            return self.handle_task()
        return self.send_error(HTTPStatus.NOT_FOUND)

    def handle_login(self, data: dict):
        client_ip = self.client_ip()
        if login_limited(client_ip):
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/login?locked=1")
            self.end_headers()
            return
        user = data.get("username", [""])[0].strip()
        password = data.get("password", [""])[0]
        with get_conn() as conn:
            stored_user = conn.execute("select value from settings where key='username'").fetchone()["value"]
            row = conn.execute("select value from settings where key='password_hash'").fetchone()
        if row and user == stored_user and verify_password(password, row["value"]):
            LOGIN_FAILURES.pop(client_ip, None)
            token = make_session(user)
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", f"anyvps_session={token}; Path=/; HttpOnly; Secure; SameSite=Lax")
            self.end_headers()
            return
        record_login_failure(client_ip)
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/login?error=1")
        self.end_headers()

    def client_ip(self) -> str:
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",", 1)[0].strip()
        return self.client_address[0]



    def handle_save_vps(self):
        data = self.read_json()
        allowed = [
            "name",
            "role",
            "expires_at",
            "renewal_amount",
            "currency",
            "renewal_period",
            "bandwidth",
            "monthly_traffic",
            "status",
            "xui_sub_url",
            "combo_sub_url",
            "cdn_sub_url",
            "preferred_sources",
            "admin_url",
            "health_url",
            "source_file",
            "sync_webhook_url",
            "sync_command",
            "substore_download_url",
            "substore_api_url",
            "substore_item",
            "substore_target",
        ]
        vps_id = int(data.get("id", 0))
        values = {key: clean_text(data.get(key), 4000) for key in allowed}
        if values["currency"] not in {"USD", "CNY"}:
            values["currency"] = "USD"
        if values["substore_target"] not in {"Mihomo", "ClashMeta", "sing-box", "Surge"}:
            values["substore_target"] = "Mihomo"
        sets = ",".join(f"{key}=?" for key in values)
        with get_conn() as conn:
            conn.execute(
                f"update vps set {sets}, updated_at=? where id=?",
                [*values.values(), now_ts(), vps_id],
            )

        # 如果有 sync_webhook_url，发送 Webhook 通知 VPS 更新优选 IP 源
        webhook_url = values.get("sync_webhook_url", "").strip()
        if webhook_url and values.get("preferred_sources"):
            try:
                import urllib.request
                webhook_data = {
                    "vps_id": vps_id,
                    "preferred_sources": values["preferred_sources"]
                }
                req = urllib.request.Request(
                    webhook_url,
                    data=json.dumps(webhook_data).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    result = json.loads(resp.read().decode())
                    print(f"Webhook 发送成功: {webhook_url} -> {result}")
            except Exception as e:
                print(f"Webhook 发送失败: {webhook_url} -> {e}")

        return self.send_json({"ok": True})

    def handle_new_vps(self):
        data = self.read_json()
        name = clean_text(data.get("name") or "新 VPS", 120)
        with get_conn() as conn:
            base = name
            suffix = 2
            while conn.execute("select 1 from vps where name=?", (name,)).fetchone():
                name = f"{base} {suffix}"
                suffix += 1
            cur = conn.execute(
                """
                insert into vps(
                  name,role,expires_at,renewal_amount,currency,renewal_period,bandwidth,monthly_traffic,status,
                  xui_sub_url,combo_sub_url,cdn_sub_url,preferred_sources,admin_url,health_url,
                  source_file,sync_webhook_url,sync_command,substore_download_url,substore_api_url,
                  substore_item,substore_target,last_sync_at,last_sync_status,updated_at
                ) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    name,
                    "",
                    "",
                    "",
                    "USD",
                    "monthly",
                    "",
                    "",
                    "待刷新",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "Mihomo",
                    0,
                    "",
                    now_ts(),
                ),
            )
            vps_id = cur.lastrowid
            conn.execute(
                "insert into tasks(vps_id,kind,status,message,created_at) values(?,?,?,?,?)",
                (vps_id, "new_vps", "done", f"已新增 VPS：{name}", now_ts()),
            )
        return self.send_json({"ok": True, "id": vps_id, "name": name})

    def handle_delete_vps(self):
        data = self.read_json()
        vps_id = int(data.get("id", 0))
        with get_conn() as conn:
            total = conn.execute("select count(*) from vps").fetchone()[0]
            row = conn.execute("select name from vps where id=?", (vps_id,)).fetchone()
            if row is None:
                return self.send_json({"ok": False, "error": "vps_not_found"})
            if total <= 1:
                return self.send_json({"ok": False, "error": "last_vps"})
            name = row["name"]
            conn.execute("delete from ip_checks where vps_id=?", (vps_id,))
            conn.execute("update tasks set vps_id=null where vps_id=?", (vps_id,))
            conn.execute("delete from vps where id=?", (vps_id,))
            conn.execute(
                "insert into tasks(vps_id,kind,status,message,created_at) values(?,?,?,?,?)",
                (None, "delete_vps", "done", f"已删除 VPS：{name}", now_ts()),
            )
        return self.send_json({"ok": True})

    def handle_register_vps(self):
        """处理 VPS 注册请求（由一键部署脚本调用）"""
        data = self.read_json()
        name = clean_text(data.get("name", "新 VPS"), 120)
        host_hint = clean_text(data.get("host_hint", ""), 120)
        agent_token = secrets.token_urlsafe(32)
        agent_token_hash = hash_agent_token(agent_token)
        agent_source_file = clean_text(data.get("agent_source_file", ""), 500)
        agent_refresh_command = clean_text(data.get("agent_refresh_command", ""), 1000)
        agent_verify_url = clean_text(data.get("agent_verify_url", ""), 1000)
        agent_version = clean_text(data.get("agent_version", "2026-07-07-sync-agent"), 120)

        admin_url_val = clean_text(data.get("admin_url", ""), 500)
        with get_conn() as conn:
            # 匹配优先级：公网 IP > 优选管理页地址
            # 不用 name 匹配：采集回传的是主机名，与手填中文名不一致，用它匹配会漏判并产生重复记录
            # admin_url 作为兜底键，让首次重跑也能命中已有的手动命名记录（多数记录已存有正确 admin_url），
            # 命中后会把公网 IP 写入 host_hint，之后即可稳定按 IP 匹配
            existing = None
            if host_hint:
                existing = conn.execute(
                    "select id from vps where host_hint=? and host_hint!=''",
                    (host_hint,)
                ).fetchone()
            if not existing and admin_url_val:
                existing = conn.execute(
                    "select id from vps where admin_url=? and admin_url!=''",
                    (admin_url_val,)
                ).fetchone()

            if existing:
                # 已存在，更新信息
                vps_id = existing["id"]
                conn.execute("""
                    update vps set
                        role=?, admin_url=?, health_url=?,
                        host_hint=case when ?!='' then ? else host_hint end,
                        xui_sub_url=?, combo_sub_url=?, cdn_sub_url=?,
                        preferred_sources=?,
                        agent_token_hash=?,
                        agent_source_file=?,
                        agent_refresh_command=?,
                        agent_verify_url=?,
                        agent_version=?,
                        updated_at=?
                    where id=?
                """, (
                    clean_text(data.get("role", ""), 500),
                    clean_text(data.get("admin_url", ""), 500),
                    clean_text(data.get("health_url", ""), 500),
                    host_hint, host_hint,
                    clean_text(data.get("xui_sub_url", ""), 500),
                    clean_text(data.get("combo_sub_url", ""), 500),
                    clean_text(data.get("cdn_sub_url", ""), 500),
                    clean_text(data.get("preferred_sources", ""), 50000),
                    agent_token_hash,
                    agent_source_file,
                    agent_refresh_command,
                    agent_verify_url,
                    agent_version,
                    now_ts(),
                    vps_id
                ))
                conn.execute(
                    "insert into tasks(vps_id,kind,status,message,created_at) values(?,?,?,?,?)",
                    (vps_id, "register", "done", f"VPS 重新注册：{name}", now_ts())
                )
            else:
                # 新 VPS，插入
                cur = conn.execute("""
                    insert into vps(
                        name, role, status, host_hint, admin_url, health_url,
                        xui_sub_url, combo_sub_url, cdn_sub_url,
                        preferred_sources, agent_token_hash, agent_source_file,
                        agent_refresh_command, agent_verify_url, agent_version,
                        updated_at
                    ) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    name,
                    clean_text(data.get("role", ""), 500),
                    "待刷新",
                    host_hint,
                    clean_text(data.get("admin_url", ""), 500),
                    clean_text(data.get("health_url", ""), 500),
                    clean_text(data.get("xui_sub_url", ""), 500),
                    clean_text(data.get("combo_sub_url", ""), 500),
                    clean_text(data.get("cdn_sub_url", ""), 500),
                    clean_text(data.get("preferred_sources", ""), 50000),
                    agent_token_hash,
                    agent_source_file,
                    agent_refresh_command,
                    agent_verify_url,
                    agent_version,
                    now_ts()
                ))
                vps_id = cur.lastrowid
                conn.execute(
                    "insert into tasks(vps_id,kind,status,message,created_at) values(?,?,?,?,?)",
                    (vps_id, "register", "done", f"新 VPS 注册：{name}", now_ts())
                )

        return self.send_json({"ok": True, "vps_id": vps_id, "name": name, "agent_token": agent_token})

    def handle_set_webhook(self):
        """设置 VPS 的 Webhook URL（由一键部署脚本调用）"""
        data = self.read_json()
        vps_id = int(data.get("vps_id", 0))
        webhook_url = clean_text(data.get("sync_webhook_url", ""), 500)
        if not vps_id or not webhook_url:
            return self.send_json({"ok": False, "error": "参数不完整"})
        with get_conn() as conn:
            conn.execute(
                "update vps set sync_webhook_url=?, updated_at=? where id=?",
                (webhook_url, now_ts(), vps_id),
            )
        return self.send_json({"ok": True, "vps_id": vps_id, "sync_webhook_url": webhook_url})

    def handle_agent_heartbeat(self):
        """处理 Agent 心跳请求"""
        data = self.read_json()
        vps_id = int(data.get("vps_id", 0))

        if not vps_id:
            return self.send_json({"ok": False, "error": "vps_id required"})

        with get_conn() as conn:
            row = conn.execute("select name from vps where id=?", (vps_id,)).fetchone()
            if not row:
                return self.send_json({"ok": False, "error": "vps_not_found"})

            conn.execute(
                "insert into tasks(vps_id,kind,status,message,created_at) values(?,?,?,?,?)",
                (vps_id, "heartbeat", "done", f"Agent 心跳：{row['name']}", now_ts())
            )

        return self.send_json({"ok": True})

    def authorize_agent(self, data: dict) -> sqlite3.Row | None:
        vps_id = int(data.get("vps_id", 0))
        token = clean_text(data.get("agent_token", ""), 500)
        if not vps_id:
            return None
        with get_conn() as conn:
            row = conn.execute("select * from vps where id=?", (vps_id,)).fetchone()
        if row is None:
            return None
        token_hash = row["agent_token_hash"] if "agent_token_hash" in row.keys() else ""
        if token_hash and verify_agent_token(token, token_hash):
            return row
        return None

    def handle_agent_snapshot(self):
        """Agent 每日回传本机实际探测到的订阅、优选源和执行器配置。"""
        data = self.read_json()
        row = self.authorize_agent(data)
        if row is None:
            return self.send_json({"ok": False, "error": "unauthorized"})

        fields = {
            "role": clean_text(data.get("role", ""), 500),
            "admin_url": clean_text(data.get("admin_url", ""), 500),
            "health_url": clean_text(data.get("health_url", ""), 500),
            "host_hint": clean_text(data.get("host_hint", ""), 120),
            "xui_sub_url": clean_text(data.get("xui_sub_url", ""), 500),
            "combo_sub_url": clean_text(data.get("combo_sub_url", ""), 500),
            "cdn_sub_url": clean_text(data.get("cdn_sub_url", ""), 500),
            "preferred_sources": clean_text(data.get("preferred_sources", ""), 50000),
            "agent_source_file": clean_text(data.get("agent_source_file", ""), 500),
            "agent_refresh_command": clean_text(data.get("agent_refresh_command", ""), 1000),
            "agent_verify_url": clean_text(data.get("agent_verify_url", ""), 1000),
            "agent_version": clean_text(data.get("agent_version", "2026-07-13-daily-snapshot"), 120),
        }
        sets = []
        values = []
        for key, value in fields.items():
            if value:
                sets.append(f"{key}=?")
                values.append(value)
        reason = clean_text(data.get("reason", "daily_0300"), 80)
        source_lines = len([line for line in fields["preferred_sources"].splitlines() if line.strip()])
        check_rows = []
        check_errors = []
        if fields["preferred_sources"]:
            check_rows, check_errors = collect_ip_check_rows(fields["preferred_sources"])
        usable_count = sum(1 for item in check_rows if item["status"] in {"可用", "慢"})
        cdn_status = "CDN已更新" if fields["cdn_sub_url"] else "CDN未探测到"
        source_status = (
            f"优选源{source_lines}行，解析{len(check_rows)}个，可用{usable_count}个"
            if fields["preferred_sources"] else "优选源未探测到"
        )
        sync_message = f"{reason}：{cdn_status}，{source_status}"
        sets.extend(["status=?", "last_sync_at=?", "last_sync_status=?", "updated_at=?"])
        ts = now_ts()
        values.extend(["已回传", ts, sync_message, ts, row["id"]])
        with get_conn() as conn:
            conn.execute(f"update vps set {','.join(sets)} where id=?", values)
            if fields["preferred_sources"]:
                write_ip_check_rows(conn, row["id"], check_rows, check_errors, "agent_snapshot_check", "快照后 IP 检测")
            conn.execute(
                "insert into tasks(vps_id,kind,status,message,created_at) values(?,?,?,?,?)",
                (row["id"], "agent_snapshot", "done", sync_message, ts),
            )
        return self.send_json({"ok": True, "vps_id": row["id"], "updated": len(fields)})

    def handle_agent_poll(self):
        """Agent 拉取待执行的优选 IP 同步任务"""
        data = self.read_json()
        row = self.authorize_agent(data)
        if row is None:
            return self.send_json({"ok": False, "error": "unauthorized"})
        with get_conn() as conn:
            current = conn.execute("select * from vps where id=?", (row["id"],)).fetchone()
        if current["pending_sync_status"] != "pending" or not current["pending_sync_sources"].strip():
            return self.send_json({"ok": True, "task": None})
        return self.send_json(
            {
                "ok": True,
                "task": {
                    "sync_id": current["pending_sync_id"],
                    "source_name": current["pending_sync_source_name"],
                    "preferred_sources": current["pending_sync_sources"],
                    "sources": [line for line in current["pending_sync_sources"].splitlines() if line.strip()],
                    "source_file": current["agent_source_file"],
                    "refresh_command": current["agent_refresh_command"],
                    "verify_url": current["agent_verify_url"] or current["cdn_sub_url"] or current["combo_sub_url"],
                },
            }
        )

    def handle_agent_report(self):
        """Agent 回报远端执行结果"""
        data = self.read_json()
        row = self.authorize_agent(data)
        if row is None:
            return self.send_json({"ok": False, "error": "unauthorized"})
        sync_id = clean_text(data.get("sync_id", ""), 200)
        ok = bool(data.get("ok"))
        message = clean_text(data.get("message", ""), 2000) or ("agent done" if ok else "agent failed")
        source_file = clean_text(data.get("source_file", ""), 500)
        line_count = int(data.get("line_count", 0) or 0)
        with get_conn() as conn:
            current = conn.execute("select * from vps where id=?", (row["id"],)).fetchone()
            if sync_id and current["pending_sync_id"] and sync_id != current["pending_sync_id"]:
                return self.send_json({"ok": False, "error": "sync_id_mismatch"})
            status = "已同步" if ok else "异常"
            pending_status = "done" if ok else "failed"
            full_message = f"Agent {pending_status}：{message}"
            if line_count:
                full_message += f"；源 {line_count} 行"
            if source_file:
                full_message += f"；文件 {source_file}"
            conn.execute(
                """
                update vps set
                  status=?,
                  last_sync_status=?,
                  pending_sync_status=?,
                  pending_sync_message=?,
                  pending_sync_finished_at=?,
                  updated_at=?
                where id=?
                """,
                (status, full_message, pending_status, full_message, now_ts(), now_ts(), row["id"]),
            )
            conn.execute(
                "insert into tasks(vps_id,kind,status,message,created_at) values(?,?,?,?,?)",
                (row["id"], "agent_sync_report", "done" if ok else "failed", full_message, now_ts()),
            )
        return self.send_json({"ok": True})

    def handle_import_inventory(self):
        data = self.read_json()
        rows = data.get("vps", [])
        if not isinstance(rows, list):
            return self.send_json({"ok": False, "error": "invalid_payload"})
        count = upsert_inventory_rows(rows)
        with get_conn() as conn:
            conn.execute(
                "insert into tasks(vps_id,kind,status,message,created_at) values(?,?,?,?,?)",
                (None, "import_inventory", "done", f"本地 VPS 清单已导入 SQLite：{count} 台", now_ts()),
            )
        return self.send_json({"ok": True, "count": count})

    def handle_check_ips(self):
        data = self.read_json()
        result = check_vps_sources(int(data.get("vps_id", 0)))
        return self.send_json(result)

    def handle_sync_sources(self):
        data = self.read_json()
        source_id = int(data.get("source_vps_id", 0))
        target_ids = [int(v) for v in data.get("target_vps_ids", []) if str(v).isdigit()]
        result = sync_sources(source_id, target_ids)
        return self.send_json(result)

    def handle_substore_verify(self):
        data = self.read_json()
        vps_id = int(data.get("vps_id", 0))
        with get_conn() as conn:
            row = conn.execute("select * from vps where id=?", (vps_id,)).fetchone()
            if row is None:
                return self.send_json({"ok": False, "error": "vps_not_found"})
            url = substore_verify_url(row, data.get("url", ""))
        if not url:
            return self.send_json({"ok": False, "error": "download_url_empty"})
        try:
            info = verify_subscription(add_no_cache_param(url))
            status = "done" if info["valid"] else "failed"
            message = f"Sub-Store 导出验证：HTTP {info['status']}，{info['bytes']} bytes，{info['lines']} 行"
            with get_conn() as conn:
                conn.execute(
                    "insert into tasks(vps_id,kind,status,message,created_at) values(?,?,?,?,?)",
                    (vps_id, "substore_verify", status, message, now_ts()),
                )
            return self.send_json({"ok": info["valid"], **info})
        except Exception as exc:
            with get_conn() as conn:
                conn.execute(
                    "insert into tasks(vps_id,kind,status,message,created_at) values(?,?,?,?,?)",
                    (vps_id, "substore_verify", "failed", f"Sub-Store 验证失败：{type(exc).__name__}", now_ts()),
                )
            return self.send_json({"ok": False, "error": type(exc).__name__})

    def handle_task(self):
        data = self.read_json()
        kind = str(data.get("kind", "manual"))
        vps_id = data.get("vps_id")
        message = str(data.get("message", "任务已进入队列"))
        with get_conn() as conn:
            conn.execute(
                "insert into tasks(vps_id,kind,status,message,created_at) values(?,?,?,?,?)",
                (vps_id, kind, "queued", message, now_ts()),
            )
        return self.send_json({"ok": True})

    def handle_substore_upload(self):
        data = self.read_json()
        vps_id = int(data.get("vps_id", 0))
        vps_name = str(data.get("vps_name", ""))
        source_type = str(data.get("source_type", ""))
        source_url = str(data.get("source_url", ""))

        if not all([vps_id, vps_name, source_type, source_url]):
            return self.send_json({"ok": False, "error": "参数不完整"})

        result = upload_to_substore(vps_id, vps_name, source_type, source_url)
        return self.send_json(result)

    def current_user(self) -> str | None:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get("anyvps_session")
        return read_session(morsel.value if morsel else None)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length).decode() or "{}")

    def read_form(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode()
        return parse_qs(body)

    def send_json(self, value: dict):
        payload = json_dumps(value).encode()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_static(self, rel_path: str):
        target = (STATIC_DIR / rel_path).resolve()
        if not target.is_relative_to(STATIC_DIR) or not target.is_file():
            return self.send_error(HTTPStatus.NOT_FOUND)
        content_type = STATIC_MIME.get(target.suffix.lower(), "application/octet-stream")
        payload = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(payload)

    def send_text(self, text: str, content_type: str):
        payload = text.encode()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def redirect(self, location: str):
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.end_headers()


def main():
        if not PASSWORD:
            raise SystemExit("ANYVPS_PASSWORD is required")
        init_db()
        httpd = ThreadingHTTPServer((HOST, PORT), Handler)
        print(f"AnyVPS listening on {HOST}:{PORT}")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
