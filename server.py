import json
import secrets
import sqlite3
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from config import HOST, PASSWORD, PORT
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
curl -fsSL -o /usr/local/bin/anyvps-webhook-receiver.py https://anyvps.240314.xyz/vps-webhook-receiver.py
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
"""
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            payload = install_webhook_script.encode()
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if path == "/login":
            return self.send_html(LOGIN_HTML)
        username = self.current_user()
        if not username:
            return self.redirect("/login")
        if path == "/":
            return self.send_html(APP_HTML)
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

    def send_html(self, html: str):
        payload = html.encode()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
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


LOGIN_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>zane 自用入口</title>
<style>
:root{--mint:#eaf8f6;--teal:#10a88a;--text:#151923;--muted:#737987;--line:#e8edf0}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:linear-gradient(180deg,#f7fbfb,#eaf8f6);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",sans-serif;color:var(--text);display:grid;place-items:center}.login{width:min(420px,calc(100vw - 32px));background:#fff;border:1px solid var(--line);border-radius:12px;box-shadow:0 18px 55px rgba(22,50,48,.12);padding:28px}.brand{display:flex;align-items:center;gap:12px;margin-bottom:24px}.logo{width:42px;height:42px;border-radius:12px;background:#dff9ee;display:grid;place-items:center;color:var(--teal);font-weight:800}.brand h1{font-size:22px;margin:0}.brand p{margin:4px 0 0;color:var(--muted);font-size:13px}label{display:block;font-size:13px;color:#4d5562;margin:14px 0 6px}input{width:100%;height:44px;border:1px solid var(--line);border-radius:8px;padding:0 12px;font-size:15px;outline:none}input:focus{border-color:var(--teal);box-shadow:0 0 0 3px rgba(16,168,138,.12)}button{width:100%;height:44px;border:0;border-radius:8px;background:var(--teal);color:white;font-size:15px;font-weight:700;margin-top:20px;cursor:pointer}.err,.lock{background:#fff1f2;color:#d92d43;border:1px solid #ffd6dc;border-radius:8px;padding:10px 12px;font-size:13px;margin-bottom:14px;display:none}body:has(form[action*="login"]) .err,body:has(form[action*="login"]) .lock{display:block}.hint{font-size:12px;color:var(--muted);margin-top:14px;text-align:center}
</style>
</head>
<body>
<form class="login" method="post" action="/api/login">
  <div class="brand"><div class="logo">ZA</div><div><h1>zane 自用入口</h1><p>仅限本人访问</p></div></div>
  <div class="err">用户名或密码不正确</div>
  <div class="lock">失败次数过多，请稍后再试</div>
  <label>用户名</label><input name="username" autocomplete="username" required autofocus>
  <label>密码</label><input name="password" type="password" autocomplete="current-password" required>
  <button type="submit">登录</button>
  <div class="hint">登录后右上角头像菜单仅显示用户名和退出登录</div>
</form>
<script>
if(!location.search.includes("error=1"))document.querySelector(".err").remove();
if(!location.search.includes("locked=1"))document.querySelector(".lock").remove();
</script>
</body>
</html>"""


APP_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AnyVPS 控制台</title>
<style>
:root{--bg:#eef9f7;--panel:#fff;--text:#151923;--muted:#737987;--line:#e8edf0;--teal:#10a88a;--teal-weak:#e5fbf4;--purple:#7c3aed;--amber:#d98b19;--red:#de3150;--green:#119d72;--shadow:0 10px 30px rgba(32,70,68,.08)}
*{box-sizing:border-box}body{margin:0;background:linear-gradient(180deg,#f8fbfb 0,#eef9f7 240px,#f7fafb 100%);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",sans-serif}.app{display:grid;grid-template-columns:286px minmax(0,1fr) 326px;min-height:100vh}.side{background:rgba(255,255,255,.86);border-right:1px solid var(--line);padding:18px 14px;position:sticky;top:0;height:100vh;display:flex;flex-direction:column}.brand{display:flex;align-items:center;gap:10px;margin:2px 8px 18px}.logo{width:34px;height:34px;border-radius:10px;background:#dff9ee;color:var(--teal);display:grid;place-items:center;font-weight:900}.brand strong{font-size:18px}.search{height:38px;border:1px solid var(--line);border-radius:8px;padding:0 12px;width:100%;margin-bottom:14px}.vps-list{display:grid;gap:8px;overflow:auto;padding-bottom:10px}.side-tools{margin-top:auto;border-top:1px solid var(--line);padding-top:12px;display:grid;grid-template-columns:44px 1fr;gap:8px}.side-tool{height:38px;border:1px solid var(--line);background:#fff;border-radius:8px;color:#41505c;font-weight:800;cursor:pointer;transition:all .15s}.side-tool.primary-tool{background:var(--teal);border-color:var(--teal);color:#fff}.side-tool:hover{box-shadow:0 0 0 3px rgba(16,168,138,.1)}.side-tool:active{transform:translateY(1px)}.side-tool.primary-tool:active{background:#0f9977}.vps-row{position:relative;border:1px solid transparent;border-radius:8px;padding:10px 10px;background:transparent;cursor:pointer}.vps-row.active{background:#ecfbf7;border-color:#d8f3ec}.vps-row:hover{background:#f7fbfb}.vps-title{display:flex;justify-content:space-between;gap:8px;font-weight:700}.meta{font-size:12px;color:var(--muted);line-height:1.55;margin-top:3px}.dot{width:8px;height:8px;border-radius:99px;display:inline-block;background:var(--green);margin-right:5px}.dot.warn{background:var(--amber)}.dot.err{background:var(--red)}.ctx{position:absolute;width:168px;background:white;border:1px solid var(--line);box-shadow:var(--shadow);border-radius:8px;padding:6px;z-index:40;display:none}.ctx.open{display:block}.ctx button{display:block;width:100%;text-align:left;background:white;border:0;border-radius:6px;padding:9px 10px;color:#303846;cursor:pointer;transition:all .15s}.ctx button:hover{background:#f4fbfa}.ctx button:active{background:#e5f9f5}.ctx button.danger{color:#d92d43}.main{padding:18px 20px 32px}.top{height:54px;display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}.mobile-menu{display:none}.top h1{font-size:20px;margin:0}.top-sub{font-size:12px;color:var(--muted);margin-top:3px}.actions{display:flex;align-items:center;gap:12px}.chip{border:1px solid var(--line);background:white;border-radius:99px;padding:6px 10px;font-size:12px;color:#4f5a66}.avatar{border:0;background:var(--teal);color:#fff;width:38px;height:38px;border-radius:12px;font-weight:800;cursor:pointer;transition:all .15s;position:absolute;right:20px;top:20px;z-index:15}.avatar:active{transform:scale(.95)}.user-menu{position:absolute;right:20px;top:62px;width:170px;background:#fff;border:1px solid var(--line);border-radius:8px;box-shadow:var(--shadow);padding:8px;display:none;z-index:20}.user-menu.open{display:block}.user-menu .name{font-weight:800;padding:8px 10px;border-bottom:1px solid var(--line);margin-bottom:6px}.user-menu button{width:100%;text-align:left;border:0;background:#fff;border-radius:6px;padding:9px 10px;color:#d92d43;cursor:pointer;transition:all .15s}.user-menu button:active{background:#fee}.cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-bottom:12px}.card,.section,.right-card{background:var(--panel);border:1px solid var(--line);border-radius:8px;box-shadow:var(--shadow)}.card{padding:14px;display:flex;gap:12px;align-items:center}.ico{width:38px;height:38px;border-radius:10px;display:grid;place-items:center;background:#dff9ee;color:var(--teal);font-weight:800}.ico.p{background:#efe8ff;color:var(--purple)}.ico.a{background:#fff5d6;color:#bc7a00}.card .label{font-size:12px;color:var(--muted)}.card .num{font-weight:900;font-size:22px;margin-top:2px}.section{padding:14px;margin-bottom:12px}.section h2,.right-card h2{font-size:15px;margin:0 0 12px}.form-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.form-grid label{font-size:12px;color:var(--muted);display:grid;gap:5px}.form-grid input,.form-grid select,.url-input{width:100%;height:36px;border:1px solid var(--line);border-radius:8px;background:#fbfdfd;padding:0 10px;color:#334155;outline:none}.form-grid input:focus,.form-grid select:focus,.url-input:focus,.editor:focus{border-color:var(--teal);box-shadow:0 0 0 3px rgba(16,168,138,.1)}.tags{display:flex;gap:7px;flex-wrap:wrap;margin-top:8px}.url-row{display:grid;grid-template-columns:120px minmax(0,1fr) 160px 66px;gap:8px;align-items:center;margin-bottom:8px}.url-row label{font-size:12px;color:var(--muted)}.url-row.substore-row{grid-template-columns:180px minmax(0,1fr) 66px;margin-bottom:0}.substore-format{height:36px;border:1px solid var(--line);border-radius:8px;background:#fff;padding:0 10px;color:#334155;outline:none;cursor:pointer}.substore-format:focus{border-color:var(--teal);box-shadow:0 0 0 3px rgba(16,168,138,.1)}.url{height:36px;border:1px solid var(--line);border-radius:8px;padding:0 10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#334155;background:#fbfdfd}.mini{height:34px;border:1px solid var(--line);background:white;border-radius:8px;color:#506070;cursor:pointer;transition:all .15s;font-size:13px}.mini:hover{background:#f7fbfb}.mini:active{background:#ecfbf7;transform:translateY(1px)}.source-head{display:flex;justify-content:space-between;align-items:center;gap:10px}.tools{display:flex;gap:8px;flex-wrap:wrap}.primary{border:0;background:var(--teal);color:white;border-radius:8px;height:36px;padding:0 12px;font-weight:800;cursor:pointer;transition:all .15s}.primary:hover{background:#0eae87}.primary:active{background:#0f9977;transform:translateY(1px)}.primary:disabled{background:#93d8c8;cursor:not-allowed;transform:none}.secondary{border:1px solid var(--line);background:white;color:#41505c;border-radius:8px;height:36px;padding:0 12px;cursor:pointer;transition:all .15s}.secondary:hover{background:#f7fbfb;box-shadow:0 1px 3px rgba(0,0,0,.05)}.secondary:active{background:#ecfbf7;transform:translateY(1px)}.secondary:disabled{opacity:.5;cursor:not-allowed;transform:none}.editor{width:100%;height:116px;margin-top:10px;border:1px solid var(--line);border-radius:8px;padding:10px 12px;font:13px/1.7 ui-monospace,SFMono-Regular,Menlo,monospace;resize:vertical;outline:none}.filters{display:flex;gap:7px;margin-bottom:8px}.filter{border:1px solid var(--line);background:white;border-radius:99px;padding:5px 9px;font-size:12px;color:#576474}.filter.active{background:var(--teal-weak);color:var(--teal);border-color:#cfefe8}.table{width:100%;border-collapse:collapse;font-size:13px}.table th{text-align:left;color:var(--muted);font-weight:600;border-bottom:1px solid var(--line);padding:9px}.table td{border-bottom:1px solid #f0f3f5;padding:10px 9px}.badge{border-radius:99px;padding:3px 8px;font-size:12px}.ok{background:#e5fbf4;color:var(--green)}.slow{background:#fff3d9;color:var(--amber)}.bad{background:#ffe8ed;color:var(--red)}.right{border-left:1px solid var(--line);padding:68px 14px 20px;background:rgba(255,255,255,.45);position:relative}.right-card{padding:14px;margin-bottom:12px}.sync-list{display:grid;gap:8px}.check{display:flex;align-items:center;gap:9px;border:1px solid var(--line);border-radius:8px;padding:9px;background:#fff}.check small{display:block;color:var(--muted);font-size:11px;margin-top:2px}.sync-btn{width:100%;height:42px;border:0;border-radius:8px;background:var(--teal);color:#fff;font-weight:900;margin-top:12px;cursor:pointer;transition:all .15s}.sync-btn:hover{background:#0eae87}.sync-btn:active{background:#0f9977;transform:translateY(1px)}.sync-btn:disabled{background:#93d8c8;cursor:not-allowed;transform:none}.steps{display:grid;gap:10px}.step{display:flex;align-items:center;gap:9px;font-size:13px;color:#65717d}.step:before{content:"";width:10px;height:10px;border-radius:99px;background:#d6dde2}.step.done:before{background:var(--green)}.step.active:before{background:var(--purple);box-shadow:0 0 0 4px rgba(124,58,237,.12)}.log{height:512px;background:#111827;color:#d1fae5;border-radius:8px;padding:10px;font:12px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;overflow:auto}.modal{position:fixed;inset:0;background:rgba(15,23,42,.42);display:none;align-items:center;justify-content:center;padding:18px;z-index:50}.modal.open{display:flex}.modal-box{width:min(980px,100%);max-height:min(88vh,860px);background:#fff;border:1px solid var(--line);border-radius:10px;box-shadow:0 24px 70px rgba(15,23,42,.24);padding:16px;display:grid;gap:12px}.modal-head{display:flex;justify-content:space-between;align-items:center;gap:12px}.modal-head h2{margin:0;font-size:17px}.modal-close{width:34px;height:34px;border:1px solid var(--line);border-radius:8px;background:#fff;cursor:pointer;transition:all .15s}.modal-close:hover{background:#f7fbfb}.modal-close:active{background:#ecfbf7;transform:scale(.95)}.modal-copy{display:flex;gap:8px;flex-wrap:wrap}.code-area,.result-area{width:100%;border:1px solid var(--line);border-radius:8px;background:#0f172a;color:#d1fae5;padding:12px;font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;resize:vertical}.code-area{height:260px}.result-area{height:128px;background:#fbfdfd;color:#334155}.modal-note{font-size:12px;color:var(--muted);line-height:1.6}.mobile-user-sheet{display:none}
.remote-tabs{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.remote-tab{height:38px;border:1px solid var(--line);border-radius:8px;background:#fff;color:#41505c;font-weight:800;cursor:pointer}.remote-tab.active{background:var(--teal-weak);border-color:#bcebdd;color:var(--teal)}.remote-panel[hidden]{display:none}
@media (max-width: 900px){.app{display:block}.side,.right{display:none}.main{padding:12px}.top{height:auto;position:sticky;top:0;z-index:5;background:rgba(248,251,251,.9);backdrop-filter:blur(12px);padding:8px 0}.mobile-menu{display:inline-grid;place-items:center;width:36px;height:36px;border:0;background:#fff;border-radius:8px;border:1px solid var(--line)}.top h1{font-size:18px}.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.card{padding:12px}.form-grid{grid-template-columns:1fr}.url-row{grid-template-columns:1fr}.url-row .mini{width:74px}.section{padding:12px}.table,.table tbody,.table tr,.table td{display:block}.table thead{display:none}.table tr{border:1px solid var(--line);border-radius:8px;margin-bottom:8px;background:#fff}.table td{border:0;padding:5px 10px}.table td:before{content:attr(data-label);display:block;font-size:11px;color:var(--muted)}.mobile-stack{display:grid;gap:12px}.user-menu{display:none}.mobile-user-sheet.open{display:block;position:fixed;left:0;right:0;bottom:0;background:#fff;border-radius:14px 14px 0 0;box-shadow:0 -16px 42px rgba(22,50,48,.18);padding:16px;z-index:20}.mobile-user-sheet .name{font-weight:900;margin-bottom:14px}.mobile-user-sheet button{width:100%;height:42px;border:0;border-radius:8px;background:#fff1f2;color:#d92d43;font-weight:800}}
</style>
</head>
<body>
<div class="app">
  <aside class="side">
    <div class="brand"><div class="logo">AV</div><strong>AnyVPS</strong></div>
    <input class="search" placeholder="搜索 VPS">
    <div class="vps-list" id="vpsList"></div>
    <div class="side-tools">
      <button class="side-tool primary-tool" id="newVpsBtn" title="添加新的 VPS">+</button>
      <button class="side-tool" id="remoteCodeBtn" title="复制到新 VPS 执行的采集代码">&lt;&gt; 远端代码</button>
    </div>
  </aside>
  <main class="main">
    <div class="top">
      <div style="display:flex;align-items:center;gap:10px"><button class="mobile-menu">☰</button><div><h1 id="title">VPS 控制台</h1><div class="top-sub" id="subtitle">优选 IP 与订阅同步</div></div></div>
      <div class="actions"><button class="avatar" id="avatar">ZA</button></div>
      <div class="user-menu" id="userMenu"><div class="name" id="userName">zane240314</div><button id="logoutBtn">退出登录</button></div>
    </div>
    <div class="cards">
      <div class="card"><div class="ico">IP</div><div><div class="label">当前 IP 数</div><div class="num" id="ipTotal">42</div></div></div>
      <div class="card"><div class="ico">✓</div><div><div class="label">可用 IP</div><div class="num" id="ipOk">31</div></div></div>
      <div class="card"><div class="ico a">↻</div><div><div class="label">上次同步</div><div class="num" style="font-size:18px" id="lastSync">-</div></div></div>
    </div>
    <section class="section">
      <div class="source-head"><h2>VPS 信息编辑</h2><button class="primary" id="saveInfoBtn">保存信息</button></div>
      <div class="form-grid">
        <label>名称<input id="editName"></label>
        <label>到期时间<input id="editExpires" placeholder="YYYY-MM-DD"></label>
        <label>续费金额<input id="editRenewal"></label>
        <label>币种<select id="editCurrency"><option value="USD">$ USD</option><option value="CNY">¥ RMB</option></select></label>
        <label>续费周期<select id="editRenewalPeriod"><option value="monthly">月付</option><option value="yearly">年付</option></select></label>
        <label>带宽<input id="editBandwidth" placeholder="例如: 100Mbps"></label>
        <label>月流量<input id="editTraffic"></label>
        <label>状态<select id="editStatus"><option>已同步</option><option>已回传</option><option>待刷新</option><option>异常</option></select></label>
        <label>优选管理页<input id="editAdmin"></label>
        <label>健康检查<input id="editHealth"></label>
        <label>Webhook URL<input id="editWebhookUrl" placeholder="http://VPS_IP:18964/webhook"></label>
      </div>
    </section>
    <section class="section">
      <div class="source-head"><h2>通用订阅地址</h2><div class="tags" id="roleTags"></div></div>
      <div class="url-row"><label>3x-ui 通用订阅地址</label><input class="url-input" id="xuiUrl" placeholder="未安装"><button class="mini secondary" id="uploadXui">↑上传</button><button class="mini copy" data-copy="xuiUrl">复制</button></div>
      <div class="url-row"><label>八合一通用订阅地址</label><input class="url-input" id="comboUrl" placeholder="未安装"><button class="mini secondary" id="uploadCombo">↑上传</button><button class="mini copy" data-copy="comboUrl">复制</button></div>
      <div class="url-row"><label>CDN 通用订阅地址</label><input class="url-input" id="cdnUrl" placeholder="未安装"><button class="mini secondary" id="uploadCdn">↑上传</button><button class="mini copy" data-copy="cdnUrl">复制</button></div>
    </section>
    <section class="section">
      <div class="source-head"><h2>SubStore 转换订阅</h2></div>
      <div class="url-row"><label>3x-ui 转换订阅</label><input class="url-input" id="substoreXuiUrl" placeholder="请先上传原始订阅" readonly><select id="substoreXuiFormat" class="substore-format"><option value="base64">通用 (Base64)</option><option value="mihomo">Mihomo (Clash Meta)</option><option value="surge">Surge (macOS)</option><option value="singbox">Sing-box</option></select><button class="mini copy" data-copy="substoreXuiUrl">复制</button></div>
      <div class="url-row"><label>八合一转换订阅</label><input class="url-input" id="substoreComboUrl" placeholder="请先上传原始订阅" readonly><select id="substoreComboFormat" class="substore-format"><option value="base64">通用 (Base64)</option><option value="mihomo">Mihomo (Clash Meta)</option><option value="surge">Surge (macOS)</option><option value="singbox">Sing-box</option></select><button class="mini copy" data-copy="substoreComboUrl">复制</button></div>
      <div class="url-row"><label>CDN 转换订阅</label><input class="url-input" id="substoreCdnUrl" placeholder="请先上传原始订阅" readonly><select id="substoreCdnFormat" class="substore-format"><option value="base64">通用 (Base64)</option><option value="mihomo">Mihomo (Clash Meta)</option><option value="surge">Surge (macOS)</option><option value="singbox">Sing-box</option></select><button class="mini copy" data-copy="substoreCdnUrl">复制</button></div>
    </section>
    <section class="section">
      <div class="source-head"><h2>优选 IP 源</h2><div class="tools"><button class="secondary" id="validateBtn">解析并检测 IP</button><button class="secondary" id="dedupeBtn">去重</button><button class="secondary" id="substoreBtn">验证 Sub-Store</button><button class="primary" id="saveBtn">保存配置</button></div></div>
      <textarea class="editor" id="sources"></textarea>
    </section>
    <section class="section">
      <div class="source-head"><h2>源内 IP 明细检测</h2><div class="filters"><span class="filter active">全部</span><span class="filter">可用</span><span class="filter">低延迟</span><span class="filter">异常</span></div></div>
      <table class="table"><thead><tr><th>IP:端口</th><th>来源</th><th>地区</th><th>延迟</th><th>可用</th><th>最后检测</th></tr></thead><tbody id="checkRows"></tbody></table>
    </section>
  </main>
  <aside class="right">
    <div class="right-card">
      <h2>同步到其他 VPS</h2>
      <div class="sync-list" id="syncTargets"></div>
      <button class="sync-btn" id="syncBtn">一键同步 IP 源</button>
    </div>
    <div class="right-card">
      <h2>同步链路</h2>
      <div class="steps" id="syncSteps">
        <div class="step">管理页已同步</div>
        <div class="step">远端已执行</div>
        <div class="step">订阅已刷新</div>
        <div class="step">Sub-Store已验证</div>
      </div>
    </div>
    <div class="right-card"><h2>任务日志</h2><div class="log" id="log"></div></div>
  </aside>
</div>
<div class="modal" id="remoteCodeModal">
  <div class="modal-box">
    <div class="modal-head">
      <div><h2 id="remoteToolTitle">远端采集代码</h2><div class="modal-note" id="remoteToolNote">复制下面代码到新 VPS 执行，输出 JSON 后可粘贴到下方并填入当前 VPS。</div></div>
      <button class="modal-close" id="closeRemoteCode">×</button>
    </div>
    <div class="remote-tabs" role="tablist" aria-label="远端工具">
      <button class="remote-tab active" type="button" data-remote-tool="collector">远端采集</button>
      <button class="remote-tab" type="button" data-remote-tool="installer">3x-ui-zane 安装</button>
    </div>
    <section class="remote-panel" id="remoteCollectorPanel">
      <textarea class="code-area" id="remoteCode" spellcheck="false" readonly></textarea>
      <div class="modal-copy">
        <button class="primary" id="copyRemoteCode">复制代码</button>
        <button class="secondary" id="applyRemoteResult">将采集结果填入当前 VPS</button>
      </div>
      <textarea class="result-area" id="remoteResult" spellcheck="false" placeholder="把新 VPS 执行后输出的 JSON 粘贴到这里"></textarea>
      <div class="modal-note">采集脚本会避开常见 password/token/key 字段；但粘贴结果前仍建议扫一眼，别把长期密钥带回管理页。</div>
    </section>
    <section class="remote-panel" id="remoteInstallerPanel" hidden>
      <textarea class="code-area" id="installerCode" spellcheck="false" readonly>curl -fsSL https://789.240314.xyz/install.sh | bash</textarea>
      <div class="modal-copy"><button class="primary" id="copyInstallerCode">复制安装命令</button></div>
      <div class="modal-note">使用 root 用户在 Linux amd64 VPS 执行。脚本会检查系统和架构、补齐依赖、备份现有 3x-ui，并校验安装包。</div>
    </section>
  </div>
</div>
<div class="ctx" id="vpsContext">
  <button id="ctxEdit">编辑信息</button>
  <button class="danger" id="ctxDelete">删除 VPS</button>
</div>
<div class="mobile-user-sheet" id="mobileUser"><div class="name" id="mobileUserName">zane240314</div><button id="mobileLogout">退出登录</button></div>
<script>
let state=null, currentId=null, contextVpsId=null;
const $=s=>document.querySelector(s);
const statusDot=v=>v.status==="异常"?"err":(v.last_sync_at&&v.last_sync_at>0?"":"warn");
const money=v=>`${v.currency==="CNY"?"¥":"$"}${v.renewal_amount}/${v.renewal_period==="yearly"?"年":"月"}`;
const lineCount=v=>(v||"").split("\n").map(x=>x.trim()).filter(Boolean).length;
const shortTime=ts=>ts&&ts>0?new Date(ts*1000).toLocaleString("zh-CN",{month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",hour12:false}).replace(/\//g,"-"):"未同步";
function syncLabel(v){
 if(!v.last_sync_at||v.last_sync_at<=0)return "未同步";
 const prefix=(v.last_sync_status||"").includes("daily_0300")?"03:00回传":((v.last_sync_status||"").includes("manual_verify")?"手动回传":"最近同步");
 return `${prefix} ${shortTime(v.last_sync_at)}`;
}
async function load(){state=await fetch("/api/state").then(r=>r.json()); normalizeCurrent(); $("#userName").textContent=state.username;$("#mobileUserName").textContent=state.username;render();}
function normalizeCurrent(){if(!state.vps.length){currentId=null;return} if(!state.vps.some(v=>v.id===currentId)) currentId=state.vps[0].id;}
function current(){normalizeCurrent(); return state.vps.find(v=>v.id===currentId)||state.vps[0]}
function fillForm(c){
 $("#editName").value=c.name||""; $("#editExpires").value=c.expires_at||"";
 $("#editRenewal").value=c.renewal_amount||""; $("#editCurrency").value=c.currency||"USD"; $("#editRenewalPeriod").value=c.renewal_period||"monthly"; $("#editBandwidth").value=c.bandwidth||""; $("#editTraffic").value=c.monthly_traffic||"";
 $("#editStatus").value=c.status||"待刷新"; $("#editAdmin").value=c.admin_url||""; $("#editHealth").value=c.health_url||""; $("#editWebhookUrl").value=c.sync_webhook_url||"";
 $("#xuiUrl").value=c.xui_sub_url||""; $("#comboUrl").value=c.combo_sub_url||""; $("#cdnUrl").value=c.cdn_sub_url||""; $("#sources").value=c.preferred_sources||"";
}
function collectForm(){
 const c={...current()};
 c.name=$("#editName").value; c.expires_at=$("#editExpires").value; c.renewal_amount=$("#editRenewal").value;
 c.currency=$("#editCurrency").value; c.renewal_period=$("#editRenewalPeriod").value; c.bandwidth=$("#editBandwidth").value; c.monthly_traffic=$("#editTraffic").value; c.status=$("#editStatus").value; c.admin_url=$("#editAdmin").value;
 c.health_url=$("#editHealth").value; c.sync_webhook_url=$("#editWebhookUrl").value;
 c.xui_sub_url=$("#xuiUrl").value; c.combo_sub_url=$("#comboUrl").value; c.cdn_sub_url=$("#cdnUrl").value; c.preferred_sources=$("#sources").value;
 return c;
}
function applyCollectedData(data){
 if(!data||typeof data!=="object")return;
 if(data.name)$("#editName").value=data.name;
 if(data.status)$("#editStatus").value=data.status;
 if(data.admin_url)$("#editAdmin").value=data.admin_url;
 if(data.health_url)$("#editHealth").value=data.health_url;
 if(data.xui_sub_url)$("#xuiUrl").value=data.xui_sub_url;
 if(data.combo_sub_url)$("#comboUrl").value=data.combo_sub_url;
 if(data.cdn_sub_url)$("#cdnUrl").value=data.cdn_sub_url;
 if(data.preferred_sources)$("#sources").value=data.preferred_sources;
}
function showContext(x,y){
 const menu=$("#vpsContext");
 menu.style.left=Math.min(x,innerWidth-190)+"px";
 menu.style.top=Math.min(y,innerHeight-96)+"px";
 menu.classList.add("open");
}
function hideContext(){
 const menu=$("#vpsContext");
 if(menu)menu.classList.remove("open");
}
async function deleteContextVps(){
 const v=state.vps.find(x=>x.id===contextVpsId);
 if(!v)return;
 if(!confirm(`删除 ${v.name}？这会删除这台 VPS 的检测记录。`))return;
 const res=await fetch("/api/vps/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:v.id})}).then(r=>r.json());
 hideContext();
 if(!res.ok){alert(res.error==="last_vps"?"至少保留一台 VPS":"删除失败");return;}
 currentId=null;
 contextVpsId=null;
 await load();
}
function render(){
 const c=current();
 $("#title").textContent=c.name; $("#subtitle").textContent=c.role||"优选 IP 与订阅同步";
 $("#roleTags").innerHTML=(c.role||"").split("·").filter(Boolean).map(x=>`<span class="chip">${x.trim()}</span>`).join("");
 fillForm(c);
 updateAllSubstoreUrls();
 $("#vpsList").innerHTML=state.vps.map(v=>`<div class="vps-row ${v.id===currentId?"active":""}" data-id="${v.id}"><div class="vps-title"><span>${v.name}</span><small><i class="dot ${statusDot(v)}"></i>${syncLabel(v)}</small></div><div class="meta">到期 ${v.expires_at||"-"} · 续费 ${money(v)} · ${v.monthly_traffic||"-"}</div></div>`).join("");
 document.querySelectorAll(".vps-row").forEach(el=>{
  el.onclick=()=>{hideContext(); currentId=Number(el.dataset.id); render();};
  el.oncontextmenu=e=>{
   e.preventDefault();
   contextVpsId=Number(el.dataset.id);
   currentId=contextVpsId;
   render();
   showContext(e.clientX,e.clientY);
  };
 });
 const checks=state.checks.filter(x=>x.vps_id===c.id);
 const ok=checks.filter(x=>x.status==="可用"||x.status==="慢").length;

 // 更新卡片数据
 $("#ipTotal").textContent=checks.length||"-";
 $("#ipOk").textContent=ok;

 // 显示上次同步时间
 if(c.last_sync_at && c.last_sync_at > 0) {
   const syncDate = new Date(c.last_sync_at * 1000);
   const now = Date.now();
   const diffMs = now - syncDate.getTime();
   const diffHours = Math.floor(diffMs / 3600000);
   const diffMins = Math.floor(diffMs / 60000);

   let syncText = "";
   if(diffMins < 1) syncText = "刚刚";
   else if(diffMins < 60) syncText = diffMins + "分钟前";
   else if(diffHours < 24) syncText = diffHours + "小时前";
   else syncText = Math.floor(diffHours / 24) + "天前";

   $("#lastSync").textContent = syncText;
 } else {
   $("#lastSync").textContent = "-";
 }

 $("#checkRows").innerHTML=(checks.length?checks:[{endpoint:"等待检测",source:"-",region:"",latency_ms:null,status:"待检测",checked_at:0}]).map(x=>`<tr><td data-label="IP:端口">${x.endpoint}</td><td data-label="来源">${x.source}</td><td data-label="地区">${x.region||"-"}</td><td data-label="延迟">${x.latency_ms?x.latency_ms+"ms":"--"}</td><td data-label="可用"><span class="badge ${x.status==="可用"?"ok":(x.status==="慢"?"slow":"bad")}">${x.status}</span></td><td data-label="最后检测">${x.checked_at?new Date(x.checked_at*1000).toLocaleString():"-"}</td></tr>`).join("");
 // 格式化同步状态显示
 function formatSyncStatus(v){
   const isError = v.status==="异常" || (v.last_sync_status && v.last_sync_status.includes("失败"));
   if(isError && v.last_sync_status){
     return " · "+v.last_sync_status;
   }
   return "";
 }
 $("#syncTargets").innerHTML=state.vps.filter(v=>v.id!==c.id).map(v=>`<label class="check"><input type="checkbox" value="${v.id}"><span><b>${v.name}</b><small>源数量 ${lineCount(v.preferred_sources)} · ${v.status}${formatSyncStatus(v)}</small></span></label>`).join("");
 // 更新同步链路步骤
 function updateSyncSteps(status){
   const steps=["管理页已同步","远端已执行","订阅已刷新","Sub-Store已验证"];
   const stepStates=[false,false,false,false];
   if(!status){
     $("#syncSteps").innerHTML=steps.map(s=>`<div class="step">${s}</div>`).join("");
     return;
   }
   if(status.includes("管理页已同步"))stepStates[0]=true;
   if(status.includes("远端已执行")||status.includes("远端执行器响应"))stepStates[1]=true;
   if(status.includes("订阅已刷新"))stepStates[2]=true;
   if(status.includes("Sub-Store已验证"))stepStates[3]=true;
   $("#syncSteps").innerHTML=steps.map((s,i)=>`<div class="step ${stepStates[i]?'done':''}">${s}</div>`).join("");
 }
 updateSyncSteps(c.last_sync_status);
 $("#log").innerHTML=(state.tasks.length?state.tasks:[{message:"等待操作：保存配置后可执行 IP 检测或同步。"}]).map(t=>`&gt; ${t.message}`).join("<br>");
}
$("#avatar").onclick=()=>{if(innerWidth<=900)$("#mobileUser").classList.toggle("open");else $("#userMenu").classList.toggle("open")};
async function logout(){await fetch("/api/logout",{method:"POST"}); location.href="/login"}
$("#logoutBtn").onclick=logout; $("#mobileLogout").onclick=logout;
$("#ctxEdit").onclick=()=>{hideContext(); if(contextVpsId){currentId=contextVpsId; render(); document.querySelector("#editName").focus();}};
$("#ctxDelete").onclick=deleteContextVps;
document.addEventListener("click",e=>{if(!e.target.closest("#vpsContext"))hideContext();});
document.addEventListener("keydown",e=>{if(e.key==="Escape")hideContext();});
// 按钮加载状态辅助函数
function btnLoading(btn,text){btn.disabled=true;btn.dataset.originalText=btn.textContent;btn.textContent=text;}
function btnReset(btn){btn.disabled=false;if(btn.dataset.originalText)btn.textContent=btn.dataset.originalText;}
async function saveCurrent(){const c=collectForm(); currentId=c.id; await fetch("/api/vps",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(c)}); await load(); return current();}
$("#saveBtn").onclick=async()=>{try{btnLoading($("#saveBtn"),"保存中...");await saveCurrent();alert("✓ 配置已保存");btnReset($("#saveBtn"));}catch(e){alert("✗ 保存失败: "+e.message);btnReset($("#saveBtn"));}};
$("#saveInfoBtn").onclick=async()=>{try{btnLoading($("#saveInfoBtn"),"保存中...");await saveCurrent();alert("✓ 配置已保存");btnReset($("#saveInfoBtn"));}catch(e){alert("✗ 保存失败: "+e.message);btnReset($("#saveInfoBtn"));}};
$("#newVpsBtn").onclick=async()=>{const name=prompt("新 VPS 名称","新 VPS"); if(name===null)return; const res=await fetch("/api/vps/new",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name})}).then(r=>r.json()); if(res.ok){currentId=res.id; await load(); document.querySelector("#editName").focus();}};
function applyCollectedData(data){
  console.log("应用远端采集数据:", data);
  const c=current();
  if(data.name)$("#editName").value=data.name;
  if(data.role)$("#editRole").value=data.role;
  if(data.admin_url)$("#editAdmin").value=data.admin_url;
  if(data.health_url)$("#editHealth").value=data.health_url;
  if(data.xui_sub_url)$("#xuiUrl").value=data.xui_sub_url;
  if(data.combo_sub_url)$("#comboUrl").value=data.combo_sub_url;
  if(data.cdn_sub_url)$("#cdnUrl").value=data.cdn_sub_url;
  if(data.substore_download_url)$("#editSubstore").value=data.substore_download_url;
  if(data.preferred_sources){
    const existing=$("#sources").value.trim();
    const newSources=data.preferred_sources.trim();
    if(existing&&newSources&&!confirm("当前已有优选源配置，是否替换为远端采集的源？\n\n点击「确定」替换，点击「取消」保留现有配置。"))return;
    $("#sources").value=newSources;
  }
  console.log("✓ 远端数据已填充到表单");
  alert("远端数据已填充完成！\n\n请检查表单内容，确认无误后点击「保存信息」。"+(data.detected_urls?"\n\n检测到 "+data.detected_urls.length+" 个 URL，已自动匹配订阅地址。":""));
}
async function setRemoteTool(tool){
 const isCollector=tool==="collector";
 $("#remoteCollectorPanel").hidden=!isCollector; $("#remoteInstallerPanel").hidden=isCollector;
 $("#remoteToolTitle").textContent=isCollector?"远端采集代码":"3x-ui-zane 一键安装";
 $("#remoteToolNote").textContent=isCollector?"复制下面代码到新 VPS 执行，输出 JSON 后可粘贴到下方并填入当前 VPS。":"复制命令到其他 VPS 直接执行，无需记忆安装地址。";
 document.querySelectorAll("[data-remote-tool]").forEach(button=>button.classList.toggle("active",button.dataset.remoteTool===tool));
 if(isCollector&&!$("#remoteCode").value)$("#remoteCode").value=await fetch("/api/remote-code").then(r=>r.text());
}
$("#remoteCodeBtn").onclick=async()=>{$("#remoteCodeModal").classList.add("open"); await setRemoteTool("collector");};
document.querySelectorAll("[data-remote-tool]").forEach(button=>button.onclick=()=>setRemoteTool(button.dataset.remoteTool));
$("#closeRemoteCode").onclick=()=>$("#remoteCodeModal").classList.remove("open");
$("#remoteCodeModal").onclick=e=>{if(e.target.id==="remoteCodeModal")$("#remoteCodeModal").classList.remove("open")};
$("#copyRemoteCode").onclick=()=>navigator.clipboard.writeText($("#remoteCode").value||"");
$("#copyInstallerCode").onclick=()=>navigator.clipboard.writeText($("#installerCode").value);
$("#applyRemoteResult").onclick=()=>{try{applyCollectedData(JSON.parse($("#remoteResult").value)); $("#remoteCodeModal").classList.remove("open");}catch(e){console.error("JSON解析失败:",e);alert("JSON 解析失败: "+e.message+"\n\n请检查是否完整复制了脚本输出的 JSON。");}};
$("#dedupeBtn").onclick=()=>{const before=$("#sources").value.split("\n").filter(Boolean).length;$("#sources").value=[...new Set($("#sources").value.split("\n").map(x=>x.trim()).filter(Boolean))].join("\n");const after=$("#sources").value.split("\n").filter(Boolean).length;if(before>after)alert(`✓ 去重完成\n\n删除了 ${before-after} 个重复项`);else alert("✓ 无重复项");};
$("#validateBtn").onclick=async()=>{try{btnLoading($("#validateBtn"),"检测中...");const c=await saveCurrent();await fetch("/api/check-ips",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({vps_id:c.id})});await load();alert("✓ IP 检测已完成\n\n请查看下方「源内 IP 明细检测」表格");btnReset($("#validateBtn"));}catch(e){alert("✗ 检测失败: "+e.message);btnReset($("#validateBtn"));}};
$("#substoreBtn").onclick=async()=>{try{btnLoading($("#substoreBtn"),"验证中...");const c=await saveCurrent();const resp=await fetch("/api/substore/verify",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({vps_id:c.id})});await load();const result=await resp.json();if(result.ok)alert("✓ Sub-Store 验证成功");else alert("✗ Sub-Store 验证失败: "+(result.error||"未知错误"));btnReset($("#substoreBtn"));}catch(e){alert("✗ 验证失败: "+e.message);btnReset($("#substoreBtn"));}};
$("#syncBtn").onclick=async()=>{
  try {
    let ids=[...document.querySelectorAll("#syncTargets input:checked")].map(x=>Number(x.value));
    const c=await saveCurrent();
    if(!ids.length)ids=state.vps.filter(v=>v.id!==c.id).map(v=>v.id);
    if(!ids.length){alert("请至少勾选一个目标 VPS");return;}
    console.log("开始同步到目标 VPS:", ids);
    $("#syncBtn").disabled=true;
    $("#syncBtn").textContent="同步中...";
    const response=await fetch("/api/sync-sources",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({source_vps_id:c.id,target_vps_ids:ids})});
    const result=await response.json();
    if(result.ok){
      console.log("✓ 同步成功:", result);
      alert(`✓ 同步完成！\n\n已同步到 ${ids.length} 台 VPS\n\n请查看右侧任务日志了解详情。`);
    }else{
      console.error("✗ 同步失败:", result);
      alert(`✗ 同步失败：${result.error || "未知错误"}`);
    }
    await load();
  }catch(e){
    console.error("同步异常:", e);
    alert("同步失败: "+e.message);
  }finally{
    $("#syncBtn").disabled=false;
    $("#syncBtn").textContent="一键同步 IP 源";
  }
};
document.querySelectorAll(".copy").forEach(btn=>btn.onclick=()=>{
  const value=$("#"+btn.dataset.copy).value;
  if(!value){
    alert("⚠️ 无内容可复制");
    return;
  }
  navigator.clipboard.writeText(value);
  const originalText=btn.textContent;
  btn.textContent="✓ 已复制";
  btn.style.background="#e5fbf4";
  btn.style.color="#059669";
  setTimeout(()=>{
    btn.textContent=originalText;
    btn.style.background="";
    btn.style.color="";
  },1500);
});
// SubStore 格式选择器（3个独立的）
$("#substoreXuiFormat").onchange=function(){
  updateSubstoreUrl('xui');
};
$("#substoreComboFormat").onchange=function(){
  updateSubstoreUrl('combo');
};
$("#substoreCdnFormat").onchange=function(){
  updateSubstoreUrl('cdn');
};

function updateSubstoreUrl(type){
  const c=current();

  if(type==='xui'){
    const format=$("#substoreXuiFormat").value;
    const urlMap={
      "base64": c.substore_xui_base64_url,
      "mihomo": c.substore_xui_mihomo_url,
      "surge": c.substore_xui_surge_url,
      "singbox": c.substore_xui_singbox_url
    };
    const url=urlMap[format]||"";
    $("#substoreXuiUrl").value=url;
    $("#substoreXuiUrl").placeholder=url?"":"请先上传原始订阅";
  } else if(type==='combo'){
    const format=$("#substoreComboFormat").value;
    const urlMap={
      "base64": c.substore_combo_base64_url,
      "mihomo": c.substore_combo_mihomo_url,
      "surge": c.substore_combo_surge_url,
      "singbox": c.substore_combo_singbox_url
    };
    const url=urlMap[format]||"";
    $("#substoreComboUrl").value=url;
    $("#substoreComboUrl").placeholder=url?"":"请先上传原始订阅";
  } else if(type==='cdn'){
    const format=$("#substoreCdnFormat").value;
    const urlMap={
      "base64": c.substore_cdn_base64_url,
      "mihomo": c.substore_cdn_mihomo_url,
      "surge": c.substore_cdn_surge_url,
      "singbox": c.substore_cdn_singbox_url
    };
    const url=urlMap[format]||"";
    $("#substoreCdnUrl").value=url;
    $("#substoreCdnUrl").placeholder=url?"":"请先上传原始订阅";
  }
}

// 更新所有 SubStore URL
function updateAllSubstoreUrls(){
  updateSubstoreUrl('xui');
  updateSubstoreUrl('combo');
  updateSubstoreUrl('cdn');
}

// 上传订阅到 SubStore
async function uploadToSubstore(type){
  const c=current();
  const urlMap={
    "xui": $("#xuiUrl").value,
    "combo": $("#comboUrl").value,
    "cdn": $("#cdnUrl").value
  };

  const sourceUrl=urlMap[type];
  if(!sourceUrl){
    alert("⚠️ 请先填写订阅地址");
    return;
  }

  const btn=$("#upload"+type.charAt(0).toUpperCase()+type.slice(1));
  const originalText=btn.textContent;

  try{
    btn.disabled=true;
    btn.textContent="上传中...";

    const resp=await fetch("/api/substore/upload",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({
        vps_id:c.id,
        vps_name:c.name,
        source_type:type,
        source_url:sourceUrl
      })
    });

    const result=await resp.json();

    if(result.ok){
      alert(`✓ 上传成功！\n\n已在 SubStore 创建订阅项：${result.item_name}\n生成了 4 种格式的转换链接`);

      // 更新当前 VPS 数据
      c.substore_base64_url=result.urls.base64;
      c.substore_mihomo_url=result.urls.mihomo;
      c.substore_surge_url=result.urls.surge;
      c.substore_singbox_url=result.urls.singbox;

      // 刷新显示
      updateAllSubstoreUrls();

      // 重新加载数据
      await load();
    }else{
      alert(`✗ 上传失败：${result.error||"未知错误"}`);
    }
  }catch(e){
    console.error("上传异常:",e);
    alert("✗ 上传失败: "+e.message);
  }finally{
    btn.disabled=false;
    btn.textContent=originalText;
  }
}

$("#uploadXui").onclick=()=>uploadToSubstore("xui");
$("#uploadCombo").onclick=()=>uploadToSubstore("combo");
$("#uploadCdn").onclick=()=>uploadToSubstore("cdn");

load();
</script>
</body>
</html>"""


def main():
        if not PASSWORD:
            raise SystemExit("ANYVPS_PASSWORD is required")
        init_db()
        httpd = ThreadingHTTPServer((HOST, PORT), Handler)
        print(f"AnyVPS listening on {HOST}:{PORT}")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
