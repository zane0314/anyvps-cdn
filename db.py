import sqlite3

from config import DATA_DIR, DB_PATH, PASSWORD, USERNAME
from security import hash_password, now_ts

def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_columns(conn: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
    existing = {row["name"] for row in conn.execute(f"pragma table_info({table})")}
    for name, ddl in columns.items():
        if name not in existing:
            conn.execute(f"alter table {table} add column {name} {ddl}")


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(
            """
            create table if not exists settings (
              key text primary key,
              value text not null
            );
            create table if not exists vps (
              id integer primary key autoincrement,
              name text not null,
              host_hint text not null default '',
              role text not null default '',
              expires_at text not null default '',
              renewal_amount text not null default '',
              currency text not null default 'USD',
              renewal_period text not null default 'monthly',
              bandwidth text not null default '',
              monthly_traffic text not null default '',
              status text not null default '待刷新',
              xui_sub_url text not null default '',
              combo_sub_url text not null default '',
              cdn_sub_url text not null default '',
              preferred_sources text not null default '',
              admin_url text not null default '',
              health_url text not null default '',
              source_file text not null default '',
              sync_webhook_url text not null default '',
              sync_webhook_token text not null default '',
              sync_command text not null default '',
              agent_token_hash text not null default '',
              agent_source_file text not null default '',
              agent_refresh_command text not null default '',
              agent_verify_url text not null default '',
              agent_version text not null default '',
              pending_sync_id text not null default '',
              pending_sync_sources text not null default '',
              pending_sync_source_name text not null default '',
              pending_sync_status text not null default '',
              pending_sync_message text not null default '',
              pending_sync_requested_at integer not null default 0,
              pending_sync_finished_at integer not null default 0,
              substore_download_url text not null default '',
              substore_api_url text not null default '',
              substore_item text not null default '',
              substore_target text not null default 'Mihomo',
              substore_xui_base64_url text not null default '',
              substore_xui_mihomo_url text not null default '',
              substore_xui_surge_url text not null default '',
              substore_xui_singbox_url text not null default '',
              substore_combo_base64_url text not null default '',
              substore_combo_mihomo_url text not null default '',
              substore_combo_surge_url text not null default '',
              substore_combo_singbox_url text not null default '',
              substore_cdn_base64_url text not null default '',
              substore_cdn_mihomo_url text not null default '',
              substore_cdn_surge_url text not null default '',
              substore_cdn_singbox_url text not null default '',
              last_sync_at integer not null default 0,
              last_sync_status text not null default '',
              updated_at integer not null default 0
            );
            create table if not exists ip_checks (
              id integer primary key autoincrement,
              vps_id integer not null,
              endpoint text not null,
              source text not null,
              region text not null default '',
              latency_ms integer,
              status text not null,
              checked_at integer not null,
              foreign key(vps_id) references vps(id) on delete cascade
            );
            create table if not exists tasks (
              id integer primary key autoincrement,
              vps_id integer,
              kind text not null,
              status text not null,
              message text not null default '',
              created_at integer not null,
              foreign key(vps_id) references vps(id) on delete set null
            );
            create table if not exists collector_tokens (
              id integer primary key autoincrement,
              token text not null unique,
              vps_id integer,
              created_at integer not null,
              expires_at integer not null,
              used_at integer,
              foreign key(vps_id) references vps(id) on delete set null
            );
            """
        )
        ensure_columns(
            conn,
            "vps",
            {
                "host_hint": "text not null default ''",
                "renewal_period": "text not null default 'monthly'",
                "bandwidth": "text not null default ''",
                "admin_url": "text not null default ''",
                "health_url": "text not null default ''",
                "source_file": "text not null default ''",
                "sync_webhook_url": "text not null default ''",
                "sync_webhook_token": "text not null default ''",
                "sync_command": "text not null default ''",
                "agent_token_hash": "text not null default ''",
                "agent_source_file": "text not null default ''",
                "agent_refresh_command": "text not null default ''",
                "agent_verify_url": "text not null default ''",
                "agent_version": "text not null default ''",
                "pending_sync_id": "text not null default ''",
                "pending_sync_sources": "text not null default ''",
                "pending_sync_source_name": "text not null default ''",
                "pending_sync_status": "text not null default ''",
                "pending_sync_message": "text not null default ''",
                "pending_sync_requested_at": "integer not null default 0",
                "pending_sync_finished_at": "integer not null default 0",
                "collector_url": "text not null default ''",
                "collector_token": "text not null default ''",
                "substore_download_url": "text not null default ''",
                "substore_api_url": "text not null default ''",
                "substore_item": "text not null default ''",
                "substore_target": "text not null default 'Mihomo'",
                "substore_base64_url": "text not null default ''",
                "substore_mihomo_url": "text not null default ''",
                "substore_surge_url": "text not null default ''",
                "substore_singbox_url": "text not null default ''",
                "substore_xui_base64_url": "text not null default ''",
                "substore_xui_mihomo_url": "text not null default ''",
                "substore_xui_surge_url": "text not null default ''",
                "substore_xui_singbox_url": "text not null default ''",
                "substore_combo_base64_url": "text not null default ''",
                "substore_combo_mihomo_url": "text not null default ''",
                "substore_combo_surge_url": "text not null default ''",
                "substore_combo_singbox_url": "text not null default ''",
                "substore_cdn_base64_url": "text not null default ''",
                "substore_cdn_mihomo_url": "text not null default ''",
                "substore_cdn_surge_url": "text not null default ''",
                "substore_cdn_singbox_url": "text not null default ''",
                "last_sync_at": "integer not null default 0",
                "last_sync_status": "text not null default ''",
                "last_collect_at": "integer not null default 0",
            },
        )
        password_hash = conn.execute(
            "select value from settings where key='password_hash'"
        ).fetchone()
        if password_hash is None and PASSWORD:
            conn.execute(
                "insert into settings(key,value) values('password_hash',?)",
                (hash_password(PASSWORD),),
            )
        user = conn.execute("select value from settings where key='username'").fetchone()
        if user is None:
            conn.execute(
                "insert into settings(key,value) values('username',?)",
                (USERNAME,),
            )
        count = conn.execute("select count(*) from vps").fetchone()[0]
        if count == 0:
            seed_vps(conn)


def seed_vps(conn: sqlite3.Connection) -> None:
    rows = [
        (
            "洛杉矶 主控",
            "Sub-Store · nginx · x-ui · CDN 优选",
            "2026-12-18",
            "8",
            "USD",
            "8TB",
            "已同步",
            "https://3xui.example.com/sub/...",
            "https://la.example.com/all-in-one/sub...",
            "https://la-cdn.example.com/sub...?refresh=1",
            "https://example.com/bestcf.txt\nhttps://ip-source.example.net/cf.list\nhttps://raw.example.org/cloudflare-speed.txt",
        ),
        ("云途 A", "3x-ui · CDN 优选", "2026-10-02", "42", "CNY", "1TB", "待刷新", "", "", "", ""),
        ("云途 B", "3x-ui · Docker", "2026-11-15", "48", "CNY", "2TB", "已同步", "", "", "", ""),
        ("圣何塞 CN2", "备用 · 低延迟", "2026-09-01", "6", "USD", "500GB", "待刷新", "", "", "", ""),
        ("凯撒斯", "代理 · 备用", "2026-08-20", "5", "USD", "1TB", "异常", "", "", "", ""),
    ]
    conn.executemany(
        """
        insert into vps(
          name,role,expires_at,renewal_amount,currency,monthly_traffic,status,
          xui_sub_url,combo_sub_url,cdn_sub_url,preferred_sources,updated_at
        ) values(?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        [(*row, now_ts()) for row in rows],
    )
    checks = [
        (1, "104.21.80.138:443", "bestcf.txt", "LAX", 86, "可用", now_ts()),
        (1, "172.67.12.10:443", "cf.list", "SJC", 142, "慢", now_ts()),
        (1, "162.159.140.33:443", "cloudflare-speed.txt", "HKG", 94, "可用", now_ts()),
        (1, "198.41.214.162:443", "bestcf.txt", "N/A", None, "超时", now_ts()),
    ]
    conn.executemany(
        "insert into ip_checks(vps_id,endpoint,source,region,latency_ms,status,checked_at) values(?,?,?,?,?,?,?)",
        checks,
    )
