from config import APP_NAME
from db import get_conn

def collect_state() -> dict:
    with get_conn() as conn:
        vps = [dict(row) for row in conn.execute("select * from vps order by id")]
        checks = [
            dict(row)
            for row in conn.execute(
                "select * from ip_checks order by case status when '可用' then 0 when '慢' then 1 else 2 end, latency_ms"
            )
        ]
        tasks = [
            dict(row)
            for row in conn.execute("select * from tasks order by created_at desc, id desc limit 20")
        ]
        username = conn.execute("select value from settings where key='username'").fetchone()["value"]
        imported = conn.execute("select value from settings where key='inventory_imported_at'").fetchone()
    return {
        "app": APP_NAME,
        "username": username,
        "vps": vps,
        "checks": checks,
        "tasks": tasks,
        "inventory_imported_at": int(imported["value"]) if imported else 0,
    }
