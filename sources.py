import re
import socket
import sqlite3
import time
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlparse

from config import CONNECT_TIMEOUT, HTTP_TIMEOUT, IP_CHECK_LIMIT, SOURCE_FETCH_LIMIT
from db import get_conn
from security import now_ts

def clean_text(value, limit: int = 2000) -> str:
    if value is None:
        return ""
    text = str(value).replace("\x00", "").strip()
    return text[:limit]


def upsert_inventory_rows(rows: list[dict]) -> int:
    imported = 0
    allowed = [
        "name",
        "role",
        "expires_at",
        "renewal_amount",
        "currency",
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
    with get_conn() as conn:
        already_imported = conn.execute("select value from settings where key='inventory_imported_at'").fetchone()
        if rows and already_imported is None:
            sample_ids = [
                row["id"]
                for row in conn.execute(
                    """
                    select id from vps
                    where source_file=''
                      and (
                        xui_sub_url like '%example.com%'
                        or combo_sub_url like '%example.com%'
                        or cdn_sub_url like '%example.com%'
                        or name in ('主控 VPS','边缘 VPS A','边缘 VPS B','备用 VPS','代理 VPS')
                      )
                    """
                )
            ]
            if sample_ids:
                conn.execute(
                    f"delete from ip_checks where vps_id in ({','.join('?' for _ in sample_ids)})",
                    sample_ids,
                )
                conn.execute(
                    f"delete from vps where id in ({','.join('?' for _ in sample_ids)})",
                    sample_ids,
                )
        for row in rows:
            name = clean_text(row.get("name"), 120)
            if not name:
                continue
            values = {key: clean_text(row.get(key), 4000) for key in allowed}
            values["name"] = name
            if values["currency"] not in {"USD", "CNY"}:
                values["currency"] = "USD"
            if values["substore_target"] not in {"Mihomo", "ClashMeta", "sing-box", "Surge"}:
                values["substore_target"] = "Mihomo"
            values["updated_at"] = str(now_ts())
            existing = None
            source_file = values.get("source_file")
            if source_file:
                existing = conn.execute(
                    "select id from vps where source_file=?",
                    (source_file,),
                ).fetchone()
            if existing is None:
                existing = conn.execute("select id from vps where name=?", (name,)).fetchone()
            columns = [*allowed, "updated_at"]
            if existing:
                sets = ",".join(f"{key}=?" for key in columns)
                conn.execute(
                    f"update vps set {sets} where id=?",
                    [values[key] for key in columns] + [existing["id"]],
                )
            else:
                placeholders = ",".join("?" for _ in columns)
                conn.execute(
                    f"insert into vps({','.join(columns)}) values({placeholders})",
                    [values[key] for key in columns],
                )
            imported += 1
        conn.execute(
            "insert or replace into settings(key,value) values('inventory_imported_at',?)",
            (str(now_ts()),),
        )
    return imported


def read_url(url: str, timeout: int = HTTP_TIMEOUT) -> tuple[int, str, bytes]:
    req = urlrequest.Request(url, headers={"User-Agent": "AnyVPS/0.1"})
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.headers.get("content-type", ""), resp.read(SOURCE_FETCH_LIMIT)
    except urlerror.HTTPError as exc:
        return exc.code, exc.headers.get("content-type", ""), exc.read(min(SOURCE_FETCH_LIMIT, 80_000))


ENDPOINT_RE = re.compile(
    r"(?<![\w.-])((?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-fA-F:]+\]|[a-zA-Z0-9][a-zA-Z0-9.-]{1,250}\.[a-zA-Z]{2,})(?::|%3A)([0-9]{2,5})"
)


def parse_endpoints(text: str, source: str) -> list[dict]:
    found = []
    seen = set()
    for match in ENDPOINT_RE.finditer(text):
        host = match.group(1).strip("[]")
        port = int(match.group(2))
        if port < 1 or port > 65535:
            continue
        endpoint = f"{host}:{port}"
        if endpoint in seen:
            continue
        seen.add(endpoint)
        found.append({"endpoint": endpoint, "host": host, "port": port, "source": source})
        if len(found) >= IP_CHECK_LIMIT:
            break
    return found


def source_label(line: str) -> str:
    parsed = urlparse(line)
    if parsed.netloc:
        return (parsed.netloc + parsed.path).strip("/")[-80:] or parsed.netloc
    return "manual"


def gather_source_endpoints(source_lines: list[str]) -> tuple[list[dict], list[str]]:
    endpoints = []
    errors = []
    for raw in source_lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        label = source_label(line)
        content = line
        if line.startswith(("http://", "https://")):
            try:
                status, _ctype, body = read_url(line)
                if status >= 400:
                    errors.append(f"{label} HTTP {status}")
                    continue
                content = body.decode("utf-8", "ignore")
            except Exception as exc:
                errors.append(f"{label} {type(exc).__name__}")
                continue
        for item in parse_endpoints(content, label):
            endpoints.append(item)
            if len(endpoints) >= IP_CHECK_LIMIT:
                return endpoints, errors
    return endpoints, errors


def tcp_check(host: str, port: int) -> tuple[str, int | None]:
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            latency = int((time.monotonic() - start) * 1000)
            return ("慢" if latency > 300 else "可用"), latency
    except Exception:
        return "超时", None


def collect_ip_check_rows(sources: str) -> tuple[list[dict], list[str]]:
    endpoints, errors = gather_source_endpoints(sources.splitlines())
    rows = []
    checked_at = now_ts()
    for item in endpoints:
        status, latency = tcp_check(item["host"], item["port"])
        rows.append(
            {
                "endpoint": item["endpoint"],
                "source": item["source"],
                "region": "",
                "latency_ms": latency,
                "status": status,
                "checked_at": checked_at,
            }
        )
    return rows, errors


def write_ip_check_rows(conn: sqlite3.Connection, vps_id: int, rows: list[dict], errors: list[str], kind: str, prefix: str) -> tuple[int, int]:
    conn.execute("delete from ip_checks where vps_id=?", (vps_id,))
    if rows:
        conn.executemany(
            "insert into ip_checks(vps_id,endpoint,source,region,latency_ms,status,checked_at) values(?,?,?,?,?,?,?)",
            [
                (
                    vps_id,
                    row["endpoint"],
                    row["source"],
                    row["region"],
                    row["latency_ms"],
                    row["status"],
                    row["checked_at"],
                )
                for row in rows
            ],
        )
    ok_count = sum(1 for row in rows if row["status"] in {"可用", "慢"})
    message = f"{prefix}：解析 {len(rows)} 个，连通 {ok_count} 个"
    if errors:
        message += "；源错误：" + "；".join(errors[:4])
    conn.execute(
        "insert into tasks(vps_id,kind,status,message,created_at) values(?,?,?,?,?)",
        (vps_id, kind, "done", message, now_ts()),
    )
    return len(rows), ok_count


def check_vps_sources(vps_id: int) -> dict:
    with get_conn() as conn:
        row = conn.execute("select * from vps where id=?", (vps_id,)).fetchone()
        if row is None:
            return {"ok": False, "error": "vps_not_found"}
        sources = row["preferred_sources"]
    rows, errors = collect_ip_check_rows(sources)
    with get_conn() as conn:
        total, ok_count = write_ip_check_rows(conn, vps_id, rows, errors, "check_ips", "IP 检测完成")
    return {"ok": True, "total": total, "usable": ok_count, "errors": errors}
