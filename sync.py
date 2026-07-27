import json
import os
import secrets
import sqlite3
import subprocess
import tempfile
from pathlib import Path
from urllib import error as urlerror
from urllib import request as urlrequest

from config import DATA_DIR, HTTP_TIMEOUT
from db import get_conn
from security import now_ts
from sources import collect_ip_check_rows, write_ip_check_rows

def post_webhook(url: str, payload: dict, token: str = "") -> tuple[bool, str]:
    headers = {"Content-Type": "application/json", "User-Agent": "AnyVPS/0.1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urlrequest.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urlrequest.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            body = resp.read(20_000).decode("utf-8", "ignore")
            return resp.status < 400, f"webhook HTTP {resp.status} {body[:160]}".strip()
    except urlerror.HTTPError as exc:
        return False, f"webhook HTTP {exc.code}"
    except Exception as exc:
        return False, f"webhook {type(exc).__name__}"


def run_sync_command(command: str, target: sqlite3.Row, sources: str) -> tuple[bool, str]:
    sync_dir = DATA_DIR / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=sync_dir, delete=False) as tmp:
        tmp.write(sources)
        source_path = tmp.name
    env = os.environ.copy()
    env.update(
        {
            "ANYVPS_TARGET_ID": str(target["id"]),
            "ANYVPS_TARGET_NAME": target["name"],
            "ANYVPS_SOURCES_FILE": source_path,
        }
    )
    try:
        proc = subprocess.run(
            command,
            shell=True,
            cwd=str(DATA_DIR),
            env=env,
            text=True,
            capture_output=True,
            timeout=45,
        )
        output = (proc.stdout + "\n" + proc.stderr).strip().replace("\n", " ")
        return proc.returncode == 0, f"command exit {proc.returncode} {output[:220]}".strip()
    except subprocess.TimeoutExpired:
        return False, "command timeout"
    except Exception as exc:
        return False, f"command {type(exc).__name__}"
    finally:
        try:
            Path(source_path).unlink()
        except OSError:
            pass


def sync_sources(source_id: int, target_ids: list[int]) -> dict:
    with get_conn() as conn:
        source = conn.execute("select * from vps where id=?", (source_id,)).fetchone()
        if source is None:
            return {"ok": False, "error": "source_not_found"}
        sources = source["preferred_sources"]
        targets = [
            row
            for row in conn.execute(
                f"select * from vps where id in ({','.join('?' for _ in target_ids)})",
                target_ids,
            )
        ] if target_ids else []
    check_rows, check_errors = collect_ip_check_rows(sources)
    with get_conn() as conn:
        write_ip_check_rows(conn, source_id, check_rows, check_errors, "sync_check_ips", "同步源检测")
    results = []
    for target in targets:
        remote_ok = True
        remote_msg = "本地 SQLite 已同步；未配置远端执行器"
        if target["sync_webhook_url"]:
            remote_ok, remote_msg = post_webhook(
                target["sync_webhook_url"],
                {
                    "target": target["name"],
                    "source": source["name"],
                    "preferred_sources": sources,
                    "sources": [line for line in sources.splitlines() if line.strip()],
                },
                target["sync_webhook_token"],
            )
        elif target["sync_command"]:
            remote_ok, remote_msg = run_sync_command(target["sync_command"], target, sources)
        elif target["agent_token_hash"]:
            sync_id = secrets.token_urlsafe(16)
            remote_msg = f"已下发给 Agent，等待执行：{sync_id}"
        status = "done" if remote_ok else "failed"
        vps_status = "已同步" if remote_ok else "异常"
        with get_conn() as conn:
            if target["agent_token_hash"] and not target["sync_webhook_url"] and not target["sync_command"]:
                conn.execute(
                    """
                    update vps set
                      preferred_sources=?,
                      status='待执行',
                      last_sync_at=?,
                      last_sync_status=?,
                      pending_sync_id=?,
                      pending_sync_sources=?,
                      pending_sync_source_name=?,
                      pending_sync_status='pending',
                      pending_sync_message=?,
                      pending_sync_requested_at=?,
                      pending_sync_finished_at=0,
                      updated_at=?
                    where id=?
                    """,
                    (
                        sources,
                        now_ts(),
                        remote_msg,
                        sync_id,
                        sources,
                        source["name"],
                        remote_msg,
                        now_ts(),
                        now_ts(),
                        target["id"],
                    ),
                )
                status = "pending"
            else:
                conn.execute(
                    "update vps set preferred_sources=?,status=?,last_sync_at=?,last_sync_status=?,updated_at=? where id=?",
                    (sources, vps_status, now_ts(), remote_msg, now_ts(), target["id"]),
                )
            write_ip_check_rows(conn, target["id"], check_rows, check_errors, "sync_check_ips", "同步后源检测")
            conn.execute(
                "insert into tasks(vps_id,kind,status,message,created_at) values(?,?,?,?,?)",
                (target["id"], "sync_sources", status, f"{source['name']} -> {target['name']}：{remote_msg}", now_ts()),
            )
        results.append({"id": target["id"], "name": target["name"], "ok": remote_ok, "message": remote_msg})
    return {"ok": all(item["ok"] for item in results) if results else False, "results": results}
