#!/usr/bin/env python3
import json
import os
import re
import socket
import sys
import time
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from datetime import datetime
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

MANAGER_URL = os.getenv("ANYVPS_MANAGER_URL", "__MANAGER_URL__")
VPS_ID = os.getenv("ANYVPS_VPS_ID", "")
AGENT_TOKEN = os.getenv("ANYVPS_AGENT_TOKEN", "")
LOCAL_SOURCE_FILE = os.getenv("ANYVPS_SOURCE_FILE", "")
LOCAL_REFRESH_COMMAND = os.getenv("ANYVPS_REFRESH_COMMAND", "")
LOCAL_VERIFY_URL = os.getenv("ANYVPS_VERIFY_URL", "")
SNAPSHOT_STATE_FILE = os.getenv("ANYVPS_SNAPSHOT_STATE_FILE", "/var/lib/anyvps-agent/last_snapshot_date")
MAX_SOURCE_LINES = 100
AGENT_SCAN_PATHS = ["/etc/nginx/nginx.conf", "/etc/nginx/conf.d", "/etc/x-ui", "/opt/x-ui", "/root/sub", "/root/cf-dynamic-sub", "/root/la-cdn-sub", "/root/jp-cdn-sub", "/root/yuntub-sub"]
SECRET_WORDS = re.compile(r"(pass|password|passwd|secret|key|uuid|private|credential)", re.I)
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
SERVER_NAME_RE = re.compile(r"\bserver_name\s+([^;]+);")
PATH_RE = re.compile(r"(?<![A-Za-z0-9])/(?:sub|subs|s/(?:cdn|default)|api/subs|download|sub/)[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]*")


__DETECT_COMMON__


def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)

def http_post(path, data):
    try:
        req = urllib.request.Request(
            f"{MANAGER_URL}{path}",
            data=json.dumps(data).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "AnyVPS-Agent/0.3"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        log(f"HTTP 请求失败: {e}")
        return None

def heartbeat():
    result = http_post("/api/agent/heartbeat", {"vps_id": VPS_ID, "agent_token": AGENT_TOKEN})
    if result and result.get("ok"):
        return True
    log("心跳失败")
    return False


def add_refresh_param(url):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query["refresh"] = ["1"]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))

def verify_url(url):
    if not url:
        return True, "未配置验证 URL"
    try:
        req = urllib.request.Request(add_refresh_param(url), headers={"User-Agent": "AnyVPS-Agent/0.2"})
        with urllib.request.urlopen(req, timeout=25) as resp:
            body = resp.read(300000)
            ok = resp.status < 400 and len(body) > 80
            return ok, f"验证 HTTP {resp.status} {len(body)} bytes"
    except Exception as e:
        return False, f"验证失败 {type(e).__name__}"

def clean_sources(raw):
    values = raw if isinstance(raw, list) else str(raw or "").splitlines()
    lines, seen = [], set()
    for value in values:
        line = str(value).replace("\x00", "").strip()
        if not line or line.startswith("#"):
            continue
        if len(line) > 500:
            raise ValueError("source_line_too_long")
        looks_url = line.startswith("http://") or line.startswith("https://")
        looks_endpoint = ":" in line and " " not in line and "/" not in line
        if not looks_url and not looks_endpoint:
            raise ValueError("unsupported_source_line")
        if any(mark in line for mark in ("`", "$(", "${", ";", "|", "&&", "||")):
            raise ValueError("shell_like_source_line")
        if line not in seen:
            seen.add(line)
            lines.append(line)
        if len(lines) > MAX_SOURCE_LINES:
            raise ValueError("too_many_sources")
    if not lines:
        raise ValueError("empty_sources")
    return lines

def detect_source_file():
    if LOCAL_SOURCE_FILE:
        return LOCAL_SOURCE_FILE
    candidates = [
        "/var/lib/la-cdn-sub/sources.json",
        "/var/lib/cf-dynamic-sub/sources.json",
        "/var/lib/jp-cdn-sub/sources.json",
        "/var/lib/yuntub-sub/sources.json",
        "/root/la-cdn-sub/sources.json",
        "/root/cf-dynamic-sub/sources.json",
        "/root/jp-cdn-sub/sources.json",
        "/root/yuntub-sub/sources.json",
    ]
    existing = [path for path in candidates if Path(path).exists()]
    if len(existing) == 1:
        return existing[0]
    for service in ("la-cdn-sub", "cf-dynamic-sub", "jp-cdn-sub", "yuntub-sub"):
        matches = [path for path in existing if service in path]
        if matches and subprocess.run(f"systemctl is-active --quiet {service}", shell=True).returncode == 0:
            return matches[0]
    return ""

def detect_refresh_command(source_file):
    if LOCAL_REFRESH_COMMAND:
        return LOCAL_REFRESH_COMMAND
    for service in ("la-cdn-sub", "cf-dynamic-sub", "jp-cdn-sub", "yuntub-sub"):
        if service in source_file and subprocess.run(f"systemctl is-active --quiet {service}", shell=True).returncode == 0:
            return f"systemctl restart {service}"
    return ""


def collect_snapshot():
    urls = collect_urls(collect_texts_targeted(AGENT_SCAN_PATHS))
    source_file = detect_source_file()
    return {
        "name": socket.gethostname(),
        "host_hint": public_ip(),
        "role": service_hint(),
        "admin_url": detect_admin_url() or first_url(urls, "admindav") or first_url(urls, "youxuan"),
        "health_url": first_url(urls, "health"),
        "xui_sub_url": pick_subscription(urls, "xui"),
        "combo_sub_url": pick_subscription(urls, "combo"),
        "cdn_sub_url": detect_cdn_sub_url() or pick_subscription(urls, "cdn"),
        "preferred_sources": detect_preferred_sources() or "\n".join([u for u in urls if ("bestcf" in u.lower() or "youxuan" in u.lower())][:20]),
        "agent_source_file": source_file,
        "agent_refresh_command": detect_refresh_command(source_file),
        "agent_verify_url": LOCAL_VERIFY_URL or pick_subscription(urls, "cdn") or pick_subscription(urls, "combo") or pick_subscription(urls, "xui"),
        "agent_version": "2026-07-13-daily-snapshot",
    }

def snapshot_once(reason="daily_0300"):
    payload = collect_snapshot()
    payload.update({"vps_id": VPS_ID, "agent_token": AGENT_TOKEN, "reason": reason})
    result = http_post("/api/agent/snapshot", payload)
    if result and result.get("ok"):
        log(f"快照回传成功: {reason}")
        return True
    log(f"快照回传失败: {reason}")
    return False

def read_last_snapshot_date():
    return read(SNAPSHOT_STATE_FILE, 100).strip()

def write_last_snapshot_date(value):
    path = Path(SNAPSHOT_STATE_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")

def encode_sources(path, lines):
    if path.endswith(".json"):
        return json.dumps(lines, ensure_ascii=False, indent=2) + "\n"
    return "\n".join(lines) + "\n"

def atomic_write(path, content):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        backup = target.with_suffix(target.suffix + f".bak-{int(time.time())}")
        try:
            backup.write_bytes(target.read_bytes())
        except Exception:
            pass
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=str(target.parent), delete=False) as tmp:
        tmp.write(content)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = Path(tmp.name)
    tmp_path.chmod(0o600)
    tmp_path.replace(target)

def run_refresh(command):
    if not command:
        return True, "未配置刷新命令"
    proc = subprocess.run(command, shell=True, text=True, capture_output=True, timeout=60)
    output = (proc.stdout + "\n" + proc.stderr).strip().replace("\n", " ")
    return proc.returncode == 0, f"刷新 exit {proc.returncode} {output[:180]}".strip()

def execute_task(task):
    source_file = LOCAL_SOURCE_FILE or task.get("source_file") or detect_source_file()
    if not source_file:
        raise RuntimeError("ANYVPS_SOURCE_FILE 未配置，且未自动识别到唯一源文件")
    lines = clean_sources(task.get("sources") or task.get("preferred_sources") or "")
    atomic_write(source_file, encode_sources(source_file, lines))
    refresh_ok, refresh_msg = run_refresh(LOCAL_REFRESH_COMMAND or task.get("refresh_command") or detect_refresh_command(source_file))
    verify_ok, verify_msg = verify_url(LOCAL_VERIFY_URL or task.get("verify_url") or "")
    ok = refresh_ok and verify_ok
    return {
        "ok": ok,
        "source_file": source_file,
        "line_count": len(lines),
        "message": f"{refresh_msg}；{verify_msg}",
    }

def poll_once():
    result = http_post("/api/agent/poll", {"vps_id": VPS_ID, "agent_token": AGENT_TOKEN})
    if not result or not result.get("ok"):
        return
    task = result.get("task")
    if not task:
        return
    sync_id = task.get("sync_id", "")
    log(f"收到同步任务 {sync_id}")
    try:
        report = execute_task(task)
    except Exception as e:
        report = {"ok": False, "message": f"{type(e).__name__}: {e}", "line_count": 0, "source_file": ""}
    report.update({"vps_id": VPS_ID, "agent_token": AGENT_TOKEN, "sync_id": sync_id})
    http_post("/api/agent/report", report)
    log(f"同步任务 {sync_id} 回报完成: {report.get('message')}")

def main():
    if not VPS_ID or not AGENT_TOKEN:
        log("错误: 未设置 ANYVPS_VPS_ID 或 ANYVPS_AGENT_TOKEN")
        sys.exit(1)
    log(f"Agent 启动，VPS ID: {VPS_ID}")
    last_heartbeat = 0
    while True:
        now = time.time()
        if now - last_heartbeat >= 300:
            heartbeat()
            last_heartbeat = now
        today = datetime.now().strftime("%Y-%m-%d")
        if datetime.now().hour == 3 and read_last_snapshot_date() != today:
            if snapshot_once("daily_0300"):
                write_last_snapshot_date(today)
        poll_once()
        time.sleep(60)

if __name__ == "__main__":
    if "--snapshot-now" in sys.argv:
        if not VPS_ID or not AGENT_TOKEN:
            log("错误: 未设置 ANYVPS_VPS_ID 或 ANYVPS_AGENT_TOKEN")
            sys.exit(1)
        sys.exit(0 if snapshot_once("manual_verify") else 1)
    main()
