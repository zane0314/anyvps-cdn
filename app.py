#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sqlite3
import subprocess
import tempfile
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlencode, urlparse, urlunparse
from urllib import error as urlerror
from urllib import request as urlrequest


APP_NAME = "AnyVPS"
DATA_DIR = Path(os.environ.get("ANYVPS_DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "anyvps.db"
HOST = os.environ.get("ANYVPS_HOST", "0.0.0.0")
PORT = int(os.environ.get("ANYVPS_PORT", "8090"))
USERNAME = os.environ.get("ANYVPS_USERNAME", "admin")
PASSWORD = os.environ.get("ANYVPS_PASSWORD", "")
SESSION_SECRET = os.environ.get("ANYVPS_SESSION_SECRET", "")
PUBLIC_URL = os.environ.get("ANYVPS_PUBLIC_URL", "").rstrip("/")
LOGIN_FAILURES: dict[str, list[int]] = {}
LOGIN_WINDOW_SECONDS = 600
LOGIN_MAX_FAILURES = 5
SOURCE_FETCH_LIMIT = 300_000
IP_CHECK_LIMIT = 300
HTTP_TIMEOUT = 12
CONNECT_TIMEOUT = 2.5


ROBOTS_TXT = """User-agent: *
Disallow: /

X-Robots-Tag: noindex, nofollow, noarchive
"""


REMOTE_COLLECTOR_SCRIPT = r"""curl -fsSL __ANYVPS_PUBLIC_URL__/install.sh | bash"""

INSTALL_SCRIPT = r"""#!/bin/bash
# AnyVPS 一键部署脚本
set -e

MANAGER_URL="${MANAGER_URL:-__ANYVPS_PUBLIC_URL__}"
AGENT_PATH="/usr/local/bin/anyvps-agent"
SERVICE_PATH="/etc/systemd/system/anyvps-agent.service"
ANYVPS_SOURCE_FILE="${ANYVPS_SOURCE_FILE:-}"
ANYVPS_REFRESH_COMMAND="${ANYVPS_REFRESH_COMMAND:-}"
ANYVPS_VERIFY_URL="${ANYVPS_VERIFY_URL:-}"
export ANYVPS_SOURCE_FILE ANYVPS_REFRESH_COMMAND ANYVPS_VERIFY_URL

echo "==> AnyVPS 一键部署开始..."

# 1. 采集 VPS 信息
echo "==> 采集 VPS 信息..."
python3 <<'ANYVPS_COLLECTOR'
# AnyVPS 信息采集脚本
import json
import os
import re
import socket
import subprocess
from pathlib import Path


SECRET_WORDS = re.compile(r"(pass|password|passwd|secret|key|uuid|private|credential)", re.I)
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
SERVER_NAME_RE = re.compile(r"\bserver_name\s+([^;]+);")
PATH_RE = re.compile(r"(?<![A-Za-z0-9])/(?:sub|subs|s/(?:cdn|default)|api/subs|download|sub/)[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]*")


def sh(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=8).strip()
    except Exception:
        return ""


def read(path, limit=200000):
    try:
        return Path(path).read_text(errors="ignore")[:limit]
    except Exception:
        return ""


def public_ip():
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        out = sh(f"curl -fsSL --max-time 5 {url}")
        if out:
            return out.splitlines()[0].strip()
    return ""


def collect_texts():
    roots = [
        "/etc/nginx",
        "/etc/systemd/system",
        "/etc",
        "/root/data/docker_data",
        "/opt",
    ]
    texts = []
    for root in roots:
        p = Path(root)
        if not p.exists():
            continue
        for file in p.rglob("*"):
            if not file.is_file():
                continue
            name = str(file)
            if any(part in name for part in ("/.git/", "__pycache__", ".db", ".sqlite", ".key", ".pem")):
                continue
            try:
                if file.stat().st_size > 500000:
                    continue
            except Exception:
                continue
            text = read(file)
            if text:
                texts.append((name, text))
    return texts


def derive_urls(texts):
    hosts = []
    paths = []
    for _name, text in texts:
        for match in SERVER_NAME_RE.finditer(text):
            for host in match.group(1).split():
                host = host.strip()
                if not host or host in {"_", "localhost"} or "*" in host:
                    continue
                if "." in host and host not in hosts:
                    hosts.append(host)
        for path in PATH_RE.findall(text):
            clean = path.rstrip(");,")
            if len(clean) > 2 and clean not in paths:
                paths.append(clean)
    derived = []
    for host in hosts[:12]:
        for path in paths[:40]:
            derived.append(f"https://{host}{path}")
    return derived


def collect_urls():
    texts = collect_texts()
    urls = []
    seen = set()
    for _name, text in texts:
        for url in URL_RE.findall(text):
            clean = url.rstrip("),.;")
            if SECRET_WORDS.search(clean):
                continue
            if clean not in seen:
                seen.add(clean)
                urls.append(clean)
    for url in derive_urls(texts):
        if SECRET_WORDS.search(url):
            continue
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def first_url(urls, *needles):
    for url in urls:
        lower = url.lower()
        if all(n.lower() in lower for n in needles):
            return url
    return ""


def pick_subscription(urls, kind):
    preferred = {
        "xui": ("/sub/", "/sub?", "/sub", "xui", "3x"),
        "combo": ("/s/default", "/api/subs", "default", "combo", "all-in-one", "all"),
        "cdn": ("/s/cdn", "cdn", "refresh=1"),
    }[kind]
    for needle in preferred:
        found = first_url(urls, needle)
        if found:
            return found
    return ""


def service_hint():
    names = []
    for service in ("x-ui", "3x-ui", "nginx", "sing-box", "docker", "cf-dynamic-sub", "la-cdn-sub", "jp-cdn-sub", "yuntub-sub"):
        active = sh(f"systemctl is-active {service}")
        if active:
            names.append(f"{service}:{active}")
    return " · ".join(names)


urls = collect_urls()
host = socket.gethostname()
result = {
    "name": host,
    "host_hint": public_ip(),
    "role": service_hint(),
    "status": "待刷新",
    "admin_url": first_url(urls, "admindav") or first_url(urls, "youxuan"),
    "health_url": first_url(urls, "health"),
    "xui_sub_url": pick_subscription(urls, "xui"),
    "combo_sub_url": pick_subscription(urls, "combo"),
    "cdn_sub_url": pick_subscription(urls, "cdn"),
    "preferred_sources": "\n".join([u for u in urls if ("bestcf" in u.lower() or "youxuan" in u.lower() or u.endswith(".txt"))][:20]),
    "detected_urls": urls[:80],
}
print(json.dumps(result, ensure_ascii=False, indent=2))
ANYVPS_COLLECTOR

VPS_INFO=$(python3 <<'ANYVPS_COLLECTOR'
import json
import os
import re
import socket
import subprocess
from pathlib import Path

SECRET_WORDS = re.compile(r"(pass|password|passwd|secret|key|uuid|private|credential)", re.I)
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
SERVER_NAME_RE = re.compile(r"\bserver_name\s+([^;]+);")
PATH_RE = re.compile(r"(?<![A-Za-z0-9])/(?:sub|subs|s/(?:cdn|default)|api/subs|download|sub/)[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]*")

def sh(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=8).strip()
    except Exception:
        return ""

def read(path, limit=200000):
    try:
        return Path(path).read_text(errors="ignore")[:limit]
    except Exception:
        return ""

def public_ip():
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        out = sh(f"curl -fsSL --max-time 5 {url}")
        if out:
            return out.splitlines()[0].strip()
    return ""

def collect_texts():
    paths = ["/etc/nginx/nginx.conf", "/etc/nginx/conf.d", "/etc/x-ui", "/opt/x-ui", "/root/sub", "/root/cf-dynamic-sub", "/root/la-cdn-sub", "/root/jp-cdn-sub"]
    texts = []
    for p in paths:
        if not os.path.exists(p):
            continue
        if os.path.isfile(p):
            texts.append((p, read(p)))
        else:
            for entry in Path(p).rglob("*"):
                if entry.is_file() and entry.stat().st_size < 500_000:
                    texts.append((str(entry), read(str(entry))))
    return texts

def derive_urls(texts):
    hosts, paths = [], []
    for _name, text in texts:
        for m in SERVER_NAME_RE.finditer(text):
            for host in m.group(1).split():
                host = host.strip()
                if not host or host in {"_", "localhost"} or "*" in host:
                    continue
                if "." in host and host not in hosts:
                    hosts.append(host)
        for path in PATH_RE.findall(text):
            clean = path.rstrip(");,")
            if len(clean) > 2 and clean not in paths:
                paths.append(clean)
    derived = []
    for host in hosts[:12]:
        for path in paths[:40]:
            derived.append(f"https://{host}{path}")
    return derived

def collect_urls():
    texts = collect_texts()
    urls = []
    seen = set()
    for _name, text in texts:
        for url in URL_RE.findall(text):
            clean = url.rstrip("),.;")
            if SECRET_WORDS.search(clean):
                continue
            if clean not in seen:
                seen.add(clean)
                urls.append(clean)
    for url in derive_urls(texts):
        if SECRET_WORDS.search(url):
            continue
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls

def first_url(urls, *needles):
    for url in urls:
        lower = url.lower()
        if all(n.lower() in lower for n in needles):
            return url
    return ""

def pick_subscription(urls, kind):
    preferred = {
        "xui": ("/sub/", "/sub?", "/sub", "xui", "3x"),
        "combo": ("/s/default", "/api/subs", "default", "combo", "all-in-one", "all"),
        "cdn": ("/s/cdn", "cdn", "refresh=1"),
    }[kind]
    for needle in preferred:
        found = first_url(urls, needle)
        if found:
            return found
    return ""

def service_hint():
    names = []
    for service in ("x-ui", "3x-ui", "nginx", "sing-box", "docker"):
        active = sh(f"systemctl is-active {service}")
        if active == "active":
            names.append(service)
    return " · ".join(names) if names else "unknown"

def active_service(name):
    return sh(f"systemctl is-active {name}") == "active"

def detect_source_file():
    configured = os.getenv("ANYVPS_SOURCE_FILE", "").strip()
    if configured:
        return configured
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
        if matches and active_service(service):
            return matches[0]
    return ""

def detect_refresh_command(source_file):
    configured = os.getenv("ANYVPS_REFRESH_COMMAND", "").strip()
    if configured:
        return configured
    for service in ("la-cdn-sub", "cf-dynamic-sub", "jp-cdn-sub", "yuntub-sub"):
        if service in source_file and active_service(service):
            return f"systemctl restart {service}"
    return ""

def detect_verify_url(urls):
    configured = os.getenv("ANYVPS_VERIFY_URL", "").strip()
    if configured:
        return configured
    return pick_subscription(urls, "cdn") or pick_subscription(urls, "combo") or pick_subscription(urls, "xui")

urls = collect_urls()
host = socket.gethostname()
agent_source_file = detect_source_file()
result = {
    "name": host,
    "host_hint": public_ip(),
    "role": service_hint(),
    "status": "待刷新",
    "admin_url": first_url(urls, "admindav") or first_url(urls, "youxuan"),
    "health_url": first_url(urls, "health"),
    "xui_sub_url": pick_subscription(urls, "xui"),
    "combo_sub_url": pick_subscription(urls, "combo"),
    "cdn_sub_url": pick_subscription(urls, "cdn"),
    "preferred_sources": "\n".join([u for u in urls if ("bestcf" in u.lower() or "youxuan" in u.lower() or u.endswith(".txt"))][:20]),
    "agent_source_file": agent_source_file,
    "agent_refresh_command": detect_refresh_command(agent_source_file),
    "agent_verify_url": detect_verify_url(urls),
    "agent_version": "2026-07-07-sync-agent",
}
print(json.dumps(result, ensure_ascii=False, indent=2))
ANYVPS_COLLECTOR
)

if [ $? -ne 0 ]; then
    echo "✗ 采集 VPS 信息失败"
    exit 1
fi

echo "✓ VPS 信息采集完成"

# 2. 注册到管理端
echo "==> 注册到管理端..."
RESPONSE=$(curl -fsSL -X POST "$MANAGER_URL/api/register-vps" \
    -H "Content-Type: application/json" \
    -d "$VPS_INFO" 2>&1)

if [ $? -ne 0 ]; then
    echo "✗ 注册失败"
    exit 1
fi

VPS_ID=$(printf '%s' "$RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("vps_id",""))')
if [ -z "$VPS_ID" ]; then
    echo "✗ 注册失败: 未获取到 VPS ID"
    exit 1
fi
AGENT_TOKEN=$(printf '%s' "$RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("agent_token",""))')
if [ -z "$AGENT_TOKEN" ]; then
    echo "✗ 注册失败: 未获取到 Agent Token"
    exit 1
fi

echo "✓ 注册成功，VPS ID: $VPS_ID"

# 3. 部署 Agent 程序
echo "==> 部署 Agent 程序..."
cat > "$AGENT_PATH" <<'AGENT_EOF'
#!/usr/bin/env python3
import json
import os
import sys
import time
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from datetime import datetime
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

MANAGER_URL = os.getenv("ANYVPS_MANAGER_URL", "__ANYVPS_PUBLIC_URL__")
VPS_ID = os.getenv("ANYVPS_VPS_ID", "")
AGENT_TOKEN = os.getenv("ANYVPS_AGENT_TOKEN", "")
LOCAL_SOURCE_FILE = os.getenv("ANYVPS_SOURCE_FILE", "")
LOCAL_REFRESH_COMMAND = os.getenv("ANYVPS_REFRESH_COMMAND", "")
LOCAL_VERIFY_URL = os.getenv("ANYVPS_VERIFY_URL", "")
MAX_SOURCE_LINES = 100

def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)

def http_post(path, data):
    try:
        req = urllib.request.Request(f"{MANAGER_URL}{path}", data=json.dumps(data).encode(), headers={"Content-Type": "application/json"})
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
        poll_once()
        time.sleep(60)

if __name__ == "__main__":
    main()
AGENT_EOF

chmod +x "$AGENT_PATH"
echo "✓ Agent 程序已部署"

# 4. 创建 Systemd 服务
echo "==> 创建 Systemd 服务..."
cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=AnyVPS Agent
After=network.target

[Service]
Type=simple
Environment="ANYVPS_MANAGER_URL=$MANAGER_URL"
Environment="ANYVPS_VPS_ID=$VPS_ID"
Environment="ANYVPS_AGENT_TOKEN=$AGENT_TOKEN"
Environment="ANYVPS_SOURCE_FILE=$ANYVPS_SOURCE_FILE"
Environment="ANYVPS_REFRESH_COMMAND=$ANYVPS_REFRESH_COMMAND"
Environment="ANYVPS_VERIFY_URL=$ANYVPS_VERIFY_URL"
ExecStart=$AGENT_PATH
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable anyvps-agent
systemctl restart anyvps-agent

if systemctl is-active --quiet anyvps-agent; then
    echo "✓ Agent 服务已启动"
else
    echo "✗ Agent 服务启动失败"
    exit 1
fi

echo ""
echo "=========================================="
echo "✓ AnyVPS 部署完成！"
echo "=========================================="
echo "VPS ID: $VPS_ID"
echo "管理端: $MANAGER_URL"
echo "=========================================="
"""


def now_ts() -> int:
    return int(time.time())


def json_dumps(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 180_000)
    return "pbkdf2_sha256$180000$%s$%s" % (
        base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode(),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, rounds, salt_b64, digest_b64 = encoded.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds))
        return hmac.compare_digest(digest, expected)
    except Exception:
        return False


def hash_agent_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def verify_agent_token(token: str, token_hash: str) -> bool:
    if not token or not token_hash:
        return False
    return hmac.compare_digest(hash_agent_token(token), token_hash)


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
                        or name in ('洛杉矶 主控','云途 A','云途 B','圣何塞 CN2','凯撒斯')
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
    seen = set()
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
            if item["endpoint"] in seen:
                continue
            seen.add(item["endpoint"])
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


def add_refresh_param(url: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query["refresh"] = ["1"]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def add_no_cache_param(url: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query["noCache"] = ["true"]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def substore_verify_url(row: sqlite3.Row | dict, requested: str = "") -> str:
    return clean_text(requested) or row["substore_base64_url"] or row["substore_cdn_base64_url"] or row["substore_combo_base64_url"] or row["substore_xui_base64_url"]


def verify_subscription(url: str) -> dict:
    status, ctype, body = read_url(add_refresh_param(url))
    text = body[:500_000].decode("utf-8", "ignore")
    line_count = len([line for line in text.splitlines() if line.strip()])
    looks_yaml = "proxies:" in text or "proxy-groups:" in text
    looks_uri = any(proto in text for proto in ("vless://", "vmess://", "trojan://", "hysteria2://", "tuic://"))
    looks_base64 = False
    if not looks_yaml and not looks_uri and line_count <= 5:
        try:
            decoded = base64.b64decode("".join(text.split()), validate=False).decode("utf-8", "ignore")
            looks_base64 = any(proto in decoded for proto in ("vless://", "vmess://", "trojan://", "hysteria2://", "tuic://"))
            if looks_base64:
                line_count = len([line for line in decoded.splitlines() if line.strip()])
        except Exception:
            looks_base64 = False
    return {
        "status": status,
        "content_type": ctype,
        "bytes": len(body),
        "lines": line_count,
        "valid": status < 400 and (looks_yaml or looks_uri or looks_base64 or len(body) > 80),
    }


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


def upload_to_substore(vps_id: int, vps_name: str, source_type: str, source_url: str) -> dict:
    """
    上传订阅到 SubStore 并返回转换后的链接

    Args:
        vps_id: VPS ID
        vps_name: VPS 名称
        source_type: 订阅类型 (xui/combo/cdn)
        source_url: 原始订阅地址

    Returns:
        {
            "ok": True/False,
            "item_name": "订阅项名称",
            "urls": {
                "base64": "通用订阅链接",
                "mihomo": "Mihomo订阅链接",
                "surge": "Surge订阅链接",
                "singbox": "Sing-box订阅链接"
            }
        }
    """
    # SubStore 配置（从环境变量读取）
    SUBSTORE_API = os.getenv("SUBSTORE_API", "http://localhost:3001")
    SUBSTORE_TOKEN = os.getenv("SUBSTORE_TOKEN", "")
    SUBSTORE_BASE_URL = os.getenv("SUBSTORE_BASE_URL") or (f"{PUBLIC_URL}/substore" if PUBLIC_URL else "/substore")

    # 生成订阅项名称：vps名称-类型 (如: yunyo-cdn)
    item_name = f"{vps_name.lower().replace(' ', '-')}-{source_type}"

    try:
        # 策略：先删除旧订阅（如果存在），然后创建新的
        # 这样可以避免 SubStore API 的重复键和更新问题

        print(f"[SubStore] 处理订阅: {item_name}")

        # 1. 尝试删除现有订阅（URL 编码名称）
        encoded_name = quote(item_name, safe='')
        delete_req = urlrequest.Request(
            f"{SUBSTORE_API}/api/sub/{encoded_name}",
            headers={"Authorization": f"Bearer {SUBSTORE_TOKEN}"},
            method="DELETE",
        )
        try:
            with urlrequest.urlopen(delete_req, timeout=5) as resp:
                print(f"[SubStore] DELETE (encoded) 状态码: {resp.status}")
        except urlerror.HTTPError as exc:
            print(f"[SubStore] DELETE (encoded) 状态码: {exc.code}")

        # 2. 创建新订阅
        config = {
            "name": item_name,
            "url": source_url,
            "icon": "",
            "ua": ""
        }

        print(f"[SubStore] 创建订阅: {item_name}")
        post_req = urlrequest.Request(
            f"{SUBSTORE_API}/api/subs",
            data=json.dumps(config, ensure_ascii=False).encode(),
            headers={
                "Authorization": f"Bearer {SUBSTORE_TOKEN}",
                "Content-Type": "application/json"
            },
            method="POST",
        )
        try:
            with urlrequest.urlopen(post_req, timeout=5) as resp:
                post_status = resp.status
                post_text = resp.read(20_000).decode("utf-8", "ignore")
        except urlerror.HTTPError as exc:
            post_status = exc.code
            post_text = exc.read(20_000).decode("utf-8", "ignore")
        print(f"[SubStore] POST 状态码: {post_status}, 响应: {post_text[:200]}")

        if post_status not in [200, 201]:
            return {"ok": False, "error": f"创建订阅失败: HTTP {post_status}, {post_text[:100]}"}

        # 2. 生成各格式的转换链接
        urls = {
            "base64": f"{SUBSTORE_BASE_URL}/download/{encoded_name}",
            "mihomo": f"{SUBSTORE_BASE_URL}/download/{encoded_name}?target=Clash",
            "surge": f"{SUBSTORE_BASE_URL}/download/{encoded_name}?target=Surge&ver=4",
            "singbox": f"{SUBSTORE_BASE_URL}/download/{encoded_name}?target=SingBox"
        }

        verification = verify_subscription(add_no_cache_param(urls["base64"]))
        if not verification["valid"]:
            return {"ok": False, "error": "SubStore 已创建，但实时刷新验证失败"}

        # 3. 更新数据库（根据订阅类型更新对应字段）
        with get_conn() as conn:
            if source_type == "xui":
                conn.execute("""
                    UPDATE vps SET
                        substore_xui_base64_url = ?,
                        substore_xui_mihomo_url = ?,
                        substore_xui_surge_url = ?,
                        substore_xui_singbox_url = ?,
                        updated_at = ?
                    WHERE id = ?
                """, (
                    urls["base64"],
                    urls["mihomo"],
                    urls["surge"],
                    urls["singbox"],
                    now_ts(),
                    vps_id
                ))
            elif source_type == "combo":
                conn.execute("""
                    UPDATE vps SET
                        substore_combo_base64_url = ?,
                        substore_combo_mihomo_url = ?,
                        substore_combo_surge_url = ?,
                        substore_combo_singbox_url = ?,
                        updated_at = ?
                    WHERE id = ?
                """, (
                    urls["base64"],
                    urls["mihomo"],
                    urls["surge"],
                    urls["singbox"],
                    now_ts(),
                    vps_id
                ))
            elif source_type == "cdn":
                conn.execute("""
                    UPDATE vps SET
                        substore_cdn_base64_url = ?,
                        substore_cdn_mihomo_url = ?,
                        substore_cdn_surge_url = ?,
                        substore_cdn_singbox_url = ?,
                        updated_at = ?
                    WHERE id = ?
                """, (
                    urls["base64"],
                    urls["mihomo"],
                    urls["surge"],
                    urls["singbox"],
                    now_ts(),
                    vps_id
                ))

            # 同时保留旧字段的兼容性（指向最后上传的订阅）
            conn.execute("""
                UPDATE vps SET
                    substore_base64_url = ?,
                    substore_mihomo_url = ?,
                    substore_surge_url = ?,
                    substore_singbox_url = ?
                WHERE id = ?
            """, (
                urls["base64"],
                urls["mihomo"],
                urls["surge"],
                urls["singbox"],
                vps_id
            ))

        return {
            "ok": True,
            "item_name": item_name,
            "urls": urls,
            "verification": verification,
        }

    except Exception as e:
        import traceback
        error_detail = f"{type(e).__name__}: {str(e)}"
        print(f"SubStore 上传异常: {error_detail}")
        traceback.print_exc()
        return {"ok": False, "error": error_detail}


def make_session(username: str) -> str:
    issued = str(now_ts())
    nonce = secrets.token_urlsafe(16)
    payload = base64.urlsafe_b64encode(f"{username}|{issued}|{nonce}".encode()).decode()
    secret = SESSION_SECRET or get_or_create_session_secret()
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def get_or_create_session_secret() -> str:
    with get_conn() as conn:
        row = conn.execute("select value from settings where key='session_secret'").fetchone()
        if row:
            return row["value"]
        secret = secrets.token_urlsafe(48)
        conn.execute("insert into settings(key,value) values('session_secret',?)", (secret,))
        return secret


def read_session(token: str | None) -> str | None:
    if not token or "." not in token:
        return None
    payload, sig = token.rsplit(".", 1)
    secret = SESSION_SECRET or get_or_create_session_secret()
    expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        username, issued, _nonce = base64.urlsafe_b64decode(payload.encode()).decode().split("|", 2)
        if now_ts() - int(issued) > 86400 * 7:
            return None
        return username
    except Exception:
        return None


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

    def public_url(self) -> str:
        if PUBLIC_URL:
            return PUBLIC_URL
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or f"127.0.0.1:{PORT}"
        proto = self.headers.get("X-Forwarded-Proto") or ("https" if self.headers.get("X-Forwarded-SSL") == "on" else "http")
        return f"{proto}://{host}".rstrip("/")

    def render_public_url(self, text: str) -> str:
        return text.replace("__ANYVPS_PUBLIC_URL__", self.public_url())

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/healthz":
            return self.send_text("ok\n", "text/plain")
        if path == "/robots.txt":
            return self.send_text(ROBOTS_TXT, "text/plain")
        if path == "/install.sh":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            payload = self.render_public_url(INSTALL_SCRIPT).encode()
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
            payload = self.render_public_url(REMOTE_COLLECTOR_SCRIPT).encode()
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
        if path == "/api/agent/heartbeat":
            return self.handle_agent_heartbeat()
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
        if self.login_limited(client_ip):
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
        self.record_login_failure(client_ip)
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/login?error=1")
        self.end_headers()

    def client_ip(self) -> str:
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",", 1)[0].strip()
        return self.client_address[0]

    def login_limited(self, client_ip: str) -> bool:
        cutoff = now_ts() - LOGIN_WINDOW_SECONDS
        failures = [ts for ts in LOGIN_FAILURES.get(client_ip, []) if ts >= cutoff]
        LOGIN_FAILURES[client_ip] = failures
        return len(failures) >= LOGIN_MAX_FAILURES

    def record_login_failure(self, client_ip: str) -> None:
        cutoff = now_ts() - LOGIN_WINDOW_SECONDS
        failures = [ts for ts in LOGIN_FAILURES.get(client_ip, []) if ts >= cutoff]
        failures.append(now_ts())
        LOGIN_FAILURES[client_ip] = failures

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

        with get_conn() as conn:
            # 检查是否已存在相同名称或 IP 的 VPS
            existing = conn.execute(
                "select id from vps where name=? or host_hint=?",
                (name, host_hint)
            ).fetchone()

            if existing:
                # 已存在，更新信息
                vps_id = existing["id"]
                conn.execute("""
                    update vps set
                        role=?, admin_url=?, health_url=?,
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
                        name, role, status, admin_url, health_url,
                        xui_sub_url, combo_sub_url, cdn_sub_url,
                        preferred_sources, agent_token_hash, agent_source_file,
                        agent_refresh_command, agent_verify_url, agent_version,
                        updated_at
                    ) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    name,
                    clean_text(data.get("role", ""), 500),
                    "待刷新",
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

            # 更新最后上报时间
            conn.execute(
                "update vps set last_sync_at=? where id=?",
                (now_ts(), vps_id)
            )

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

    def handle_agent_poll(self):
        """Agent 拉取待执行的优选 IP 同步任务"""
        data = self.read_json()
        row = self.authorize_agent(data)
        if row is None:
            return self.send_json({"ok": False, "error": "unauthorized"})
        with get_conn() as conn:
            conn.execute("update vps set last_sync_at=? where id=?", (now_ts(), row["id"]))
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
      <div class="user-menu" id="userMenu"><div class="name" id="userName">admin</div><button id="logoutBtn">退出登录</button></div>
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
        <label>状态<select id="editStatus"><option>已同步</option><option>待刷新</option><option>异常</option></select></label>
        <label>优选管理页<input id="editAdmin"></label>
        <label>健康检查<input id="editHealth"></label>
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
      <div><h2>远端采集代码</h2><div class="modal-note">复制下面代码到新 VPS 执行，输出 JSON 后可粘贴到下方并填入当前 VPS。</div></div>
      <button class="modal-close" id="closeRemoteCode">×</button>
    </div>
    <textarea class="code-area" id="remoteCode" spellcheck="false" readonly></textarea>
    <div class="modal-copy">
      <button class="primary" id="copyRemoteCode">复制代码</button>
      <button class="secondary" id="applyRemoteResult">将采集结果填入当前 VPS</button>
    </div>
    <textarea class="result-area" id="remoteResult" spellcheck="false" placeholder="把新 VPS 执行后输出的 JSON 粘贴到这里"></textarea>
    <div class="modal-note">采集脚本会避开常见 password/token/key 字段；但粘贴结果前仍建议扫一眼，别把长期密钥带回管理页。</div>
  </div>
</div>
<div class="ctx" id="vpsContext">
  <button id="ctxEdit">编辑信息</button>
  <button class="danger" id="ctxDelete">删除 VPS</button>
</div>
<div class="mobile-user-sheet" id="mobileUser"><div class="name" id="mobileUserName">admin</div><button id="mobileLogout">退出登录</button></div>
<script>
let state=null, currentId=null, contextVpsId=null;
const $=s=>document.querySelector(s);
const statusDot=s=>s==="异常"?"err":(s==="待刷新"?"warn":"");
const money=v=>`${v.currency==="CNY"?"¥":"$"}${v.renewal_amount}/${v.renewal_period==="yearly"?"年":"月"}`;
const lineCount=v=>(v||"").split("\n").map(x=>x.trim()).filter(Boolean).length;
async function load(){state=await fetch("/api/state").then(r=>r.json()); normalizeCurrent(); $("#userName").textContent=state.username;$("#mobileUserName").textContent=state.username;render();}
function normalizeCurrent(){if(!state.vps.length){currentId=null;return} if(!state.vps.some(v=>v.id===currentId)) currentId=state.vps[0].id;}
function current(){normalizeCurrent(); return state.vps.find(v=>v.id===currentId)||state.vps[0]}
function fillForm(c){
 $("#editName").value=c.name||""; $("#editExpires").value=c.expires_at||"";
 $("#editRenewal").value=c.renewal_amount||""; $("#editCurrency").value=c.currency||"USD"; $("#editRenewalPeriod").value=c.renewal_period||"monthly"; $("#editBandwidth").value=c.bandwidth||""; $("#editTraffic").value=c.monthly_traffic||"";
 $("#editStatus").value=c.status||"待刷新"; $("#editAdmin").value=c.admin_url||""; $("#editHealth").value=c.health_url||"";
 $("#xuiUrl").value=c.xui_sub_url||""; $("#comboUrl").value=c.combo_sub_url||""; $("#cdnUrl").value=c.cdn_sub_url||""; $("#sources").value=c.preferred_sources||"";
}
function collectForm(){
 const c={...current()};
 c.name=$("#editName").value; c.expires_at=$("#editExpires").value; c.renewal_amount=$("#editRenewal").value;
 c.currency=$("#editCurrency").value; c.renewal_period=$("#editRenewalPeriod").value; c.bandwidth=$("#editBandwidth").value; c.monthly_traffic=$("#editTraffic").value; c.status=$("#editStatus").value; c.admin_url=$("#editAdmin").value;
 c.health_url=$("#editHealth").value;
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
 $("#vpsList").innerHTML=state.vps.map(v=>`<div class="vps-row ${v.id===currentId?"active":""}" data-id="${v.id}"><div class="vps-title"><span>${v.name}</span><small><i class="dot ${statusDot(v.status)}"></i>${v.status}</small></div><div class="meta">到期 ${v.expires_at||"-"} · 续费 ${money(v)} · ${v.monthly_traffic||"-"}</div></div>`).join("");
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
 $("#ipTotal").textContent=checks.length||lineCount(c.preferred_sources);
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
$("#remoteCodeBtn").onclick=async()=>{$("#remoteCodeModal").classList.add("open"); if(!$("#remoteCode").value)$("#remoteCode").value=await fetch("/api/remote-code").then(r=>r.text());};
$("#closeRemoteCode").onclick=()=>$("#remoteCodeModal").classList.remove("open");
$("#remoteCodeModal").onclick=e=>{if(e.target.id==="remoteCodeModal")$("#remoteCodeModal").classList.remove("open")};
$("#copyRemoteCode").onclick=()=>navigator.clipboard.writeText($("#remoteCode").value||"");
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


if __name__ == "__main__":
    if not PASSWORD:
        raise SystemExit("ANYVPS_PASSWORD is required")
    init_db()
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"AnyVPS listening on {HOST}:{PORT}")
    httpd.serve_forever()
