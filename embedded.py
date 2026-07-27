ROBOTS_TXT = """User-agent: *
Disallow: /

X-Robots-Tag: noindex, nofollow, noarchive
"""


REMOTE_COLLECTOR_SCRIPT = r"""curl -fsSL https://anyvps.240314.xyz/install.sh | bash"""


INSTALL_SCRIPT = r"""#!/bin/bash
# AnyVPS 一键部署脚本
set -e

MANAGER_URL="${MANAGER_URL:-https://anyvps.240314.xyz}"
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


def detect_admin_url():
    # 从订阅服务配置构造优选管理页地址：
    # 扫描 /etc/*/state.json 取 admin_host，同目录 admin.env 取 *_ADMIN_PATH，
    # 拼成 https://{admin_host}/{admin_path}。适配不同 VPS 的不同服务名。
    import glob
    for state_path in sorted(glob.glob("/etc/*/state.json")):
        try:
            state = json.loads(read(state_path))
        except Exception:
            continue
        admin_host = str(state.get("admin_host", "")).strip()
        if not admin_host:
            continue
        admin_env = os.path.join(os.path.dirname(state_path), "admin.env")
        admin_path = ""
        for line in read(admin_env).splitlines():
            m = re.match(r'\s*[A-Z0-9_]*ADMIN_PATH\s*=\s*(.+)', line)
            if m:
                admin_path = m.group(1).strip().strip('"').strip("'")
                break
        if admin_path:
            return f"https://{admin_host}/{admin_path.lstrip('/')}"
        return f"https://{admin_host}"
    env_paths = sorted(set(
        glob.glob("/etc/*admin.env") + glob.glob("/etc/*/admin.env") +
        glob.glob("/etc/*.env") + glob.glob("/etc/*/*.env")
    ))
    for env_path in env_paths:
        public_sub_url = ""
        admin_path = ""
        for line in read(env_path).splitlines():
            m = re.match(r'\s*PUBLIC_SUB_URL\s*=\s*(.+)', line)
            if m:
                public_sub_url = m.group(1).strip().strip('"').strip("'")
            m = re.match(r'\s*[A-Z0-9_]*ADMIN_PATH\s*=\s*(.+)', line)
            if m:
                admin_path = m.group(1).strip().strip('"').strip("'")
        if public_sub_url.startswith("http") and admin_path:
            from urllib.parse import urlsplit
            parts = urlsplit(public_sub_url)
            if parts.scheme and parts.netloc:
                return f"{parts.scheme}://{parts.netloc}/{admin_path.lstrip('/')}"
    return ""

def detect_cdn_sub_url():
    # 从订阅服务配置获取 CDN 订阅地址（权威来源，含 ?refresh=1 等查询参数）：
    #   1. 扫 env 文件里的 PUBLIC_SUB_URL=（cf-dynamic-sub 结构，值即完整地址）
    #   2. 从 state.json 用 cdn_host + sub_path 拼接，并补 ?refresh=1（jp-cdn-sub 结构）
    # 都取不到返回空，由调用方回退到 grep 匹配
    import glob
    env_paths = sorted(set(
        glob.glob("/etc/*admin.env") + glob.glob("/etc/*/admin.env") +
        glob.glob("/etc/*.env") + glob.glob("/etc/*/*.env")
    ))
    for env_path in env_paths:
        for line in read(env_path).splitlines():
            m = re.match(r'\s*PUBLIC_SUB_URL\s*=\s*(.+)', line)
            if m:
                url = m.group(1).strip().strip('"').strip("'")
                if url.startswith("http"):
                    return url
    for state_path in sorted(glob.glob("/etc/*/state.json")):
        try:
            state = json.loads(read(state_path))
        except Exception:
            continue
        cdn_host = str(state.get("cdn_host", "")).strip()
        sub_path = str(state.get("sub_path", "")).strip()
        if cdn_host and sub_path:
            url = f"https://{cdn_host}/{sub_path.lstrip('/')}"
            if "refresh=" not in url:
                url += "?refresh=1"
            return url
    return ""

def detect_preferred_sources():
    # 读取订阅服务实际使用的优选源文件（CDN 正在用的源），权威回填。
    #   1. 从 systemd 服务配置读 SUB_SOURCE_FILE / ANYVPS_SOURCE_FILE 指定的路径
    #   2. 回退扫描 /var/lib/*/sources.json
    # 文件内容支持 JSON 数组或每行一个 URL；取不到返回空，由调用方回退到 grep。
    import glob
    env_paths = sorted(set(
        glob.glob("/etc/*admin.env") + glob.glob("/etc/*/admin.env") +
        glob.glob("/etc/*.env") + glob.glob("/etc/*/*.env")
    ))
    for env_path in env_paths:
        lines = []
        for line in read(env_path).splitlines():
            m = re.match(r'\s*(?:SOURCES|PREFERRED_SOURCES|PREFERRED_SOURCE_URLS|SOURCE_URLS)\s*=\s*(.+)', line)
            if not m:
                continue
            value = m.group(1).strip().strip('"').strip("'")
            for item in re.split(r'[\s,]+', value):
                item = item.strip().strip('"').strip("'")
                if item.startswith(("http://", "https://")):
                    lines.append(item)
        if lines:
            return "\n".join(lines[:100])
    candidates = []
    for svc_path in sorted(glob.glob("/etc/systemd/system/*.service")):
        for line in read(svc_path).splitlines():
            m = re.search(r'(?:SUB_SOURCE_FILE|ANYVPS_SOURCE_FILE)\s*=\s*(\S+)', line)
            if m:
                candidates.append(m.group(1).strip().strip('"').strip("'"))
    candidates += sorted(glob.glob("/var/lib/*/sources.json"))
    seen = set()
    for path in candidates:
        if not path or path in seen:
            continue
        seen.add(path)
        raw = read(path).strip()
        if not raw:
            continue
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                lines = [str(x).strip() for x in data if str(x).strip()]
            else:
                lines = [str(data).strip()]
        except Exception:
            lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        if lines:
            return "\n".join(lines[:20])
    return ""

urls = collect_urls()
host = socket.gethostname()
result = {
    "name": host,
    "host_hint": public_ip(),
    "role": service_hint(),
    "status": "待刷新",
    "admin_url": detect_admin_url() or first_url(urls, "admindav") or first_url(urls, "youxuan"),
    "health_url": first_url(urls, "health"),
    "xui_sub_url": pick_subscription(urls, "xui"),
    "combo_sub_url": pick_subscription(urls, "combo"),
    "cdn_sub_url": detect_cdn_sub_url() or pick_subscription(urls, "cdn"),
    "preferred_sources": detect_preferred_sources() or "\n".join([u for u in urls if ("bestcf" in u.lower() or "youxuan" in u.lower())][:20]),
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

def detect_admin_url():
    # 从订阅服务配置构造优选管理页地址：
    # 扫描 /etc/*/state.json 取 admin_host，同目录 admin.env 取 *_ADMIN_PATH，
    # 拼成 https://{admin_host}/{admin_path}。适配不同 VPS 的不同服务名。
    import glob
    for state_path in sorted(glob.glob("/etc/*/state.json")):
        try:
            state = json.loads(read(state_path))
        except Exception:
            continue
        admin_host = str(state.get("admin_host", "")).strip()
        if not admin_host:
            continue
        admin_env = os.path.join(os.path.dirname(state_path), "admin.env")
        admin_path = ""
        for line in read(admin_env).splitlines():
            m = re.match(r'\s*[A-Z0-9_]*ADMIN_PATH\s*=\s*(.+)', line)
            if m:
                admin_path = m.group(1).strip().strip('"').strip("'")
                break
        if admin_path:
            return f"https://{admin_host}/{admin_path.lstrip('/')}"
        return f"https://{admin_host}"
    env_paths = sorted(set(
        glob.glob("/etc/*admin.env") + glob.glob("/etc/*/admin.env") +
        glob.glob("/etc/*.env") + glob.glob("/etc/*/*.env")
    ))
    for env_path in env_paths:
        public_sub_url = ""
        admin_path = ""
        for line in read(env_path).splitlines():
            m = re.match(r'\s*PUBLIC_SUB_URL\s*=\s*(.+)', line)
            if m:
                public_sub_url = m.group(1).strip().strip('"').strip("'")
            m = re.match(r'\s*[A-Z0-9_]*ADMIN_PATH\s*=\s*(.+)', line)
            if m:
                admin_path = m.group(1).strip().strip('"').strip("'")
        if public_sub_url.startswith("http") and admin_path:
            from urllib.parse import urlsplit
            parts = urlsplit(public_sub_url)
            if parts.scheme and parts.netloc:
                return f"{parts.scheme}://{parts.netloc}/{admin_path.lstrip('/')}"
    return ""

def detect_cdn_sub_url():
    # 从订阅服务配置获取 CDN 订阅地址（权威来源，含 ?refresh=1 等查询参数）：
    #   1. 扫 env 文件里的 PUBLIC_SUB_URL=（cf-dynamic-sub 结构，值即完整地址）
    #   2. 从 state.json 用 cdn_host + sub_path 拼接，并补 ?refresh=1（jp-cdn-sub 结构）
    # 都取不到返回空，由调用方回退到 grep 匹配
    import glob
    env_paths = sorted(set(
        glob.glob("/etc/*admin.env") + glob.glob("/etc/*/admin.env") +
        glob.glob("/etc/*.env") + glob.glob("/etc/*/*.env")
    ))
    for env_path in env_paths:
        for line in read(env_path).splitlines():
            m = re.match(r'\s*PUBLIC_SUB_URL\s*=\s*(.+)', line)
            if m:
                url = m.group(1).strip().strip('"').strip("'")
                if url.startswith("http"):
                    return url
    for state_path in sorted(glob.glob("/etc/*/state.json")):
        try:
            state = json.loads(read(state_path))
        except Exception:
            continue
        cdn_host = str(state.get("cdn_host", "")).strip()
        sub_path = str(state.get("sub_path", "")).strip()
        if cdn_host and sub_path:
            url = f"https://{cdn_host}/{sub_path.lstrip('/')}"
            if "refresh=" not in url:
                url += "?refresh=1"
            return url
    return ""

def detect_preferred_sources():
    # 读取订阅服务实际使用的优选源文件（CDN 正在用的源），权威回填。
    #   1. 从 systemd 服务配置读 SUB_SOURCE_FILE / ANYVPS_SOURCE_FILE 指定的路径
    #   2. 回退扫描 /var/lib/*/sources.json
    # 文件内容支持 JSON 数组或每行一个 URL；取不到返回空，由调用方回退到 grep。
    import glob
    env_paths = sorted(set(
        glob.glob("/etc/*admin.env") + glob.glob("/etc/*/admin.env") +
        glob.glob("/etc/*.env") + glob.glob("/etc/*/*.env")
    ))
    for env_path in env_paths:
        lines = []
        for line in read(env_path).splitlines():
            m = re.match(r'\s*(?:SOURCES|PREFERRED_SOURCES|PREFERRED_SOURCE_URLS|SOURCE_URLS)\s*=\s*(.+)', line)
            if not m:
                continue
            value = m.group(1).strip().strip('"').strip("'")
            for item in re.split(r'[\s,]+', value):
                item = item.strip().strip('"').strip("'")
                if item.startswith(("http://", "https://")):
                    lines.append(item)
        if lines:
            return "\n".join(lines[:100])
    candidates = []
    for svc_path in sorted(glob.glob("/etc/systemd/system/*.service")):
        for line in read(svc_path).splitlines():
            m = re.search(r'(?:SUB_SOURCE_FILE|ANYVPS_SOURCE_FILE)\s*=\s*(\S+)', line)
            if m:
                candidates.append(m.group(1).strip().strip('"').strip("'"))
    candidates += sorted(glob.glob("/var/lib/*/sources.json"))
    seen = set()
    for path in candidates:
        if not path or path in seen:
            continue
        seen.add(path)
        raw = read(path).strip()
        if not raw:
            continue
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                lines = [str(x).strip() for x in data if str(x).strip()]
            else:
                lines = [str(data).strip()]
        except Exception:
            lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        if lines:
            return "\n".join(lines[:20])
    return ""

urls = collect_urls()
host = socket.gethostname()
agent_source_file = detect_source_file()
result = {
    "name": host,
    "host_hint": public_ip(),
    "role": service_hint(),
    "status": "待刷新",
    "admin_url": detect_admin_url() or first_url(urls, "admindav") or first_url(urls, "youxuan"),
    "health_url": first_url(urls, "health"),
    "xui_sub_url": pick_subscription(urls, "xui"),
    "combo_sub_url": pick_subscription(urls, "combo"),
    "cdn_sub_url": detect_cdn_sub_url() or pick_subscription(urls, "cdn"),
    "preferred_sources": detect_preferred_sources() or "\n".join([u for u in urls if ("bestcf" in u.lower() or "youxuan" in u.lower())][:20]),
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

MANAGER_URL = os.getenv("ANYVPS_MANAGER_URL", "https://anyvps.240314.xyz")
VPS_ID = os.getenv("ANYVPS_VPS_ID", "")
AGENT_TOKEN = os.getenv("ANYVPS_AGENT_TOKEN", "")
LOCAL_SOURCE_FILE = os.getenv("ANYVPS_SOURCE_FILE", "")
LOCAL_REFRESH_COMMAND = os.getenv("ANYVPS_REFRESH_COMMAND", "")
LOCAL_VERIFY_URL = os.getenv("ANYVPS_VERIFY_URL", "")
SNAPSHOT_STATE_FILE = os.getenv("ANYVPS_SNAPSHOT_STATE_FILE", "/var/lib/anyvps-agent/last_snapshot_date")
MAX_SOURCE_LINES = 100
SECRET_WORDS = re.compile(r"(pass|password|passwd|secret|key|uuid|private|credential)", re.I)
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
SERVER_NAME_RE = re.compile(r"\bserver_name\s+([^;]+);")
PATH_RE = re.compile(r"(?<![A-Za-z0-9])/(?:sub|subs|s/(?:cdn|default)|api/subs|download|sub/)[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]*")

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
    paths = ["/etc/nginx/nginx.conf", "/etc/nginx/conf.d", "/etc/x-ui", "/opt/x-ui", "/root/sub", "/root/cf-dynamic-sub", "/root/la-cdn-sub", "/root/jp-cdn-sub", "/root/yuntub-sub"]
    texts = []
    for p in paths:
        if not os.path.exists(p):
            continue
        if os.path.isfile(p):
            texts.append((p, read(p)))
        else:
            for entry in Path(p).rglob("*"):
                try:
                    if entry.is_file() and entry.stat().st_size < 500_000:
                        texts.append((str(entry), read(str(entry))))
                except OSError:
                    pass
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
    return [f"https://{host}{path}" for host in hosts[:12] for path in paths[:40]]

def collect_urls():
    texts = collect_texts()
    urls, seen = [], set()
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

def active_service(name):
    return sh(f"systemctl is-active {name}") == "active"

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

def detect_admin_url():
    for state_path in sorted(Path("/etc").glob("*/state.json")):
        try:
            state = json.loads(read(state_path))
        except Exception:
            continue
        admin_host = str(state.get("admin_host", "")).strip()
        if not admin_host:
            continue
        admin_env = state_path.parent / "admin.env"
        admin_path = ""
        for line in read(admin_env).splitlines():
            m = re.match(r'\s*[A-Z0-9_]*ADMIN_PATH\s*=\s*(.+)', line)
            if m:
                admin_path = m.group(1).strip().strip('"').strip("'")
                break
        return f"https://{admin_host}/{admin_path.lstrip('/')}" if admin_path else f"https://{admin_host}"
    env_paths = sorted(set(
        list(Path("/etc").glob("*admin.env")) +
        list(Path("/etc").glob("*/admin.env")) +
        list(Path("/etc").glob("*.env")) +
        list(Path("/etc").glob("*/*.env"))
    ))
    for env_path in env_paths:
        public_sub_url = ""
        admin_path = ""
        for line in read(env_path).splitlines():
            m = re.match(r'\s*PUBLIC_SUB_URL\s*=\s*(.+)', line)
            if m:
                public_sub_url = m.group(1).strip().strip('"').strip("'")
            m = re.match(r'\s*[A-Z0-9_]*ADMIN_PATH\s*=\s*(.+)', line)
            if m:
                admin_path = m.group(1).strip().strip('"').strip("'")
        if public_sub_url.startswith("http") and admin_path:
            from urllib.parse import urlsplit
            parts = urlsplit(public_sub_url)
            if parts.scheme and parts.netloc:
                return f"{parts.scheme}://{parts.netloc}/{admin_path.lstrip('/')}"
    return ""

def detect_cdn_sub_url():
    env_paths = sorted(set(
        list(Path("/etc").glob("*admin.env")) +
        list(Path("/etc").glob("*/admin.env")) +
        list(Path("/etc").glob("*.env")) +
        list(Path("/etc").glob("*/*.env"))
    ))
    for env_path in env_paths:
        for line in read(env_path).splitlines():
            m = re.match(r'\s*PUBLIC_SUB_URL\s*=\s*(.+)', line)
            if m:
                url = m.group(1).strip().strip('"').strip("'")
                if url.startswith("http"):
                    return url
    for state_path in sorted(Path("/etc").glob("*/state.json")):
        try:
            state = json.loads(read(state_path))
        except Exception:
            continue
        cdn_host = str(state.get("cdn_host", "")).strip()
        sub_path = str(state.get("sub_path", "")).strip()
        if cdn_host and sub_path:
            url = f"https://{cdn_host}/{sub_path.lstrip('/')}"
            return url if "refresh=" in url else f"{url}?refresh=1"
    return ""

def detect_preferred_sources():
    env_paths = sorted(set(
        list(Path("/etc").glob("*admin.env")) +
        list(Path("/etc").glob("*/admin.env")) +
        list(Path("/etc").glob("*.env")) +
        list(Path("/etc").glob("*/*.env"))
    ))
    for env_path in env_paths:
        lines = []
        for line in read(env_path).splitlines():
            m = re.match(r'\s*(?:SOURCES|PREFERRED_SOURCES|PREFERRED_SOURCE_URLS|SOURCE_URLS)\s*=\s*(.+)', line)
            if not m:
                continue
            value = m.group(1).strip().strip('"').strip("'")
            for item in re.split(r'[\s,]+', value):
                item = item.strip().strip('"').strip("'")
                if item.startswith(("http://", "https://")):
                    lines.append(item)
        if lines:
            return "\n".join(lines[:100])
    candidates = []
    for svc_path in sorted(Path("/etc/systemd/system").glob("*.service")):
        for line in read(svc_path).splitlines():
            m = re.search(r'(?:SUB_SOURCE_FILE|ANYVPS_SOURCE_FILE)\s*=\s*(\S+)', line)
            if m:
                candidates.append(m.group(1).strip().strip('"').strip("'"))
    candidates += [str(path) for path in sorted(Path("/var/lib").glob("*/sources.json"))]
    seen = set()
    for path in candidates:
        if not path or path in seen:
            continue
        seen.add(path)
        raw = read(path).strip()
        if not raw:
            continue
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                lines = [str(x).strip() for x in data if str(x).strip()]
            else:
                lines = [str(data).strip()]
        except Exception:
            lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        if lines:
            return "\n".join(lines[:100])
    return ""

def collect_snapshot():
    urls = collect_urls()
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

# 5. 部署 Webhook 接收器
echo "==> 部署 Webhook 接收器..."
curl -fsSL -o /usr/local/bin/anyvps-webhook-receiver.py "$MANAGER_URL/vps-webhook-receiver.py"
chmod +x /usr/local/bin/anyvps-webhook-receiver.py

# 5.0 探测本机订阅服务：找到 sources.json 及其对应的 systemd 服务名
echo "==> 探测订阅服务..."
DETECTED_SOURCE_FILE=""
DETECTED_SERVICE=""
for f in /var/lib/*/sources.json; do
    [ -f "$f" ] || continue
    DETECTED_SOURCE_FILE="$f"
    dir_name=$(basename "$(dirname "$f")")
    # 验证同名 systemd 服务存在
    if systemctl list-unit-files "${dir_name}.service" >/dev/null 2>&1 && \
       systemctl cat "${dir_name}.service" >/dev/null 2>&1; then
        DETECTED_SERVICE="$dir_name"
    fi
    break
done
if [ -n "$DETECTED_SOURCE_FILE" ]; then
    echo "✓ 探测到源文件: $DETECTED_SOURCE_FILE"
    echo "✓ 探测到服务名: ${DETECTED_SERVICE:-（未匹配到服务，接收器将按目录名推断）}"
else
    echo "· 未探测到 /var/lib/*/sources.json，接收器将在运行时自动扫描"
fi

cat > /etc/systemd/system/anyvps-webhook.service <<WEBHOOK_EOF
[Unit]
Description=AnyVPS Webhook Receiver
After=network.target

[Service]
Type=simple
Environment="ANYVPS_SOURCE_FILE=${DETECTED_SOURCE_FILE}"
Environment="ANYVPS_RESTART_SERVICE=${DETECTED_SERVICE}"
ExecStart=/usr/bin/python3 /usr/local/bin/anyvps-webhook-receiver.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
WEBHOOK_EOF

systemctl daemon-reload
systemctl enable anyvps-webhook
systemctl restart anyvps-webhook

if systemctl is-active --quiet anyvps-webhook; then
    echo "✓ Webhook 接收器已启动 (端口 18964)"
else
    echo "✗ Webhook 接收器启动失败"
fi

# 5.1 自动放行 18964 端口
echo "==> 放行 18964 端口..."
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow 18964/tcp >/dev/null 2>&1 && echo "✓ ufw 已放行 18964/tcp"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port=18964/tcp >/dev/null 2>&1
    firewall-cmd --reload >/dev/null 2>&1 && echo "✓ firewalld 已放行 18964/tcp"
elif command -v iptables >/dev/null 2>&1; then
    if ! iptables -C INPUT -p tcp --dport 18964 -j ACCEPT >/dev/null 2>&1; then
        iptables -I INPUT -p tcp --dport 18964 -j ACCEPT >/dev/null 2>&1 && echo "✓ iptables 已放行 18964/tcp"
    else
        echo "✓ iptables 规则已存在"
    fi
    command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
else
    echo "· 未检测到活动防火墙，跳过（如有云平台安全组请手动放行 18964）"
fi

# 6. 自动配置 Webhook URL 到管理端
echo "==> 自动配置 Webhook URL..."
PUBLIC_IP=$(printf '%s' "$VPS_INFO" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("host_hint",""))')
WEBHOOK_URL="http://${PUBLIC_IP}:18964/webhook"
curl -fsSL -X POST "$MANAGER_URL/api/set-webhook" \
    -H "Content-Type: application/json" \
    -d "{\"vps_id\":$VPS_ID,\"sync_webhook_url\":\"$WEBHOOK_URL\"}" >/dev/null 2>&1
echo "✓ Webhook URL 已配置: $WEBHOOK_URL"

echo ""
echo "=========================================="
echo "✓ AnyVPS 部署完成！"
echo "=========================================="
echo "VPS ID: $VPS_ID"
echo "管理端: $MANAGER_URL"
echo "Webhook URL: $WEBHOOK_URL"
echo "=========================================="
"""


WEBHOOK_RECEIVER_SCRIPT = r'''#!/usr/bin/env python3
"""
AnyVPS Webhook 接收器
部署在 VPS 上，接收优选 IP 源更新通知
写入订阅服务的 sources.json 并重启对应服务

配置来源（优先级从高到低）：
  1. 环境变量 ANYVPS_SOURCE_FILE / ANYVPS_RESTART_SERVICE（安装时自动探测写入）
  2. 运行时自动探测 /var/lib/*/sources.json 及对应 systemd 服务
"""
import glob
import json
import os
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path


PORT = 18964


def detect_source_file():
    """自动探测 sources.json：优先环境变量，否则扫描 /var/lib/*/sources.json"""
    env = os.getenv("ANYVPS_SOURCE_FILE", "").strip()
    if env:
        return env
    candidates = sorted(glob.glob("/var/lib/*/sources.json"))
    return candidates[0] if candidates else "/var/lib/jp-cdn-sub/sources.json"


def detect_service(source_file):
    """自动探测要重启的服务名：优先环境变量，否则从源文件所在目录名推断"""
    env = os.getenv("ANYVPS_RESTART_SERVICE", "").strip()
    if env:
        return env
    # /var/lib/jp-cdn-sub/sources.json -> jp-cdn-sub
    name = Path(source_file).parent.name
    return name or "jp-cdn-sub"


SOURCE_FILE = detect_source_file()
SERVICE_TO_RESTART = detect_service(SOURCE_FILE)


class WebhookHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {format % args}")

    def do_POST(self):
        if self.path != "/webhook":
            self.send_error(404)
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")

        try:
            data = json.loads(body)
            preferred_sources = data.get("preferred_sources", "")

            if not preferred_sources:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"ok": false, "error": "preferred_sources is empty"}')
                return

            # 解析优选源为 URL 列表（每行一个）
            urls = [line.strip() for line in preferred_sources.splitlines() if line.strip()]

            # 写入 sources.json（JSON 数组格式，jp-cdn-sub 期望的格式）
            Path(SOURCE_FILE).parent.mkdir(parents=True, exist_ok=True)
            Path(SOURCE_FILE).write_text(json.dumps(urls, ensure_ascii=False), encoding="utf-8")
            print(f"✓ 优选源已写入 {SOURCE_FILE}: {len(urls)} 个 URL")

            # 重启 jp-cdn-sub 服务
            restarted = False
            try:
                result = subprocess.run(
                    ["systemctl", "restart", SERVICE_TO_RESTART],
                    capture_output=True, timeout=15
                )
                if result.returncode == 0:
                    restarted = True
                    print(f"✓ 服务已重启: {SERVICE_TO_RESTART}")
                else:
                    print(f"✗ 服务重启失败: {result.stderr.decode()}")
            except Exception as e:
                print(f"✗ 重启服务异常: {e}")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response = {
                "ok": True,
                "message": "优选源已更新",
                "file": SOURCE_FILE,
                "count": len(urls),
                "restarted": restarted
            }
            self.wfile.write(json.dumps(response).encode("utf-8"))

        except Exception as e:
            print(f"✗ 处理失败: {e}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(json.dumps({"ok": False, "error": str(e)}).encode("utf-8"))

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_error(404)


def main():
    server = HTTPServer(("0.0.0.0", PORT), WebhookHandler)
    print(f"==> AnyVPS Webhook 接收器启动")
    print(f"==> 监听端口: {PORT}")
    print(f"==> 源文件: {SOURCE_FILE}")
    print(f"==> 重启服务: {SERVICE_TO_RESTART}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n==> 服务停止")


if __name__ == "__main__":
    main()
'''
