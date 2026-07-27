"""Shared detection helpers for AnyVPS collector and agent scripts.

This file is the SINGLE source of truth. It is inlined into
collector.py.tpl / agent.py.tpl at server startup by embedded.py.
"""
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


def collect_urls(texts):
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


def collect_texts_wide(roots):
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


def collect_texts_targeted(paths):
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
