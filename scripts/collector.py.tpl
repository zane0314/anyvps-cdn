# AnyVPS 信息采集脚本
import json
import os
import re
import socket
import subprocess
from pathlib import Path

COLLECTOR_ROOTS = [
    "/etc/nginx",
    "/etc/systemd/system",
    "/etc",
    "/root/data/docker_data",
    "/opt",
]

__DETECT_COMMON__


urls = collect_urls(collect_texts_wide(COLLECTOR_ROOTS))
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