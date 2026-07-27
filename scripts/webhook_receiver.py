#!/usr/bin/env python3
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
