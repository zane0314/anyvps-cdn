import base64
import json
import os
import sqlite3
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import parse_qs, quote, urlencode, urlparse, urlunparse

from db import get_conn
from security import now_ts
from sources import clean_text, read_url

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
    SUBSTORE_BASE_URL = os.getenv("SUBSTORE_BASE_URL", "https://anyvps.240314.xyz/substore")

    # 生成订阅项名称：vps名称-类型 (如: yunyo-cdn)
    item_name = f"{vps_name.lower().replace(' ', '-')}-{source_type}"

    try:
        # 策略：先删除旧订阅（用正确的单数路径 /api/sub/），然后创建
        print(f"[SubStore] 处理订阅: {item_name}")

        config = {
            "name": item_name,
            "url": source_url,
            "icon": "",
            "ua": ""
        }
        encoded_name = quote(item_name, safe='')

        # 1. 删除现有订阅（正确路径是单数 /api/sub/）
        delete_req = urlrequest.Request(
            f"{SUBSTORE_API}/api/sub/{encoded_name}",
            headers={"Authorization": f"Bearer {SUBSTORE_TOKEN}"},
            method="DELETE",
        )
        try:
            with urlrequest.urlopen(delete_req, timeout=5) as resp:
                print(f"[SubStore] DELETE 状态码: {resp.status}")
        except urlerror.HTTPError as exc:
            print(f"[SubStore] DELETE 状态码: {exc.code}")

        # 2. 创建新订阅（POST 用复数 /api/subs）
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
