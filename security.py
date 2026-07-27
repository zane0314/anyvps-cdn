import base64
import hashlib
import hmac
import json
import secrets
import time

from config import LOGIN_MAX_FAILURES, LOGIN_WINDOW_SECONDS, SESSION_SECRET

LOGIN_FAILURES: dict[str, list[int]] = {}


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


def make_session(username: str) -> str:
    issued = str(now_ts())
    nonce = secrets.token_urlsafe(16)
    payload = base64.urlsafe_b64encode(f"{username}|{issued}|{nonce}".encode()).decode()
    secret = SESSION_SECRET or get_or_create_session_secret()
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def get_or_create_session_secret() -> str:
    from db import get_conn

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


def login_limited(client_ip: str) -> bool:
    cutoff = now_ts() - LOGIN_WINDOW_SECONDS
    failures = [ts for ts in LOGIN_FAILURES.get(client_ip, []) if ts >= cutoff]
    LOGIN_FAILURES[client_ip] = failures
    return len(failures) >= LOGIN_MAX_FAILURES


def record_login_failure(client_ip: str) -> None:
    cutoff = now_ts() - LOGIN_WINDOW_SECONDS
    failures = [ts for ts in LOGIN_FAILURES.get(client_ip, []) if ts >= cutoff]
    failures.append(now_ts())
    LOGIN_FAILURES[client_ip] = failures
