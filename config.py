import os
from pathlib import Path

APP_NAME = "AnyVPS"
DATA_DIR = Path(os.environ.get("ANYVPS_DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "anyvps.db"
HOST = os.environ.get("ANYVPS_HOST", "0.0.0.0")
PORT = int(os.environ.get("ANYVPS_PORT", "8090"))
USERNAME = os.environ.get("ANYVPS_USERNAME", "admin")
PASSWORD = os.environ.get("ANYVPS_PASSWORD", "")
SESSION_SECRET = os.environ.get("ANYVPS_SESSION_SECRET", "")
PUBLIC_URL = os.environ.get("ANYVPS_PUBLIC_URL", "https://anyvps.example.com").rstrip("/")
LOGIN_WINDOW_SECONDS = 600
LOGIN_MAX_FAILURES = 5
SOURCE_FETCH_LIMIT = 300_000
IP_CHECK_LIMIT = 300
HTTP_TIMEOUT = 12
CONNECT_TIMEOUT = 2.5
