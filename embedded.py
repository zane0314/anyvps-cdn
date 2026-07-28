"""Embedded script constants, assembled from scripts/ templates at import time.

scripts/detect_common.py is the single source of truth for the detect_*
helpers shared by the collector and agent scripts. Editing it updates
/install.sh output for both automatically.
"""

from pathlib import Path

from config import PUBLIC_URL

SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"

ROBOTS_TXT = """User-agent: *
Disallow: /

X-Robots-Tag: noindex, nofollow, noarchive
"""

REMOTE_COLLECTOR_SCRIPT = f"curl -fsSL {PUBLIC_URL}/install.sh | bash"


def _read(name: str) -> str:
    return (SCRIPTS_DIR / name).read_text(encoding="utf-8")


def _build_install_script() -> str:
    common = _read("detect_common.py").rstrip("\n")
    collector = _read("collector.py.tpl").replace("__DETECT_COMMON__", common).rstrip("\n")
    agent = _read("agent.py.tpl").replace("__DETECT_COMMON__", common).rstrip("\n")
    return (
        _read("install.sh.tpl")
        .replace("__COLLECTOR_PY__", collector)
        .replace("__AGENT_PY__", agent)
        .replace("__MANAGER_URL__", PUBLIC_URL)
    )


INSTALL_SCRIPT = _build_install_script()
WEBHOOK_RECEIVER_SCRIPT = _read("webhook_receiver.py")
