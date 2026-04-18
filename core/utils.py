import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("GHOSTCRAWLER_DATA_DIR", str(PROJECT_ROOT / "data"))).resolve()
APP_ENV = os.getenv("GHOSTCRAWLER_ENV", "development").strip().lower()
TOR_SOCKS_HOST = os.getenv("GHOSTCRAWLER_TOR_SOCKS_HOST", "127.0.0.1").strip() or "127.0.0.1"
TOR_SOCKS_PORT = int(os.getenv("GHOSTCRAWLER_TOR_SOCKS_PORT", "9050"))
ENABLE_DEMO_CONTENT = os.getenv("GHOSTCRAWLER_ENABLE_DEMO_CONTENT", "true").strip().lower() in {"1", "true", "yes", "on"}
ENABLE_SEED_CATALOG = os.getenv("GHOSTCRAWLER_ENABLE_SEED_CATALOG", "true").strip().lower() in {"1", "true", "yes", "on"}


def tor_socks_url() -> str:
    return f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}"
