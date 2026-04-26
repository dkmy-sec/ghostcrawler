import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("GHOSTCRAWLER_DATA_DIR", str(PROJECT_ROOT / "data"))).resolve()
APP_ENV = os.getenv("GHOSTCRAWLER_ENV", "development").strip().lower()
TOR_SOCKS_HOST = os.getenv("GHOSTCRAWLER_TOR_SOCKS_HOST", "127.0.0.1").strip() or "127.0.0.1"
TOR_SOCKS_PORT = int(os.getenv("GHOSTCRAWLER_TOR_SOCKS_PORT", "9050"))
I2P_HTTP_PROXY = os.getenv("GHOSTCRAWLER_I2P_HTTP_PROXY", "http://127.0.0.1:4444").strip()
FREENET_GATEWAY_URL = os.getenv("GHOSTCRAWLER_FREENET_GATEWAY_URL", "http://127.0.0.1:8888").strip().rstrip("/")
DEFAULT_REQUEST_TIMEOUT = int(os.getenv("GHOSTCRAWLER_REQUEST_TIMEOUT_SECONDS", "20"))
CRAWL_CLEARNET_CROSS_HOST = os.getenv("GHOSTCRAWLER_CLEARNET_CROSS_HOST", "false").strip().lower() in {"1", "true", "yes", "on"}
ENABLE_DEMO_CONTENT = os.getenv("GHOSTCRAWLER_ENABLE_DEMO_CONTENT", "true").strip().lower() in {"1", "true", "yes", "on"}
ENABLE_SEED_CATALOG = os.getenv("GHOSTCRAWLER_ENABLE_SEED_CATALOG", "true").strip().lower() in {"1", "true", "yes", "on"}


def tor_socks_url() -> str:
    return f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}"


def i2p_http_proxy_url() -> str:
    return I2P_HTTP_PROXY


def freenet_gateway_url() -> str:
    return FREENET_GATEWAY_URL
