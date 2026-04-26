from __future__ import annotations

import argparse
import json
import socket
from urllib.parse import urlsplit

import requests

from core.connectors import connector_status_frame, supports_fetch
from core.crawler import crawl_target
from core.utils import DEFAULT_REQUEST_TIMEOUT, freenet_gateway_url, i2p_http_proxy_url, tor_socks_url


def check_tcp_endpoint(address: str) -> dict:
    parsed = urlsplit(address if "://" in address else f"tcp://{address}")
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 0
    result = {"target": f"{host}:{port}", "ok": False}
    try:
        with socket.create_connection((host, port), timeout=5):
            result["ok"] = True
    except OSError as exc:
        result["error"] = str(exc)
    return result


def check_http_endpoint(url: str) -> dict:
    result = {"target": url, "ok": False}
    session = requests.Session()
    session.trust_env = False
    try:
        response = session.get(url, timeout=min(DEFAULT_REQUEST_TIMEOUT, 10), allow_redirects=True)
        result["ok"] = True
        result["status_code"] = response.status_code
    except requests.RequestException as exc:
        result["error"] = str(exc)
    return result


def crawl_smoke(url: str | None) -> dict | None:
    if not url:
        return None
    if not supports_fetch(url):
        return {"url": url, "ok": False, "error": "connector_not_supported"}
    result = crawl_target(url, depth=0, max_depth=0)
    return {
        "url": url,
        "ok": not bool(result.get("error")),
        "network": result.get("network"),
        "connector": result.get("connector"),
        "error": result.get("error"),
        "found_links": len(result.get("found_links", [])),
        "snapshot_file": result.get("snapshot_file"),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check Ghostcrawler network connectors and optional smoke targets.")
    parser.add_argument("--tor-url", help="Optional .onion URL to smoke-test through Tor.")
    parser.add_argument("--i2p-url", help="Optional .i2p URL to smoke-test through I2P.")
    parser.add_argument("--freenet-url", help="Optional Freenet URI to smoke-test through the Freenet gateway.")
    parser.add_argument("--clearnet-url", help="Optional clearnet URL to smoke-test with the standard HTTP connector.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = {
        "connectors": connector_status_frame(),
        "transport_checks": {
            "tor": check_tcp_endpoint(tor_socks_url()),
            "i2p": check_http_endpoint(i2p_http_proxy_url()),
            "freenet": check_http_endpoint(freenet_gateway_url()),
        },
        "crawl_smoke": {},
    }

    optional_targets = {
        "tor": args.tor_url,
        "i2p": args.i2p_url,
        "freenet": args.freenet_url,
        "clearnet": args.clearnet_url,
    }
    for network, url in optional_targets.items():
        smoke = crawl_smoke(url)
        if smoke is not None:
            report["crawl_smoke"][network] = smoke

    print(json.dumps(report, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
