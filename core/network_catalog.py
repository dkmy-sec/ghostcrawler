from __future__ import annotations

from urllib.parse import urlparse


NETWORKS = {
    "tor": {"label": "Tor", "scope": "Dark Web", "collector": "tor_http", "supports_fetch": True},
    "i2p": {"label": "I2P", "scope": "Dark Web", "collector": "i2p_http", "supports_fetch": True},
    "freenet": {"label": "Freenet", "scope": "Dark Web", "collector": "freenet_http", "supports_fetch": True},
    "gnunet": {"label": "Gnunet", "scope": "Dark Web", "collector": "gnunet_native", "supports_fetch": False},
    "riffle": {"label": "Riffle", "scope": "Dark Web", "collector": "riffle_native", "supports_fetch": False},
    "zeronet": {"label": "ZeroNet", "scope": "Dark Web", "collector": "zeronet_http", "supports_fetch": False},
    "fossil": {"label": "Fossil", "scope": "Dark Web", "collector": "fossil_native", "supports_fetch": False},
    "lokinet": {"label": "Lokinet", "scope": "Dark Web", "collector": "lokinet_http", "supports_fetch": False},
    "clearnet": {"label": "Clear Net", "scope": "Clear Net", "collector": "http", "supports_fetch": True},
    "unknown": {"label": "Unknown", "scope": "All Sources", "collector": "manual", "supports_fetch": False},
}


NETWORK_HINTS = {
    ".onion": "tor",
    ".i2p": "i2p",
    "freenet:": "freenet",
    "USK@": "freenet",
    "SSK@": "freenet",
    "CHK@": "freenet",
    "KSK@": "freenet",
    "gnunet://": "gnunet",
    "riffle://": "riffle",
    "zeronet://": "zeronet",
    "fossil://": "fossil",
    ".loki": "lokinet",
}


FREENET_KEY_PREFIXES = ("usk@", "ssk@", "chk@", "ksk@")


def classify_network(url: str | None) -> str:
    if not url:
        return "unknown"

    lowered = url.strip().lower()
    for marker, network in NETWORK_HINTS.items():
        if marker.lower() in lowered:
            return network

    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = (parsed.netloc or parsed.path).lower()
    freenet_path = parsed.path.lstrip("/").lower()
    if ".onion" in host:
        return "tor"
    if ".i2p" in host:
        return "i2p"
    if freenet_path.startswith(FREENET_KEY_PREFIXES):
        return "freenet"
    if host:
        return "clearnet"
    return "unknown"


def network_metadata(network: str) -> dict:
    return NETWORKS.get(network, NETWORKS["unknown"])


def classify_scope(url: str | None) -> str:
    return network_metadata(classify_network(url)).get("scope", "All Sources")


def supports_fetch(url: str | None) -> bool:
    return bool(network_metadata(classify_network(url)).get("supports_fetch"))


def network_label(network: str) -> str:
    return network_metadata(network).get("label", network.title())
