from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup

try:
    from core.network_catalog import NETWORKS, classify_network
    from core.url_intake import canonical_freenet_key, canonical_freenet_url, normalize_fetchable_url
    from core.utils import (
        CRAWL_CLEARNET_CROSS_HOST,
        DEFAULT_REQUEST_TIMEOUT,
        freenet_gateway_url,
        i2p_http_proxy_url,
        tor_socks_url,
    )
except ImportError:
    from network_catalog import NETWORKS, classify_network
    from url_intake import canonical_freenet_key, canonical_freenet_url, normalize_fetchable_url
    from utils import (
        CRAWL_CLEARNET_CROSS_HOST,
        DEFAULT_REQUEST_TIMEOUT,
        freenet_gateway_url,
        i2p_http_proxy_url,
        tor_socks_url,
    )

USER_AGENT = "Ghostcrawler/1.0"


@dataclass
class FetchResult:
    url: str
    network: str
    html: str | None = None
    text: str | None = None
    links: list[str] | None = None
    error: str | None = None
    connector: str | None = None


def build_session(*, proxies: dict[str, str] | None = None) -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": USER_AGENT})
    if proxies:
        session.proxies.update(proxies)
    return session


def html_to_text(html: str) -> str:
    return BeautifulSoup(html, "html.parser").get_text(" ", strip=True)


def split_host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def should_keep_http_link(base_url: str, full_url: str, network: str, *, same_host_only: bool) -> bool:
    if classify_network(full_url) != network:
        return False
    if not same_host_only:
        return True
    return split_host(base_url) == split_host(full_url)


def freenet_fetch_url(url: str) -> str:
    key = canonical_freenet_key(url)
    if not key:
        return url.strip()
    return f"{freenet_gateway_url()}/{key}"


def normalize_http_child_link(base_url: str, href: str) -> str:
    return urljoin(base_url, href)


def normalize_freenet_child_link(base_url: str, href: str) -> str | None:
    raw = (href or "").strip()
    if not raw:
        return None
    if raw.startswith(("#", "mailto:", "javascript:")):
        return None

    gateway_base = f"{freenet_gateway_url()}/"
    full_url = urljoin(gateway_base, raw) if raw.startswith("/") else urljoin(base_url, raw)
    canonical = canonical_freenet_key(full_url) or canonical_freenet_key(raw)
    return f"freenet:{canonical}" if canonical else None


class BaseConnector:
    network = "unknown"
    name = "base"
    supports_fetch = False
    readiness = "planned"
    transport = "manual"

    def accepts(self, url: str) -> bool:
        return classify_network(url) == self.network

    def fetch(self, url: str) -> FetchResult:
        return FetchResult(
            url=url,
            network=self.network,
            error=f"{self.network} connector is not implemented yet",
            connector=self.name,
        )

    def discover_links(self, url: str, html: str) -> list[str]:
        return []

    def diagnostics(self) -> dict[str, str | bool]:
        return {
            "network": self.network,
            "connector": self.name,
            "transport": self.transport,
            "readiness": self.readiness,
            "supports_fetch": self.supports_fetch,
        }


class HttpConnector(BaseConnector):
    network = "clearnet"
    name = "http"
    supports_fetch = True
    readiness = "ready"
    transport = "direct"
    same_host_only = False

    def __init__(self, session_factory: Callable[[], requests.Session] | None = None):
        self.session_factory = session_factory or build_session

    def prepare_url(self, url: str) -> str:
        return url

    def fetch(self, url: str) -> FetchResult:
        target_url = self.prepare_url(url)
        session = self.session_factory()
        response = session.get(target_url, timeout=DEFAULT_REQUEST_TIMEOUT)
        response.raise_for_status()
        html = response.text
        return FetchResult(
            url=url,
            network=self.network,
            html=html,
            text=html_to_text(html),
            links=self.discover_links(target_url, html),
            connector=self.name,
        )

    def discover_links(self, url: str, html: str) -> list[str]:
        soup = BeautifulSoup(html, "html.parser")
        links = []
        seen = set()
        for link in soup.find_all("a", href=True):
            full_url = normalize_http_child_link(url, link["href"])
            if should_keep_http_link(url, full_url, self.network, same_host_only=self.same_host_only) and full_url not in seen:
                seen.add(full_url)
                links.append(full_url)
        return links

    def diagnostics(self) -> dict[str, str | bool]:
        row = super().diagnostics()
        row["same_host_only"] = self.same_host_only
        return row


def build_tor_session() -> requests.Session:
    return build_session(
        proxies={
            "http": tor_socks_url(),
            "https": tor_socks_url(),
        }
    )


class TorConnector(HttpConnector):
    network = "tor"
    name = "tor_http"
    readiness = "ready"
    transport = "socks5h"

    def __init__(self):
        super().__init__(session_factory=build_tor_session)

    def prepare_url(self, url: str) -> str:
        if url.lower().startswith("https://") and ".onion" in url.lower():
            return "http://" + url.split("://", 1)[1]
        return url

    def diagnostics(self) -> dict[str, str | bool]:
        row = super().diagnostics()
        row["proxy"] = tor_socks_url()
        return row


def build_i2p_session() -> requests.Session:
    proxy = i2p_http_proxy_url()
    return build_session(
        proxies={
            "http": proxy,
            "https": proxy,
        }
    )


class I2PConnector(HttpConnector):
    network = "i2p"
    name = "i2p_http"
    readiness = "ready"
    transport = "http_proxy"
    same_host_only = True

    def __init__(self):
        super().__init__(session_factory=build_i2p_session)

    def diagnostics(self) -> dict[str, str | bool]:
        row = super().diagnostics()
        row["proxy"] = i2p_http_proxy_url()
        return row


class ClearnetConnector(HttpConnector):
    network = "clearnet"
    name = "http"
    readiness = "ready"
    transport = "direct"
    same_host_only = not CRAWL_CLEARNET_CROSS_HOST


class FreenetConnector(BaseConnector):
    network = "freenet"
    name = "freenet_http"
    supports_fetch = True
    readiness = "ready"
    transport = "gateway"

    def __init__(self, session_factory: Callable[[], requests.Session] | None = None):
        self.session_factory = session_factory or build_session

    def fetch(self, url: str) -> FetchResult:
        canonical_url = canonical_freenet_url(url)
        target_url = freenet_fetch_url(canonical_url)
        session = self.session_factory()
        response = session.get(target_url, timeout=DEFAULT_REQUEST_TIMEOUT)
        response.raise_for_status()
        html = response.text
        return FetchResult(
            url=canonical_url,
            network=self.network,
            html=html,
            text=html_to_text(html),
            links=self.discover_links(target_url, html),
            connector=self.name,
        )

    def discover_links(self, url: str, html: str) -> list[str]:
        soup = BeautifulSoup(html, "html.parser")
        links = []
        seen = set()
        for link in soup.find_all("a", href=True):
            full_url = normalize_freenet_child_link(url, link["href"])
            if full_url and full_url not in seen:
                seen.add(full_url)
                links.append(full_url)
        return links

    def diagnostics(self) -> dict[str, str | bool]:
        row = super().diagnostics()
        row["gateway"] = freenet_gateway_url()
        return row


class PartialDarknetConnector(BaseConnector):
    def __init__(self, network: str, name: str):
        self.network = network
        self.name = name
        self.supports_fetch = False
        self.readiness = "partial"

    def fetch(self, url: str) -> FetchResult:
        return FetchResult(
            url=url,
            network=self.network,
            error=f"{self.network} connector is registered but transport/parsing is still partial",
            connector=self.name,
        )


CONNECTOR_REGISTRY: dict[str, BaseConnector] = {
    "tor": TorConnector(),
    "clearnet": ClearnetConnector(),
    "i2p": I2PConnector(),
    "freenet": FreenetConnector(),
    "gnunet": PartialDarknetConnector("gnunet", "gnunet_native"),
    "riffle": PartialDarknetConnector("riffle", "riffle_native"),
    "zeronet": PartialDarknetConnector("zeronet", "zeronet_http"),
    "fossil": PartialDarknetConnector("fossil", "fossil_native"),
    "lokinet": PartialDarknetConnector("lokinet", "lokinet_http"),
    "unknown": BaseConnector(),
}


def get_connector_for_url(url: str) -> BaseConnector:
    return CONNECTOR_REGISTRY.get(classify_network(url), CONNECTOR_REGISTRY["unknown"])


def supports_fetch(url: str) -> bool:
    intake = normalize_fetchable_url(url)
    return intake.accepted and bool(get_connector_for_url(intake.normalized_url or url).supports_fetch)


def connector_status_frame() -> list[dict]:
    rows = []
    for network, connector in CONNECTOR_REGISTRY.items():
        meta = NETWORKS.get(network, {})
        row = {
            "network": meta.get("label", network.title()),
            "connector": connector.name,
            "transport": connector.transport,
            "readiness": connector.readiness,
            "supports_fetch": connector.supports_fetch,
        }
        row.update(
            {
                key: value
                for key, value in connector.diagnostics().items()
                if key not in {"network", "connector", "transport", "readiness", "supports_fetch"}
            }
        )
        rows.append(row)
    return rows
