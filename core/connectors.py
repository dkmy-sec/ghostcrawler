from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from requests_tor import RequestsTor

from core.network_catalog import NETWORKS, classify_network


@dataclass
class FetchResult:
    url: str
    network: str
    html: str | None = None
    text: str | None = None
    links: list[str] | None = None
    error: str | None = None
    connector: str | None = None


class BaseConnector:
    network = "unknown"
    name = "base"
    supports_fetch = False
    readiness = "planned"

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


class HttpConnector(BaseConnector):
    network = "clearnet"
    name = "http"
    supports_fetch = True
    readiness = "ready"

    def __init__(self, session_factory: Callable[[], requests.Session] | None = None):
        self.session_factory = session_factory or requests.Session

    def fetch(self, url: str) -> FetchResult:
        session = self.session_factory()
        response = session.get(url, headers={"User-Agent": "Ghostcrawler/1.0"}, timeout=20)
        html = response.text
        soup = BeautifulSoup(html, "html.parser")
        return FetchResult(
            url=url,
            network=self.network,
            html=html,
            text=soup.get_text(" ", strip=True),
            links=self.discover_links(url, html),
            connector=self.name,
        )

    def discover_links(self, url: str, html: str) -> list[str]:
        soup = BeautifulSoup(html, "html.parser")
        links = []
        for link in soup.find_all("a", href=True):
            full_url = urljoin(url, link["href"])
            if classify_network(full_url) == self.network:
                links.append(full_url)
        return links


class TorConnector(HttpConnector):
    network = "tor"
    name = "tor_http"
    readiness = "ready"

    def __init__(self):
        super().__init__(session_factory=lambda: RequestsTor(tor_ports=(9050,), autochange_id=False))

    def fetch(self, url: str) -> FetchResult:
        session = self.session_factory()
        if hasattr(session, "reset_identity"):
            session.reset_identity()
        response = session.get(url, headers={"User-Agent": "Ghostcrawler/1.0"}, timeout=20)
        html = response.text
        soup = BeautifulSoup(html, "html.parser")
        return FetchResult(
            url=url,
            network=self.network,
            html=html,
            text=soup.get_text(" ", strip=True),
            links=self.discover_links(url, html),
            connector=self.name,
        )

    def discover_links(self, url: str, html: str) -> list[str]:
        soup = BeautifulSoup(html, "html.parser")
        links = []
        for link in soup.find_all("a", href=True):
            full_url = urljoin(url, link["href"])
            if classify_network(full_url) == "tor":
                links.append(full_url)
        return links


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
    "clearnet": HttpConnector(),
    "i2p": PartialDarknetConnector("i2p", "i2p_http"),
    "freenet": PartialDarknetConnector("freenet", "freenet_native"),
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
    return bool(get_connector_for_url(url).supports_fetch)


def connector_status_frame() -> list[dict]:
    rows = []
    for network, connector in CONNECTOR_REGISTRY.items():
        meta = NETWORKS.get(network, {})
        rows.append(
            {
                "network": meta.get("label", network.title()),
                "connector": connector.name,
                "readiness": connector.readiness,
                "supports_fetch": connector.supports_fetch,
            }
        )
    return rows
