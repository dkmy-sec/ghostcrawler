from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Mapping
from urllib.parse import quote, urlsplit, urlunsplit
import re

try:
    from core.network_catalog import FREENET_KEY_PREFIXES, classify_network, network_metadata
except ImportError:
    from network_catalog import FREENET_KEY_PREFIXES, classify_network, network_metadata


FETCHABLE_SCHEMES = {"http", "https", "freenet"}
NON_WEB_SCHEMES = {
    "about",
    "blob",
    "data",
    "file",
    "ftp",
    "irc",
    "javascript",
    "magnet",
    "mailto",
    "news",
    "sms",
    "tel",
    "urn",
    "ws",
    "wss",
}
UNSAFE_HOST_CHARS = set(' \t\r\n<>"{}|\\^`')
ONION_SERVICE_RE = re.compile(r"^[a-z2-7]{56}$")


@dataclass(frozen=True)
class UrlIntakeResult:
    raw_url: str
    normalized_url: str | None
    network: str
    reason: str | None = None

    @property
    def accepted(self) -> bool:
        return self.normalized_url is not None and self.reason is None


@dataclass
class UrlIntakeSummary:
    skipped: Counter[str] = field(default_factory=Counter)

    def record(self, result: UrlIntakeResult) -> None:
        if not result.accepted:
            self.skipped[result.reason or "rejected"] += 1

    def add_counts(self, counts: Mapping[str, int] | None) -> None:
        for reason, count in (counts or {}).items():
            if count:
                self.skipped[str(reason)] += int(count)

    def as_dict(self) -> dict[str, int]:
        return dict(self.skipped)


def format_skip_summary(skipped: Mapping[str, int] | UrlIntakeSummary | None, *, limit: int = 6) -> str:
    if isinstance(skipped, UrlIntakeSummary):
        counts = skipped.skipped
    else:
        counts = Counter(skipped or {})
    if not counts:
        return "none"
    parts = [f"{reason}={count}" for reason, count in counts.most_common(limit)]
    remaining = sum(counts.values()) - sum(count for _, count in counts.most_common(limit))
    if remaining:
        parts.append(f"other={remaining}")
    return ", ".join(parts)


def canonical_freenet_key(url: str) -> str | None:
    cleaned = (url or "").strip()
    if not cleaned:
        return None

    lowered = cleaned.lower()
    if lowered.startswith("freenet:"):
        key = cleaned.split(":", 1)[1]
    else:
        parsed = urlsplit(cleaned if "://" in cleaned else f"http://placeholder/{cleaned.lstrip('/')}")
        key = parsed.path if "://" in cleaned else parsed.path.lstrip("/")

    key = key.split("#", 1)[0].strip().lstrip("/")
    return key if key.lower().startswith(FREENET_KEY_PREFIXES) else None


def canonical_freenet_url(url: str) -> str:
    key = canonical_freenet_key(url)
    return f"freenet:{key}" if key else (url or "").strip()


def normalize_fetchable_url(raw_url: str | None) -> UrlIntakeResult:
    raw = "" if raw_url is None else str(raw_url)
    cleaned = raw.strip()
    if not cleaned:
        return _reject(raw, "blank")
    if _has_control_chars(cleaned):
        return _reject(raw, "control_chars")

    freenet_key = canonical_freenet_key(cleaned)
    if freenet_key:
        if not _network_supports_fetch("freenet"):
            return _reject(raw, "non_fetchable_network", "freenet")
        return UrlIntakeResult(raw, f"freenet:{freenet_key}", "freenet")

    explicit_scheme = _explicit_scheme(cleaned)
    if explicit_scheme and explicit_scheme not in FETCHABLE_SCHEMES:
        network = classify_network(cleaned)
        if network not in {"unknown", "clearnet"} and not _network_supports_fetch(network):
            return _reject(raw, "non_fetchable_network", network)
        return _reject(raw, "non_web_scheme", network)

    candidate = cleaned
    if not explicit_scheme:
        if cleaned.startswith("//"):
            candidate = _with_protocol_relative_scheme(cleaned)
        elif not _has_probable_schemeless_host(cleaned):
            return _reject(raw, "relative_url")
        else:
            candidate = f"{_default_scheme_for_schemeless_host(cleaned)}://{cleaned}"

    return _normalize_http_url(raw, candidate)


def _reject(raw: str, reason: str, network: str | None = None) -> UrlIntakeResult:
    return UrlIntakeResult(raw, None, network or classify_network(raw), reason)


def _network_supports_fetch(network: str) -> bool:
    return bool(network_metadata(network).get("supports_fetch"))


def _has_control_chars(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def _explicit_scheme(value: str) -> str:
    match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):", value)
    if not match:
        return ""
    scheme = match.group(1).lower()
    if "://" in value or scheme in FETCHABLE_SCHEMES or scheme in NON_WEB_SCHEMES:
        return scheme
    if _looks_like_host_port(value):
        return ""
    return scheme


def _looks_like_host_port(value: str) -> bool:
    host_port = re.split(r"[/?#]", value, maxsplit=1)[0]
    if ":" not in host_port:
        return False
    host, port = host_port.rsplit(":", 1)
    return bool(host) and port.isdigit()


def _has_probable_schemeless_host(value: str) -> bool:
    host = re.split(r"[/?#]", value, maxsplit=1)[0].strip("[]")
    if not host or any(ch in UNSAFE_HOST_CHARS for ch in host):
        return False
    return "." in host or _looks_like_host_port(value) or host.lower() == "localhost"


def _with_protocol_relative_scheme(value: str) -> str:
    host = re.split(r"[/?#]", value[2:], maxsplit=1)[0].lower()
    scheme = "http" if host.endswith((".onion", ".i2p")) else "https"
    return f"{scheme}:{value}"


def _default_scheme_for_schemeless_host(value: str) -> str:
    host = re.split(r"[/?#]", value, maxsplit=1)[0].lower()
    return "http" if host.endswith((".onion", ".i2p")) else "https"


def _normalize_http_url(raw: str, candidate: str) -> UrlIntakeResult:
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return _reject(raw, "malformed")

    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        return _reject(raw, "non_web_scheme")
    if parts.username or parts.password:
        return _reject(raw, "credentials_in_url")

    try:
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return _reject(raw, "invalid_port")

    if not host:
        return _reject(raw, "missing_host")
    if not _host_looks_valid(host):
        return _reject(raw, "invalid_host")

    host = _idna_host(host)
    if not host:
        return _reject(raw, "invalid_host")

    network = classify_network(urlunsplit((scheme, host, parts.path or "/", parts.query, "")))
    if network == "tor":
        if not _valid_onion_host(host):
            return _reject(raw, "malformed_onion", network)
        scheme = "http"
    elif network == "i2p":
        if not _valid_i2p_host(host):
            return _reject(raw, "malformed_i2p", network)

    if not _network_supports_fetch(network):
        return _reject(raw, "non_fetchable_network", network)

    normalized_path = quote(parts.path or "/", safe="/:%@!$&'()*+,;=-._~%")
    if normalized_path != "/" and normalized_path.endswith("/"):
        normalized_path = normalized_path.rstrip("/")
    normalized_query = quote(parts.query, safe="=&?/:@!$,'()*+;%-._~")
    netloc = _normalized_netloc(host, scheme, port)
    normalized = urlunsplit((scheme, netloc, normalized_path, normalized_query, ""))
    return UrlIntakeResult(raw, normalized, network)


def _host_looks_valid(host: str) -> bool:
    if any(ch in UNSAFE_HOST_CHARS for ch in host):
        return False
    if ".." in host:
        return False
    labels = host.strip(".").split(".")
    return all(label and not label.startswith("-") and not label.endswith("-") for label in labels)


def _idna_host(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return ""


def _valid_onion_host(host: str) -> bool:
    labels = host.split(".")
    if len(labels) < 2 or labels[-1] != "onion":
        return False
    return bool(ONION_SERVICE_RE.fullmatch(labels[-2]))


def _valid_i2p_host(host: str) -> bool:
    labels = host.split(".")
    return len(labels) >= 2 and labels[-1] == "i2p" and bool(labels[-2])


def _normalized_netloc(host: str, scheme: str, port: int | None) -> str:
    netloc = f"[{host}]" if ":" in host and not host.startswith("[") else host
    if port and not (scheme == "http" and port == 80) and not (scheme == "https" and port == 443):
        netloc = f"{netloc}:{port}"
    return netloc
