from __future__ import annotations

import logging
import re
import sqlite3
from pathlib import Path

try:
    from core.connectors import get_connector_for_url, supports_fetch
    from core.intel_schema import ensure_database
    from core.network_catalog import classify_network
    from core.utils import DATA_DIR
except ImportError:
    DATA_DIR = Path(__file__).parent.parent / "data"
    from connectors import get_connector_for_url, supports_fetch
    from intel_schema import ensure_database
    from network_catalog import classify_network


DB_PATH = DATA_DIR / "onion_sources.db"
ensure_database(DB_PATH)

EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
API_KEY_REGEX = r"(?i)(api[_-]?key|apikey|secret|token)[\s:]*[\"']?([A-Za-z0-9\-._~+/]+=*)[\"']?"
HASH_REGEX = r"(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})"
PRIVATE_KEY_REGEX = r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"
ZERO_DAY_PATTERNS = {
    "zero_day_mention": re.compile(r"\b(?:0day|zero[\s-]?day)\b", re.IGNORECASE),
    "exploit_sale": re.compile(r"\b(?:exploit for sale|private exploit|fresh exploit)\b", re.IGNORECASE),
    "active_exploitation": re.compile(r"\b(?:exploited in the wild|active exploitation|mass exploitation)\b", re.IGNORECASE),
    "critical_cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b.{0,80}\b(?:rce|auth bypass|sandbox escape|privilege escalation)\b", re.IGNORECASE),
}

def get_connection():
    return sqlite3.connect(DB_PATH)


def classify_onion(url: str) -> str:
    lowered = (url or "").lower()
    if any(token in lowered for token in ["hub", "forum", "board", "dread"]):
        return "forum"
    if any(token in lowered for token in ["paste", "bin"]):
        return "paste"
    if any(token in lowered for token in ["market", "store", "shop"]):
        return "market"
    if any(token in lowered for token in ["leak", "dump", "breach"]):
        return "leak"
    if any(token in lowered for token in ["exploit", "0day", "zero-day"]):
        return "exploit"
    return "unknown"


def harvest_leaks(text: str, url: str) -> list[dict]:
    results = []

    for email in re.findall(EMAIL_REGEX, text):
        results.append(
            {
                "type": "email",
                "value": email,
                "snippet": text[text.find(email):text.find(email) + 50] if len(text) > 50 else text,
            }
        )

    for match in re.finditer(API_KEY_REGEX, text):
        results.append({"type": "api_key", "value": match.group(2), "snippet": match.group(0)})

    for hash_val in re.findall(HASH_REGEX, text):
        results.append({"type": "hash", "value": hash_val, "snippet": text[text.find(hash_val):text.find(hash_val) + 20]})

    for match in re.finditer(PRIVATE_KEY_REGEX, text):
        results.append({"type": "private_key", "value": match.group(0), "snippet": match.group(0)})

    return results


def detect_zero_day_signals(text: str, url: str) -> list[dict]:
    normalized = " ".join((text or "").split())
    signals = []
    network = classify_network(url)

    for signal_type, pattern in ZERO_DAY_PATTERNS.items():
        for match in pattern.finditer(normalized):
            severity = "critical" if signal_type in {"active_exploitation", "critical_cve"} else "high"
            confidence = 72 if signal_type != "zero_day_mention" else 58
            signals.append(
                {
                    "title": f"{signal_type.replace('_', ' ').title()} detected",
                    "signal_type": signal_type,
                    "indicator": match.group(0)[:240],
                    "severity": severity,
                    "confidence": confidence,
                    "url": url,
                    "source": url,
                    "network": network,
                    "details": normalized[max(0, match.start() - 120): match.end() + 120],
                }
            )

    return signals


def persist_zero_day_signals(signals: list[dict]) -> None:
    if not signals:
        return

    with get_connection() as conn:
        for signal in signals:
            conn.execute(
                """
                INSERT INTO zero_day_signals (
                    title, signal_type, indicator, severity, confidence,
                    url, source, network, details
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(url, signal_type, indicator)
                DO UPDATE SET
                    severity=excluded.severity,
                    confidence=excluded.confidence,
                    network=excluded.network,
                    details=excluded.details,
                    last_seen=CURRENT_TIMESTAMP
                """,
                (
                    signal["title"],
                    signal["signal_type"],
                    signal["indicator"],
                    signal["severity"],
                    signal["confidence"],
                    signal["url"],
                    signal["source"],
                    signal["network"],
                    signal["details"],
                ),
            )
        conn.commit()


def crawl_target(url: str, depth: int = 0, max_depth: int = 4) -> dict:
    network = classify_network(url)
    if not supports_fetch(url):
        return {
            "url": url,
            "network": network,
            "error": f"collector for {network} is not configured yet",
            "found_onions": [],
            "found_links": [],
        }

    connector = get_connector_for_url(url)

    try:
        fetched = connector.fetch(url)
        if fetched.error:
            return {
                "url": url,
                "network": network,
                "connector": fetched.connector,
                "error": fetched.error,
                "found_onions": [],
                "found_links": [],
            }
        html = fetched.html or ""

        snapshot_dir = DATA_DIR / "snapshots"
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{url.replace('http://', '').replace('https://', '').replace('/', '_')}.html"
        (snapshot_dir / filename).write_text(html, encoding="utf-8", errors="ignore")

        text = fetched.text or ""
        leaks = harvest_leaks(text, url)
        zero_day_signals = detect_zero_day_signals(text, url)

        with get_connection() as conn:
            for leak in leaks:
                try:
                    conn.execute(
                        """
                        INSERT INTO data_leaks (url, leak_type, value, snippet, network)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (url, leak["type"], leak["value"], leak["snippet"], network),
                    )
                except sqlite3.Error as exc:
                    logging.error("DB error saving leak for %s: %s", url, exc)

            found_links = []
            for full_url in fetched.links or []:
                child_network = classify_network(full_url)
                found_links.append(full_url)
                conn.execute(
                    """
                    INSERT OR IGNORE INTO onions (url, source, tag, depth, quarantined, network, collector)
                    VALUES (?, ?, ?, ?, 0, ?, ?)
                    """,
                    (full_url, url, classify_onion(full_url), depth + 1, child_network, connector.name),
                )

            conn.commit()

        persist_zero_day_signals(zero_day_signals)

        if depth < max_depth:
            for link in found_links:
                crawl_target(link, depth + 1, max_depth)

        return {
            "url": url,
            "network": network,
            "connector": connector.name,
            "snapshot_file": filename,
            "found_onions": found_links,
            "found_links": found_links,
            "zero_day_signals": len(zero_day_signals),
        }
    except Exception as exc:
        logging.error("Error crawling %s: %s", url, exc)
        return {"url": url, "network": network, "error": str(exc), "found_onions": [], "found_links": []}


def crawl_onion(url: str, depth: int = 0, max_depth: int = 4) -> dict:
    return crawl_target(url, depth=depth, max_depth=max_depth)


def crawl_seed_batch(limit: int = 12, max_depth: int = 4) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT url
            FROM onions
            WHERE COALESCE(quarantined, 0) = 0
            ORDER BY
                CASE COALESCE(priority, 'routine')
                    WHEN 'priority' THEN 0
                    ELSE 1
                END,
                COALESCE(last_seen, CURRENT_TIMESTAMP) DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    results = []
    for (url,) in rows:
        if supports_fetch(url):
            results.append(crawl_target(url, depth=0, max_depth=max_depth))
    return results


if __name__ == "__main__":
    batch = crawl_seed_batch()
    print(f"[✓] Crawled {len(batch)} seed target(s).")
