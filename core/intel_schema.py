from __future__ import annotations

import sqlite3
from pathlib import Path

from core.network_catalog import classify_network
from core.utils import DATA_DIR


DB_PATH = DATA_DIR / "onion_sources.db"

MULTI_NETWORK_SEEDS = [
    {"url": "http://vfnmxpa6fo4jdpyq3yneqhglluweax2uclvxkytfpmpkp5rsl75ir5qd.onion", "source": "manual_seed", "tag": "directory", "network": "tor"},
    {"url": "freenet:USK@darknet-threat-feed/index/1", "source": "seed_catalog", "tag": "intel_feed", "network": "freenet"},
    {"url": "gnunet://threat-exchange/forums/zero-day", "source": "seed_catalog", "tag": "forum", "network": "gnunet"},
    {"url": "riffle://intel/market-watch", "source": "seed_catalog", "tag": "market", "network": "riffle"},
    {"url": "http://hiddenwiki.i2p", "source": "seed_catalog", "tag": "directory", "network": "i2p"},
]

ZERO_DAY_FEEDS = [
    {
        "title": "Exploit Chatter",
        "signal_type": "marketplace_listing",
        "indicator": "new RCE chain for perimeter appliance",
        "severity": "critical",
        "confidence": 78,
        "url": "gnunet://threat-exchange/forums/zero-day",
        "source": "seed_catalog",
        "details": "Seeded analyst scenario representing early exploit-sale chatter before broad disclosure.",
    },
    {
        "title": "Initial Broker Post",
        "signal_type": "broker_post",
        "indicator": "0day access broker offering enterprise VPN foothold",
        "severity": "high",
        "confidence": 72,
        "url": "freenet:USK@darknet-threat-feed/index/1",
        "source": "seed_catalog",
        "details": "Seeded record to drive day-zero workflow panels while live feeds are wired in.",
    },
]


def _column_names(conn: sqlite3.Connection, table_name: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row[1] for row in rows}


def _ensure_column(conn: sqlite3.Connection, table_name: str, column_name: str, definition: str) -> None:
    if column_name not in _column_names(conn, table_name):
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")


def _seed_multi_network_sources(conn: sqlite3.Connection) -> None:
    for seed in MULTI_NETWORK_SEEDS:
        conn.execute(
            """
            INSERT OR IGNORE INTO onions (url, source, tag, network, collector, priority)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                seed["url"],
                seed.get("source", "seed_catalog"),
                seed.get("tag", "unknown"),
                seed.get("network") or classify_network(seed["url"]),
                "seed_catalog",
                "priority",
            ),
        )


def _seed_zero_day_signals(conn: sqlite3.Connection) -> None:
    for signal in ZERO_DAY_FEEDS:
        conn.execute(
            """
            INSERT OR IGNORE INTO zero_day_signals (
                title, signal_type, indicator, severity, confidence,
                url, source, network, details
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                signal["title"],
                signal["signal_type"],
                signal["indicator"],
                signal.get("severity", "medium"),
                signal.get("confidence", 50),
                signal.get("url"),
                signal.get("source", "seed_catalog"),
                classify_network(signal.get("url")),
                signal.get("details"),
            ),
        )


def ensure_database(db_path: Path = DB_PATH) -> Path:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS onions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                source TEXT,
                tag TEXT DEFAULT 'unknown',
                depth INTEGER DEFAULT 0,
                live INTEGER DEFAULT 1,
                quarantined INTEGER DEFAULT 0,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        _ensure_column(conn, "onions", "network", "TEXT DEFAULT 'tor'")
        _ensure_column(conn, "onions", "collector", "TEXT DEFAULT 'manual'")
        _ensure_column(conn, "onions", "priority", "TEXT DEFAULT 'routine'")
        _ensure_column(conn, "onions", "notes", "TEXT")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS data_leaks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                leak_type TEXT,
                value TEXT,
                snippet TEXT,
                network TEXT DEFAULT 'unknown',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS frontier (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                source TEXT,
                depth INTEGER DEFAULT 0,
                status TEXT DEFAULT 'pending',
                tries INTEGER DEFAULT 0,
                network TEXT DEFAULT 'unknown',
                last_try TIMESTAMP
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS zero_day_signals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                signal_type TEXT NOT NULL,
                indicator TEXT NOT NULL,
                severity TEXT DEFAULT 'medium',
                confidence INTEGER DEFAULT 50,
                url TEXT,
                source TEXT,
                network TEXT DEFAULT 'unknown',
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_zero_day_unique
            ON zero_day_signals(url, signal_type, indicator)
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS watchlists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                indicator TEXT NOT NULL,
                indicator_type TEXT DEFAULT 'keyword',
                severity TEXT DEFAULT 'medium',
                tags TEXT,
                scope TEXT DEFAULT 'All Sources',
                fuzzy_match INTEGER DEFAULT 1,
                enabled INTEGER DEFAULT 1,
                hit_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_hit_at TIMESTAMP
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS saved_hunts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                query TEXT NOT NULL,
                description TEXT,
                scope TEXT DEFAULT 'All Sources',
                severity TEXT DEFAULT 'medium',
                enabled INTEGER DEFAULT 1,
                hit_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_run TIMESTAMP,
                last_hit_at TIMESTAMP
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS watchlist_hits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                watchlist_id INTEGER NOT NULL,
                source_table TEXT NOT NULL,
                source_ref TEXT NOT NULL,
                matched_value TEXT NOT NULL,
                url TEXT,
                network TEXT DEFAULT 'unknown',
                context TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (watchlist_id) REFERENCES watchlists(id)
            )
            """
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_watchlist_hit_unique
            ON watchlist_hits(watchlist_id, source_table, source_ref, matched_value)
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analyst_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_kind TEXT NOT NULL,
                rule_id INTEGER NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT DEFAULT 'medium',
                title TEXT NOT NULL,
                summary TEXT,
                url TEXT,
                network TEXT DEFAULT 'unknown',
                status TEXT DEFAULT 'open',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_analyst_alert_unique
            ON analyst_alerts(alert_kind, rule_id, title, url, summary)
            """
        )

        _seed_multi_network_sources(conn)
        _seed_zero_day_signals(conn)
        conn.commit()
    return db_path
