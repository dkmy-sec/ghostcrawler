from __future__ import annotations

import sqlite3

import pandas as pd

from core.intel_schema import DB_PATH, ensure_database
from core.network_catalog import classify_network, classify_scope
from core.search_engine import search


ensure_database(DB_PATH)


def get_connection():
    return sqlite3.connect(DB_PATH)


def add_watchlist(name: str, indicator: str, indicator_type: str, severity: str, tags: str, scope: str, fuzzy_match: bool) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO watchlists (name, indicator, indicator_type, severity, tags, scope, fuzzy_match)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (name.strip(), indicator.strip(), indicator_type, severity, tags.strip(), scope, int(fuzzy_match)),
        )
        conn.commit()


def add_saved_hunt(name: str, query: str, description: str, scope: str, severity: str) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO saved_hunts (name, query, description, scope, severity)
            VALUES (?, ?, ?, ?, ?)
            """,
            (name.strip(), query.strip(), description.strip(), scope, severity),
        )
        conn.commit()


def load_watchlists() -> pd.DataFrame:
    with get_connection() as conn:
        return pd.read_sql_query(
            """
            SELECT id, name, indicator, indicator_type, severity, tags, scope, fuzzy_match, enabled, hit_count, last_hit_at, created_at
            FROM watchlists
            ORDER BY enabled DESC, severity DESC, created_at DESC
            """,
            conn,
        )


def load_saved_hunts() -> pd.DataFrame:
    with get_connection() as conn:
        return pd.read_sql_query(
            """
            SELECT id, name, query, description, scope, severity, enabled, hit_count, last_run, last_hit_at, created_at
            FROM saved_hunts
            ORDER BY enabled DESC, created_at DESC
            """,
            conn,
        )


def load_watchlist_hits(limit: int = 100) -> pd.DataFrame:
    with get_connection() as conn:
        return pd.read_sql_query(
            """
            SELECT
                wh.id,
                w.name AS watchlist_name,
                w.indicator,
                wh.source_table,
                wh.matched_value,
                wh.url,
                wh.network,
                wh.context,
                wh.last_seen
            FROM watchlist_hits wh
            JOIN watchlists w ON w.id = wh.watchlist_id
            ORDER BY wh.last_seen DESC
            LIMIT ?
            """,
            conn,
            params=(limit,),
        )


def load_analyst_alerts(limit: int = 100) -> pd.DataFrame:
    with get_connection() as conn:
        return pd.read_sql_query(
            """
            SELECT id, alert_kind, rule_name, severity, title, summary, url, network, status, last_seen
            FROM analyst_alerts
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    ELSE 3
                END,
                last_seen DESC
            LIMIT ?
            """,
            conn,
            params=(limit,),
        )


def evaluate_watchlists() -> int:
    with get_connection() as conn:
        rules = pd.read_sql_query(
            """
            SELECT id, name, indicator, indicator_type, severity, tags, scope, fuzzy_match
            FROM watchlists
            WHERE enabled = 1
            """,
            conn,
        )
        if rules.empty:
            return 0

        sources = pd.read_sql_query("SELECT id, url, source, tag, network FROM onions", conn)
        findings = pd.read_sql_query("SELECT id, url, leak_type, value, snippet, network, timestamp FROM data_leaks", conn)
        zero_day = pd.read_sql_query("SELECT id, title, indicator, details, url, network, last_seen FROM zero_day_signals", conn)
        created = 0

        for _, rule in rules.iterrows():
            needle = (rule["indicator"] or "").strip().lower()
            if not needle:
                continue
            scope = rule["scope"] or "All Sources"
            variants = {needle}
            if rule["fuzzy_match"]:
                variants.update({
                    needle.replace(".", "[.]"),
                    needle.replace("@", " at "),
                    needle.replace("-", ""),
                    needle.replace(" ", ""),
                })

            for _, row in sources.iterrows():
                haystack = " ".join(str(row.get(col, "")) for col in ["url", "source", "tag"]).lower()
                url = row.get("url")
                if scope != "All Sources" and classify_scope(url) != scope:
                    continue
                if any(v and v in haystack for v in variants):
                    created += _persist_watchlist_match(conn, rule, "onions", str(row["id"]), needle, url, row.get("network"), haystack[:280])

            for _, row in findings.iterrows():
                haystack = " ".join(str(row.get(col, "")) for col in ["value", "snippet", "url"]).lower()
                url = row.get("url")
                if scope != "All Sources" and classify_scope(url) != scope:
                    continue
                if any(v and v in haystack for v in variants):
                    created += _persist_watchlist_match(conn, rule, "data_leaks", str(row["id"]), str(row.get("value", needle)), url, row.get("network"), str(row.get("snippet", ""))[:280])

            for _, row in zero_day.iterrows():
                haystack = " ".join(str(row.get(col, "")) for col in ["title", "indicator", "details", "url"]).lower()
                url = row.get("url")
                if scope != "All Sources" and classify_scope(url) != scope:
                    continue
                if any(v and v in haystack for v in variants):
                    created += _persist_watchlist_match(conn, rule, "zero_day_signals", str(row["id"]), str(row.get("indicator", needle)), url, row.get("network"), str(row.get("details", ""))[:280])

        conn.commit()
        return created


def _persist_watchlist_match(conn: sqlite3.Connection, rule: pd.Series, source_table: str, source_ref: str, matched_value: str, url: str, network: str, context: str) -> int:
    cursor = conn.execute(
        """
        INSERT INTO watchlist_hits (watchlist_id, source_table, source_ref, matched_value, url, network, context)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(watchlist_id, source_table, source_ref, matched_value)
        DO UPDATE SET last_seen=CURRENT_TIMESTAMP, context=excluded.context
        """,
        (int(rule["id"]), source_table, source_ref, matched_value, url, network or classify_network(url), context),
    )

    conn.execute(
        """
        UPDATE watchlists
        SET hit_count = (
            SELECT COUNT(*) FROM watchlist_hits WHERE watchlist_id = ?
        ),
            last_hit_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (int(rule["id"]), int(rule["id"])),
    )
    conn.execute(
        """
        INSERT INTO analyst_alerts (alert_kind, rule_id, rule_name, severity, title, summary, url, network)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(alert_kind, rule_id, title, url, summary)
        DO UPDATE SET last_seen=CURRENT_TIMESTAMP, status='open'
        """,
        (
            "watchlist",
            int(rule["id"]),
            rule["name"],
            rule["severity"],
            f"Watchlist hit: {rule['name']}",
            matched_value,
            url,
            network or classify_network(url),
        ),
    )
    return 1 if cursor.rowcount else 0


def evaluate_saved_hunts() -> int:
    with get_connection() as conn:
        hunts = pd.read_sql_query(
            """
            SELECT id, name, query, description, scope, severity
            FROM saved_hunts
            WHERE enabled = 1
            """,
            conn,
        )
        if hunts.empty:
            return 0

        created = 0
        for _, hunt in hunts.iterrows():
            query = (hunt["query"] or "").strip()
            if not query:
                continue
            hit_count = 0

            index_results = pd.DataFrame(search(query, limit=20))
            if not index_results.empty:
                if hunt["scope"] != "All Sources":
                    index_results = index_results[index_results["url"].fillna("").map(classify_scope) == hunt["scope"]]
                hit_count += len(index_results.index)
                for _, row in index_results.head(5).iterrows():
                    created += _persist_hunt_alert(conn, hunt, row.get("title") or query, row.get("url"), "search_index")

            sources = pd.read_sql_query(
                """
                SELECT id, url, source, tag, network
                FROM onions
                WHERE url LIKE ? OR source LIKE ? OR tag LIKE ?
                LIMIT 25
                """,
                conn,
                params=(f"%{query}%", f"%{query}%", f"%{query}%"),
            )
            if not sources.empty:
                if hunt["scope"] != "All Sources":
                    sources = sources[sources["url"].fillna("").map(classify_scope) == hunt["scope"]]
                hit_count += len(sources.index)
                for _, row in sources.head(5).iterrows():
                    created += _persist_hunt_alert(conn, hunt, f"{row.get('tag', 'source')} source match", row.get("url"), row.get("network"))

            signals = pd.read_sql_query(
                """
                SELECT id, title, indicator, url, network
                FROM zero_day_signals
                WHERE title LIKE ? OR indicator LIKE ? OR details LIKE ?
                LIMIT 25
                """,
                conn,
                params=(f"%{query}%", f"%{query}%", f"%{query}%"),
            )
            if not signals.empty:
                if hunt["scope"] != "All Sources":
                    signals = signals[signals["url"].fillna("").map(classify_scope) == hunt["scope"]]
                hit_count += len(signals.index)
                for _, row in signals.head(5).iterrows():
                    created += _persist_hunt_alert(conn, hunt, row.get("title") or row.get("indicator"), row.get("url"), row.get("network"))

            conn.execute(
                """
                UPDATE saved_hunts
                SET hit_count = ?, last_run = CURRENT_TIMESTAMP,
                    last_hit_at = CASE WHEN ? > 0 THEN CURRENT_TIMESTAMP ELSE last_hit_at END
                WHERE id = ?
                """,
                (hit_count, hit_count, int(hunt["id"])),
            )

        conn.commit()
        return created


def _persist_hunt_alert(conn: sqlite3.Connection, hunt: pd.Series, summary: str, url: str, network: str) -> int:
    cursor = conn.execute(
        """
        INSERT INTO analyst_alerts (alert_kind, rule_id, rule_name, severity, title, summary, url, network)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(alert_kind, rule_id, title, url, summary)
        DO UPDATE SET last_seen=CURRENT_TIMESTAMP, status='open'
        """,
        (
            "saved_hunt",
            int(hunt["id"]),
            hunt["name"],
            hunt["severity"],
            f"Saved hunt match: {hunt['name']}",
            summary,
            url,
            network or classify_network(url),
        ),
    )
    return 1 if cursor.rowcount else 0


def refresh_analyst_signals() -> dict:
    watchlist_matches = evaluate_watchlists()
    hunt_matches = evaluate_saved_hunts()
    return {"watchlist_matches": watchlist_matches, "hunt_matches": hunt_matches}
