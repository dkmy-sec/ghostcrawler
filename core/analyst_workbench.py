from __future__ import annotations

import json
import sqlite3

import pandas as pd

from core.hunt_quality import dedupe_records, extract_entities, normalize_text, normalized_variants, score_match
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


def add_saved_view(name: str, scope: str, lens: str, tab_name: str, query: str, filters: dict, created_by: str) -> None:
    filters_json = json.dumps(filters or {}, ensure_ascii=True, sort_keys=True)
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO saved_views (name, scope, lens, tab_name, query, filters_json, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                scope=excluded.scope,
                lens=excluded.lens,
                tab_name=excluded.tab_name,
                query=excluded.query,
                filters_json=excluded.filters_json,
                created_by=excluded.created_by,
                updated_at=CURRENT_TIMESTAMP
            """,
            (name.strip(), scope, lens, tab_name, query.strip(), filters_json, created_by.strip()),
        )
        conn.commit()


def load_saved_views() -> pd.DataFrame:
    with get_connection() as conn:
        return pd.read_sql_query(
            """
            SELECT id, name, scope, lens, tab_name, query, filters_json, created_by, updated_at, created_at
            FROM saved_views
            ORDER BY updated_at DESC, created_at DESC
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


def add_campaign(name: str, description: str, actor: str, campaign_type: str, severity: str, tags: str) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO campaigns (name, description, actor, campaign_type, severity, tags)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                description=excluded.description,
                actor=excluded.actor,
                campaign_type=excluded.campaign_type,
                severity=excluded.severity,
                tags=excluded.tags,
                last_seen=CURRENT_TIMESTAMP
            """,
            (name.strip(), description.strip(), actor.strip(), campaign_type, severity, tags.strip()),
        )
        conn.commit()


def load_campaigns() -> pd.DataFrame:
    with get_connection() as conn:
        return pd.read_sql_query(
            """
            SELECT
                c.id, c.name, c.actor, c.campaign_type, c.severity, c.tags, c.status, c.last_seen,
                COUNT(cl.id) AS linked_records
            FROM campaigns c
            LEFT JOIN campaign_links cl ON cl.campaign_id = c.id
            GROUP BY c.id, c.name, c.actor, c.campaign_type, c.severity, c.tags, c.status, c.last_seen
            ORDER BY c.last_seen DESC, c.created_at DESC
            """,
            conn,
        )


def load_campaign_links(limit: int = 100) -> pd.DataFrame:
    with get_connection() as conn:
        return pd.read_sql_query(
            """
            SELECT
                cl.id,
                c.name AS campaign_name,
                cl.source_table,
                cl.title,
                cl.url,
                cl.network,
                cl.confidence,
                cl.rationale,
                cl.last_seen
            FROM campaign_links cl
            JOIN campaigns c ON c.id = cl.campaign_id
            ORDER BY cl.last_seen DESC
            LIMIT ?
            """,
            conn,
            params=(limit,),
        )


def load_source_reliability(limit: int = 100) -> pd.DataFrame:
    with get_connection() as conn:
        return pd.read_sql_query(
            """
            SELECT url, network, source, tag, score, confidence, evidence_count,
                   zero_day_count, watchlist_hit_count, freshness_days, health,
                   analyst_override, decay_penalty, rationale, override_note, updated_at
            FROM source_reliability
            ORDER BY score DESC, confidence DESC, updated_at DESC
            LIMIT ?
            """,
            conn,
            params=(limit,),
        )


def update_source_override(url: str, health: str, analyst_override: int, override_note: str, author: str) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO source_reliability (url, network, health, analyst_override, override_note)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(url) DO UPDATE SET
                health=excluded.health,
                analyst_override=excluded.analyst_override,
                override_note=excluded.override_note,
                updated_at=CURRENT_TIMESTAMP
            """,
            (url, classify_network(url), health, int(analyst_override), override_note.strip()),
        )
        conn.execute(
            """
            INSERT INTO source_health_events (url, health, note, author)
            VALUES (?, ?, ?, ?)
            """,
            (url, health, override_note.strip(), author.strip()),
        )
        conn.commit()


def load_source_health_events(limit: int = 100) -> pd.DataFrame:
    with get_connection() as conn:
        return pd.read_sql_query(
            """
            SELECT url, health, note, author, created_at
            FROM source_health_events
            ORDER BY created_at DESC
            LIMIT ?
            """,
            conn,
            params=(limit,),
        )


def add_case(title: str, summary: str, owner: str, severity: str, status: str, campaign_id: int | None) -> None:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO cases (title, summary, owner, severity, status, campaign_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (title.strip(), summary.strip(), owner.strip(), severity, status, campaign_id),
        )
        case_id = int(cursor.lastrowid)
        if campaign_id:
            campaign_links = pd.read_sql_query(
                """
                SELECT source_table, source_ref, title, url, network, confidence
                FROM campaign_links
                WHERE campaign_id = ?
                """,
                conn,
                params=(campaign_id,),
            )
            for _, row in campaign_links.iterrows():
                conn.execute(
                    """
                    INSERT OR IGNORE INTO case_links (case_id, source_table, source_ref, title, url, network, link_type, confidence)
                    VALUES (?, ?, ?, ?, ?, ?, 'campaign_seed', ?)
                    """,
                    (
                        case_id,
                        row["source_table"],
                        row["source_ref"],
                        row["title"],
                        row.get("url"),
                        row.get("network"),
                        int(row.get("confidence", 50)),
                    ),
                )
        conn.commit()


def add_case_note(case_id: int, author: str, note: str) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO case_notes (case_id, author, note)
            VALUES (?, ?, ?)
            """,
            (case_id, author.strip(), note.strip()),
        )
        conn.execute(
            """
            UPDATE cases
            SET updated_at = CURRENT_TIMESTAMP, last_activity = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (case_id,),
        )
        conn.commit()


def add_case_handoff(
    case_id: int,
    from_owner: str,
    to_owner: str,
    summary: str,
    next_steps: str,
    due_at: str,
    status: str,
) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO case_handoffs (case_id, from_owner, to_owner, summary, next_steps, due_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                from_owner.strip(),
                to_owner.strip(),
                summary.strip(),
                next_steps.strip(),
                due_at.strip(),
                status,
            ),
        )
        conn.execute(
            """
            UPDATE cases
            SET owner = COALESCE(NULLIF(?, ''), owner),
                status = CASE WHEN ? = 'completed' THEN status ELSE 'handoff' END,
                updated_at = CURRENT_TIMESTAMP,
                last_activity = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (to_owner.strip(), status, case_id),
        )
        conn.commit()


def load_cases() -> pd.DataFrame:
    with get_connection() as conn:
        return pd.read_sql_query(
            """
            SELECT
                cs.id, cs.title, cs.summary, cs.owner, cs.status, cs.severity,
                cs.campaign_id, c.name AS campaign_name, cs.last_activity, cs.updated_at,
                COUNT(cl.id) AS linked_items,
                COUNT(cn.id) AS notes
            FROM cases cs
            LEFT JOIN campaigns c ON c.id = cs.campaign_id
            LEFT JOIN case_links cl ON cl.case_id = cs.id
            LEFT JOIN case_notes cn ON cn.case_id = cs.id
            GROUP BY cs.id, cs.title, cs.summary, cs.owner, cs.status, cs.severity,
                     cs.campaign_id, c.name, cs.last_activity, cs.updated_at
            ORDER BY
                CASE cs.severity
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    ELSE 3
                END,
                cs.last_activity DESC
            """,
            conn,
        )


def load_case_links(case_id: int | None = None, limit: int = 100) -> pd.DataFrame:
    with get_connection() as conn:
        if case_id:
            return pd.read_sql_query(
                """
                SELECT cl.id, cs.title AS case_title, cl.source_table, cl.title, cl.url, cl.network, cl.link_type, cl.confidence, cl.last_seen
                FROM case_links cl
                JOIN cases cs ON cs.id = cl.case_id
                WHERE cl.case_id = ?
                ORDER BY cl.last_seen DESC
                LIMIT ?
                """,
                conn,
                params=(case_id, limit),
            )
        return pd.read_sql_query(
            """
            SELECT cl.id, cs.title AS case_title, cl.source_table, cl.title, cl.url, cl.network, cl.link_type, cl.confidence, cl.last_seen
            FROM case_links cl
            JOIN cases cs ON cs.id = cl.case_id
            ORDER BY cl.last_seen DESC
            LIMIT ?
            """,
            conn,
            params=(limit,),
        )


def load_case_handoffs(case_id: int | None = None, limit: int = 100) -> pd.DataFrame:
    with get_connection() as conn:
        if case_id:
            return pd.read_sql_query(
                """
                SELECT ch.id, cs.title AS case_title, ch.from_owner, ch.to_owner, ch.summary,
                       ch.next_steps, ch.due_at, ch.status, ch.created_at
                FROM case_handoffs ch
                JOIN cases cs ON cs.id = ch.case_id
                WHERE ch.case_id = ?
                ORDER BY ch.created_at DESC
                LIMIT ?
                """,
                conn,
                params=(case_id, limit),
            )
        return pd.read_sql_query(
            """
            SELECT ch.id, cs.title AS case_title, ch.from_owner, ch.to_owner, ch.summary,
                   ch.next_steps, ch.due_at, ch.status, ch.created_at
            FROM case_handoffs ch
            JOIN cases cs ON cs.id = ch.case_id
            ORDER BY ch.created_at DESC
            LIMIT ?
            """,
            conn,
            params=(limit,),
        )


def load_case_notes(case_id: int | None = None, limit: int = 100) -> pd.DataFrame:
    with get_connection() as conn:
        if case_id:
            return pd.read_sql_query(
                """
                SELECT cn.id, cs.title AS case_title, cn.author, cn.note, cn.created_at
                FROM case_notes cn
                JOIN cases cs ON cs.id = cn.case_id
                WHERE cn.case_id = ?
                ORDER BY cn.created_at DESC
                LIMIT ?
                """,
                conn,
                params=(case_id, limit),
            )
        return pd.read_sql_query(
            """
            SELECT cn.id, cs.title AS case_title, cn.author, cn.note, cn.created_at
            FROM case_notes cn
            JOIN cases cs ON cs.id = cn.case_id
            ORDER BY cn.created_at DESC
            LIMIT ?
            """,
            conn,
            params=(limit,),
        )


def build_case_summary(case_id: int) -> dict:
    with get_connection() as conn:
        case_row = conn.execute(
            """
            SELECT cs.id, cs.title, cs.summary, cs.owner, cs.status, cs.severity,
                   cs.created_at, cs.updated_at, cs.last_activity, c.name AS campaign_name
            FROM cases cs
            LEFT JOIN campaigns c ON c.id = cs.campaign_id
            WHERE cs.id = ?
            """,
            (case_id,),
        ).fetchone()
        if not case_row:
            return {}

        links = pd.read_sql_query(
            """
            SELECT source_table, title, url, network, link_type, confidence, last_seen
            FROM case_links
            WHERE case_id = ?
            ORDER BY confidence DESC, last_seen DESC
            LIMIT 10
            """,
            conn,
            params=(case_id,),
        )
        notes = pd.read_sql_query(
            """
            SELECT author, note, created_at
            FROM case_notes
            WHERE case_id = ?
            ORDER BY created_at DESC
            LIMIT 8
            """,
            conn,
            params=(case_id,),
        )
        handoffs = pd.read_sql_query(
            """
            SELECT from_owner, to_owner, summary, next_steps, due_at, status, created_at
            FROM case_handoffs
            WHERE case_id = ?
            ORDER BY created_at DESC
            LIMIT 5
            """,
            conn,
            params=(case_id,),
        )

    link_records = links.to_dict(orient="records")
    note_records = notes.to_dict(orient="records")
    handoff_records = handoffs.to_dict(orient="records")
    top_entities: list[str] = []
    for record in link_records[:5]:
        label = str(record.get("title") or record.get("url") or "").strip()
        if label and label not in top_entities:
            top_entities.append(label)

    return {
        "case": {
            "id": case_row[0],
            "title": case_row[1],
            "summary": case_row[2] or "",
            "owner": case_row[3] or "",
            "status": case_row[4] or "",
            "severity": case_row[5] or "",
            "created_at": case_row[6] or "",
            "updated_at": case_row[7] or "",
            "last_activity": case_row[8] or "",
            "campaign_name": case_row[9] or "",
        },
        "linked_items": len(link_records),
        "note_count": len(note_records),
        "handoff_count": len(handoff_records),
        "top_entities": top_entities,
        "recent_links": link_records,
        "recent_notes": note_records,
        "recent_handoffs": handoff_records,
    }


def export_case_summary_markdown(case_id: int) -> str:
    summary = build_case_summary(case_id)
    if not summary:
        return ""

    case = summary["case"]
    lines = [
        f"# {case['title']}",
        "",
        f"- Severity: {case['severity']}",
        f"- Status: {case['status']}",
        f"- Owner: {case['owner'] or 'unassigned'}",
        f"- Campaign: {case['campaign_name'] or 'none'}",
        f"- Linked Items: {summary['linked_items']}",
        f"- Notes: {summary['note_count']}",
        f"- Handoffs: {summary['handoff_count']}",
        f"- Last Activity: {case['last_activity']}",
        "",
        "## Summary",
        case["summary"] or "No analyst summary entered yet.",
        "",
    ]
    if summary["top_entities"]:
        lines.extend(["## Priority Leads", *[f"- {item}" for item in summary["top_entities"]], ""])
    if summary["recent_notes"]:
        lines.append("## Recent Notes")
        for note in summary["recent_notes"][:5]:
            author = note.get("author") or "unknown"
            created_at = note.get("created_at") or ""
            lines.append(f"- [{created_at}] {author}: {note.get('note') or ''}")
        lines.append("")
    if summary["recent_handoffs"]:
        lines.append("## Handoffs")
        for handoff in summary["recent_handoffs"][:3]:
            lines.append(
                f"- [{handoff.get('created_at')}] {handoff.get('from_owner') or 'unassigned'} -> "
                f"{handoff.get('to_owner') or 'unassigned'} ({handoff.get('status')}): {handoff.get('summary') or ''}"
            )
        lines.append("")
    if summary["recent_links"]:
        lines.append("## Linked Evidence")
        for link in summary["recent_links"][:8]:
            lines.append(
                f"- [{link.get('source_table')}] {link.get('title') or link.get('url') or 'untitled'} | "
                f"{link.get('network') or 'unknown'} | confidence {link.get('confidence')}"
            )
    return "\n".join(lines).strip() + "\n"


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
            needle = normalize_text(rule["indicator"])
            if not needle:
                continue
            scope = rule["scope"] or "All Sources"
            fuzzy = bool(rule["fuzzy_match"])
            indicator_type = rule.get("indicator_type", "keyword")
            variants = normalized_variants(needle) if fuzzy else {needle}

            for _, row in sources.iterrows():
                haystack = " ".join(str(row.get(col, "")) for col in ["url", "source", "tag"])
                url = row.get("url")
                if scope != "All Sources" and classify_scope(url) != scope:
                    continue
                entities = extract_entities(haystack)
                matched = False
                best_score = 0
                for variant in variants:
                    is_match, score = score_match(indicator_type, variant, haystack, entities, fuzzy)
                    if is_match and score > best_score:
                        matched = True
                        best_score = score
                if matched:
                    created += _persist_watchlist_match(conn, rule, "onions", str(row["id"]), needle, url, row.get("network"), normalize_text(haystack)[:280], best_score)

            for _, row in findings.iterrows():
                haystack = " ".join(str(row.get(col, "")) for col in ["value", "snippet", "url"])
                url = row.get("url")
                if scope != "All Sources" and classify_scope(url) != scope:
                    continue
                entities = extract_entities(haystack)
                matched = False
                best_score = 0
                for variant in variants:
                    is_match, score = score_match(indicator_type, variant, haystack, entities, fuzzy)
                    if is_match and score > best_score:
                        matched = True
                        best_score = score
                if matched:
                    created += _persist_watchlist_match(conn, rule, "data_leaks", str(row["id"]), str(row.get("value", needle)), url, row.get("network"), normalize_text(str(row.get("snippet", "")))[:280], best_score)

            for _, row in zero_day.iterrows():
                haystack = " ".join(str(row.get(col, "")) for col in ["title", "indicator", "details", "url"])
                url = row.get("url")
                if scope != "All Sources" and classify_scope(url) != scope:
                    continue
                entities = extract_entities(haystack)
                matched = False
                best_score = 0
                for variant in variants:
                    is_match, score = score_match(indicator_type, variant, haystack, entities, fuzzy)
                    if is_match and score > best_score:
                        matched = True
                        best_score = score
                if matched:
                    created += _persist_watchlist_match(conn, rule, "zero_day_signals", str(row["id"]), str(row.get("indicator", needle)), url, row.get("network"), normalize_text(str(row.get("details", "")))[:280], best_score)

        conn.commit()
        return created


def _persist_watchlist_match(conn: sqlite3.Connection, rule: pd.Series, source_table: str, source_ref: str, matched_value: str, url: str, network: str, context: str, match_score: int) -> int:
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
            f"{matched_value} (match score {match_score})",
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
            seen = set()

            index_results = pd.DataFrame(search(query, limit=30))
            if not index_results.empty:
                if hunt["scope"] != "All Sources":
                    index_results = index_results[index_results["url"].fillna("").map(classify_scope) == hunt["scope"]]
                if not index_results.empty:
                    index_results = pd.DataFrame(dedupe_records(index_results.to_dict("records"), ["url", "title"]))
                hit_count += len(index_results.index)
                for _, row in index_results.head(5).iterrows():
                    fingerprint = ("search_index", row.get("url"), row.get("title"))
                    if fingerprint in seen:
                        continue
                    seen.add(fingerprint)
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
                if not sources.empty:
                    sources["normalized"] = sources["url"].fillna("").map(normalize_text)
                    sources = sources.drop_duplicates(subset=["normalized", "tag"])
                hit_count += len(sources.index)
                for _, row in sources.head(5).iterrows():
                    fingerprint = ("source", row.get("url"), row.get("tag"))
                    if fingerprint in seen:
                        continue
                    seen.add(fingerprint)
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
                if not signals.empty:
                    signals["normalized_indicator"] = signals["indicator"].fillna("").map(normalize_text)
                    signals = signals.drop_duplicates(subset=["url", "normalized_indicator"])
                hit_count += len(signals.index)
                for _, row in signals.head(5).iterrows():
                    fingerprint = ("signal", row.get("url"), row.get("indicator"))
                    if fingerprint in seen:
                        continue
                    seen.add(fingerprint)
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
    campaign_links = refresh_campaign_links()
    reliability_updates = refresh_source_reliability()
    return {
        "watchlist_matches": watchlist_matches,
        "hunt_matches": hunt_matches,
        "campaign_links": campaign_links,
        "reliability_updates": reliability_updates,
    }


def refresh_campaign_links() -> int:
    with get_connection() as conn:
        campaigns = pd.read_sql_query(
            """
            SELECT id, name, description, actor, campaign_type, severity, tags
            FROM campaigns
            WHERE status = 'active'
            """,
            conn,
        )
        if campaigns.empty:
            return 0

        sources = pd.read_sql_query("SELECT id, url, source, tag, network FROM onions", conn)
        findings = pd.read_sql_query("SELECT id, url, leak_type, value, snippet, network FROM data_leaks", conn)
        signals = pd.read_sql_query("SELECT id, title, indicator, details, url, network FROM zero_day_signals", conn)
        created = 0

        for _, campaign in campaigns.iterrows():
            terms = {
                (campaign.get("name") or "").strip().lower(),
                (campaign.get("actor") or "").strip().lower(),
            }
            terms.update(
                part.strip().lower()
                for part in str(campaign.get("tags") or "").split(",")
                if part.strip()
            )
            terms = {term for term in terms if term}
            if not terms:
                continue

            for _, row in sources.iterrows():
                haystack = " ".join(str(row.get(col, "")) for col in ["url", "source", "tag"]).lower()
                matched = next((term for term in terms if term in haystack), None)
                if matched:
                    created += _persist_campaign_link(
                        conn, campaign, "onions", str(row["id"]), row.get("url") or matched, row.get("url"), row.get("network"), 60, f"Matched source metadata on '{matched}'"
                    )

            for _, row in findings.iterrows():
                haystack = " ".join(str(row.get(col, "")) for col in ["value", "snippet", "url"]).lower()
                matched = next((term for term in terms if term in haystack), None)
                if matched:
                    created += _persist_campaign_link(
                        conn, campaign, "data_leaks", str(row["id"]), f"{row.get('leak_type', 'finding')} match", row.get("url"), row.get("network"), 70, f"Matched evidence on '{matched}'"
                    )

            for _, row in signals.iterrows():
                haystack = " ".join(str(row.get(col, "")) for col in ["title", "indicator", "details", "url"]).lower()
                matched = next((term for term in terms if term in haystack), None)
                if matched:
                    created += _persist_campaign_link(
                        conn, campaign, "zero_day_signals", str(row["id"]), row.get("title") or row.get("indicator") or matched, row.get("url"), row.get("network"), 82, f"Matched exploit signal on '{matched}'"
                    )

            conn.execute("UPDATE campaigns SET last_seen = CURRENT_TIMESTAMP WHERE id = ?", (int(campaign["id"]),))

        conn.commit()
        return created


def _persist_campaign_link(conn: sqlite3.Connection, campaign: pd.Series, source_table: str, source_ref: str, title: str, url: str, network: str, confidence: int, rationale: str) -> int:
    cursor = conn.execute(
        """
        INSERT INTO campaign_links (campaign_id, source_table, source_ref, title, url, network, confidence, rationale)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(campaign_id, source_table, source_ref, title)
        DO UPDATE SET last_seen=CURRENT_TIMESTAMP, confidence=excluded.confidence, rationale=excluded.rationale
        """,
        (int(campaign["id"]), source_table, source_ref, title, url, network or classify_network(url), confidence, rationale),
    )
    return 1 if cursor.rowcount else 0


def refresh_source_reliability() -> int:
    with get_connection() as conn:
        sources = pd.read_sql_query("SELECT url, source, tag, network, priority, last_seen FROM onions", conn)
        if sources.empty:
            return 0

        findings = pd.read_sql_query("SELECT url FROM data_leaks", conn)
        zero_day = pd.read_sql_query("SELECT url, severity FROM zero_day_signals", conn)
        watch_hits = pd.read_sql_query("SELECT url FROM watchlist_hits", conn)
        overrides = pd.read_sql_query(
            """
            SELECT url, health, analyst_override, override_note
            FROM source_reliability
            """,
            conn,
        )

        evidence_counts = findings["url"].value_counts().to_dict() if not findings.empty else {}
        zero_counts = zero_day["url"].value_counts().to_dict() if not zero_day.empty else {}
        hit_counts = watch_hits["url"].value_counts().to_dict() if not watch_hits.empty else {}
        override_map = overrides.set_index("url").to_dict("index") if not overrides.empty else {}

        updates = 0
        for _, row in sources.iterrows():
            url = row.get("url")
            last_seen = pd.to_datetime(row.get("last_seen"), errors="coerce", utc=True)
            freshness_days = int(max((pd.Timestamp.utcnow() - last_seen).days, 0)) if pd.notna(last_seen) else 999
            evidence_count = int(evidence_counts.get(url, 0))
            zero_count = int(zero_counts.get(url, 0))
            hit_count = int(hit_counts.get(url, 0))
            override = override_map.get(url, {})
            health = override.get("health") or "active"
            analyst_override = int(override.get("analyst_override") or 0)
            override_note = override.get("override_note") or ""

            base = 20
            score = base
            score += min(evidence_count * 8, 30)
            score += min(zero_count * 18, 36)
            score += min(hit_count * 6, 18)
            score += 10 if row.get("priority") == "priority" else 0
            score += 8 if freshness_days <= 3 else 4 if freshness_days <= 14 else 0
            decay_penalty = max(min((freshness_days - 7) // 7, 8), 0) * 3 if freshness_days > 7 else 0

            health_modifier = {
                "active": 6,
                "monitored": 0,
                "stale": -8,
                "degraded": -14,
                "blocked": -20,
            }.get(health, 0)

            score = score + health_modifier + analyst_override - decay_penalty
            confidence = min(max(45 + evidence_count * 8 + zero_count * 12 + hit_count * 5 + analyst_override - decay_penalty, 20), 95)
            rationale = (
                f"evidence={evidence_count}, zero_day={zero_count}, watchlist={hit_count}, "
                f"freshness_days={freshness_days}, health={health}, decay_penalty={decay_penalty}, override={analyst_override}"
            )

            conn.execute(
                """
                INSERT INTO source_reliability (
                    url, network, source, tag, score, confidence, evidence_count,
                    zero_day_count, watchlist_hit_count, freshness_days, health,
                    analyst_override, decay_penalty, rationale, override_note
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(url) DO UPDATE SET
                    network=excluded.network,
                    source=excluded.source,
                    tag=excluded.tag,
                    score=excluded.score,
                    confidence=excluded.confidence,
                    evidence_count=excluded.evidence_count,
                    zero_day_count=excluded.zero_day_count,
                    watchlist_hit_count=excluded.watchlist_hit_count,
                    freshness_days=excluded.freshness_days,
                    health=excluded.health,
                    analyst_override=excluded.analyst_override,
                    decay_penalty=excluded.decay_penalty,
                    rationale=excluded.rationale,
                    override_note=excluded.override_note,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (
                    url,
                    row.get("network") or classify_network(url),
                    row.get("source"),
                    row.get("tag"),
                    int(min(score, 100)),
                    int(confidence),
                    evidence_count,
                    zero_count,
                    hit_count,
                    freshness_days,
                    health,
                    analyst_override,
                    decay_penalty,
                    rationale,
                    override_note,
                ),
            )
            updates += 1

        conn.commit()
        return updates
