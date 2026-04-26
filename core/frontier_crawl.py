# core/frontier_crawl.py
import sys
from pathlib import Path
# This line tells Python to look in the parent folder for the 'core' module
sys.path.append(str(Path(__file__).resolve().parent.parent))

import sqlite3, time
from datetime import datetime, timezone
from urllib.parse import urlparse

from core.utils import DATA_DIR
from core.crawler import crawl_onion
from core.safeguard import is_high_risk
from core.url_intake import UrlIntakeSummary, format_skip_summary, normalize_fetchable_url

DB = DATA_DIR / "onion_sources.db"

# Controls
MAX_DEPTH = 8
MAX_TOTAL_PAGES = 5000          # total pages fetched per run
MAX_NEW_ENQUEUE = 20000         # safety cap so frontier doesn't explode in one run
MAX_TRIES = 2                   # retry failures a couple times
SLEEP_BETWEEN = 0.15            # be gentle on Tor + remote services
PER_HOST_CAP = 400              # prevent one mega-site from consuming the crawl

def host_of(u: str) -> str:
    try:
        return urlparse(u).netloc.lower()
    except Exception:
        return ""

def enqueue(cur, url, source="seed", depth=0, skip_summary: UrlIntakeSummary | None = None) -> bool:
    intake = normalize_fetchable_url(url)
    if not intake.accepted:
        if skip_summary is not None:
            skip_summary.record(intake)
        return False
    normalized_url = intake.normalized_url or ""
    cur.execute("""
        INSERT OR IGNORE INTO frontier(url, source, depth, status, tries, network)
        VALUES (?, ?, ?, 'pending', 0, ?)
    """, (normalized_url, source, depth, intake.network))
    return cur.rowcount > 0

def next_pending(cur):
    return cur.execute("""
        SELECT url, depth, tries FROM frontier
        WHERE status='pending' AND depth <= ?
        ORDER BY depth ASC
        LIMIT 1
    """, (MAX_DEPTH,)).fetchone()

def mark(cur, url, status):
    cur.execute("""
        UPDATE frontier SET status=?, last_try=? WHERE url=?
    """, (status, datetime.now(timezone.utc).isoformat(), url))

def inc_try(cur, url):
    cur.execute("UPDATE frontier SET tries = tries + 1 WHERE url=?", (url,))

def frontier_crawl(*, emit_summary: bool = True) -> dict:
    fetched = 0
    enqueued = 0
    per_host = {}
    intake_skips = UrlIntakeSummary()

    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()

        while fetched < MAX_TOTAL_PAGES:
            row = next_pending(cur)
            if not row:
                if emit_summary:
                    print("[✓] No pending frontier items.")
                break

            url, depth, tries = row
            intake = normalize_fetchable_url(url)
            if not intake.accepted:
                intake_skips.record(intake)
                mark(cur, url, "skipped")
                conn.commit()
                continue

            normalized_url = intake.normalized_url or ""
            if normalized_url != url:
                cur.execute(
                    "UPDATE OR IGNORE frontier SET url=?, network=? WHERE url=?",
                    (normalized_url, intake.network, url),
                )
                if cur.rowcount == 0:
                    mark(cur, url, "skipped")
                    conn.commit()
                    continue
                url = normalized_url
                conn.commit()

            h = host_of(url)

            # host cap to prevent one site dominating
            per_host.setdefault(h, 0)
            if per_host[h] >= PER_HOST_CAP:
                mark(cur, url, "skipped")
                conn.commit()
                continue

            mark(cur, url, "running")
            conn.commit()

            result = crawl_onion(url, depth=depth, max_depth=MAX_DEPTH)
            fetched += 1
            per_host[h] += 1

            if result.get("error") == "quarantined":
                mark(cur, url, "quarantined")
                conn.commit()
                time.sleep(SLEEP_BETWEEN)
                continue

            if result.get("error"):
                inc_try(cur, url)
                conn.commit()
                if tries + 1 >= MAX_TRIES:
                    mark(cur, url, "skipped")
                else:
                    mark(cur, url, "pending")
                conn.commit()
                time.sleep(SLEEP_BETWEEN)
                continue

            # Success
            mark(cur, url, "done")
            intake_skips.add_counts(result.get("skipped_links", {}))

            # Enqueue found onions (BFS expansion)
            for child in result.get("found_onions", []):
                if enqueued >= MAX_NEW_ENQUEUE:
                    break
                if enqueue(cur, child, source=url, depth=depth + 1, skip_summary=intake_skips):
                    enqueued += 1

            conn.commit()
            time.sleep(SLEEP_BETWEEN)

    stats = {"fetched": fetched, "enqueued": enqueued, "skipped": intake_skips.as_dict()}
    if emit_summary:
        suffix = f", skipped={format_skip_summary(intake_skips)}" if intake_skips.skipped else ""
        print(f"[✓] Frontier crawl finished: fetched={fetched}, enqueued={enqueued}{suffix}")
    return stats

if __name__ == "__main__":
    frontier_crawl()
