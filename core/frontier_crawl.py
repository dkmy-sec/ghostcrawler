# core/frontier_crawl.py
import sqlite3, time
from datetime import datetime, timezone
from urllib.parse import urlparse

from core.utils import DATA_DIR
from core.crawler import crawl_onion
from core.safeguard import is_high_risk

DB = DATA_DIR / "onion_sources.db"

# Controls
MAX_DEPTH = 3
MAX_TOTAL_PAGES = 5000          # total pages fetched per run
MAX_NEW_ENQUEUE = 20000         # safety cap so frontier doesn't explode in one run
MAX_TRIES = 2                   # retry failures a couple times
SLEEP_BETWEEN = 0.15            # be gentle on Tor + remote services
PER_HOST_CAP = 250              # prevent one mega-site from consuming the crawl

def host_of(u: str) -> str:
    try:
        return urlparse(u).netloc.lower()
    except Exception:
        return ""

def enqueue(cur, url, source="seed", depth=0):
    cur.execute("""
        INSERT OR IGNORE INTO frontier(url, source, depth, status, tries)
        VALUES (?, ?, ?, 'pending', 0)
    """, (url, source, depth))

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

def frontier_crawl():
    fetched = 0
    enqueued = 0
    per_host = {}

    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()

        while fetched < MAX_TOTAL_PAGES:
            row = next_pending(cur)
            if not row:
                print("[✓] No pending frontier items.")
                break

            url, depth, tries = row
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

            # Enqueue found onions (BFS expansion)
            for child in result.get("found_onions", []):
                if enqueued >= MAX_NEW_ENQUEUE:
                    break
                enqueue(cur, child, source=url, depth=depth + 1)
                enqueued += 1

            conn.commit()
            time.sleep(SLEEP_BETWEEN)

    print(f"[✓] Frontier crawl finished: fetched={fetched}, enqueued={enqueued}")

if __name__ == "__main__":
    frontier_crawl()
