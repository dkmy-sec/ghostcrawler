# core/migrate_frontier.py
import sqlite3
from core.utils import DATA_DIR

DB = DATA_DIR / "onion_sources.db"

with sqlite3.connect(DB) as conn:
    cur = conn.cursor()

    # Add columns if missing (SQLite-safe approach)
    # We check pragma table_info for columns.
    cols = {r[1] for r in cur.execute("PRAGMA table_info(onions)").fetchall()}

    if "depth" not in cols:
        cur.execute("ALTER TABLE onions ADD COLUMN depth INTEGER DEFAULT 0")
    if "quarantined" not in cols:
        cur.execute("ALTER TABLE onions ADD COLUMN quarantined INTEGER DEFAULT 0")
    if "reason" not in cols:
        cur.execute("ALTER TABLE onions ADD COLUMN reason TEXT DEFAULT NULL")

    # Frontier queue
    cur.execute("""
    CREATE TABLE IF NOT EXISTS frontier (
        url TEXT PRIMARY KEY,
        source TEXT,
        depth INTEGER DEFAULT 0,
        status TEXT DEFAULT 'pending',     -- pending | running | done | skipped | quarantined
        last_try TEXT,
        tries INTEGER DEFAULT 0
    )
    """)

    # Helpful indexes
    cur.execute("CREATE INDEX IF NOT EXISTS idx_frontier_status ON frontier(status)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_onions_url ON onions(url)")

    conn.commit()

print("[✓] Migration complete.")
