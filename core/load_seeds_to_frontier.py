# core/load_seeds_to_frontier.py
import sqlite3
from core.utils import DATA_DIR

DB = DATA_DIR / "onion_sources.db"
SEED = DATA_DIR / "seed_onions.txt"

with sqlite3.connect(DB) as conn:
    cur = conn.cursor()
    seeds = [l.strip() for l in SEED.read_text(encoding="utf-8").splitlines() if l.strip()]
    for s in seeds:
        cur.execute("""
            INSERT OR IGNORE INTO frontier(url, source, depth, status)
            VALUES (?, 'seedfile', 0, 'pending')
        """, (s,))
    conn.commit()

print(f"[✓] Loaded {len(seeds)} seed URLs into frontier.")
