# core/clean_quarantine.py
import sqlite3, json, shutil
from pathlib import Path
from datetime import datetime
from core.safeguard import BAD_WORDS, is_high_risk   # already defined in your project

# ---- Paths -------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR      = PROJECT_ROOT / "data"
DB_PATH       = DATA_DIR / "onion_sources.db"
SEED_PATH     = DATA_DIR / "seed_onions.txt"
BACKUP_DIR    = DATA_DIR / "backups"
BACKUP_DIR.mkdir(exist_ok=True)

timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

# ---- 1. Back up files --------------------------------------
shutil.copy(DB_PATH,  BACKUP_DIR / f"onion_sources_{timestamp}.db")
shutil.copy(SEED_PATH, BACKUP_DIR / f"seed_onions_{timestamp}.txt")
print(f"[✓] Backups written to {BACKUP_DIR}")

# ---- 2. Clean DB -------------------------------------------
with sqlite3.connect(DB_PATH) as conn:
    cur = conn.cursor()

    # quarantine table if not exists
    cur.execute("""
        CREATE TABLE IF NOT EXISTS quarantine (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            reason TEXT,
            moved_at TEXT
        )
    """)

    # Move rows already flagged
    cur.execute("""
        INSERT OR IGNORE INTO quarantine(url, reason, moved_at)
        SELECT url, 'pre-flagged', datetime('now')
        FROM onions WHERE quarantined = 1
    """)
    cur.execute("DELETE FROM onions WHERE quarantined = 1")

    # Move rows that match BAD_WORDS but were not flagged
    placeholders = ",".join(["?"] * len(BAD_WORDS))
    cur.execute(f"""
        SELECT url FROM onions
        WHERE {" OR ".join(["url LIKE '%'||?||'%'" for _ in BAD_WORDS])}
    """, tuple(BAD_WORDS))
    bad_urls = [r[0] for r in cur.fetchall()]

    for url in bad_urls:
        cur.execute("""
            INSERT OR IGNORE INTO quarantine(url, reason, moved_at)
            VALUES (?, 'keyword-match', datetime('now'))
        """, (url,))
        cur.execute("DELETE FROM onions WHERE url = ?", (url,))

    conn.commit()
    print(f"[✓] {len(bad_urls)} additional URLs quarantined.")

# ---- 3. Rewrite seed_onions.txt ----------------------------
safe_urls = []
with SEED_PATH.open() as f:
    for line in f:
        url = line.strip()
        if not url: continue
        if any(word in url.lower() for word in BAD_WORDS):
            continue
        safe_urls.append(url)

# Deduplicate while preserving order
seen = set()
safe_urls = [u for u in safe_urls if not (u in seen or seen.add(u))]

SEED_PATH.write_text("\n".join(safe_urls) + "\n")
print(f"[✓] seed_onions.txt cleaned → {len(safe_urls)} safe URLs")

print("Done. Quarantined data now lives in data/quarantine table and backups.")
