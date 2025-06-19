import sqlite3
from pathlib import Path

DB_PATH = Path("../data/onion_sources.db")

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Check if the 'tag' column exists
cursor.execute("PRAGMA table_info(onions);")
columns = [col[1] for col in cursor.fetchall()]

if "tag" not in columns:
    print("[~] Adding missing 'tag' column...")
    cursor.execute("ALTER TABLE onions ADD COLUMN tag TEXT DEFAULT 'unknown'")
    conn.commit()
    print("✓ Column 'tag' added.")
else:
    print("✓ 'tag' column already exists.")

conn.close()
