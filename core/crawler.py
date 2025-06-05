import requests
from bs4 import BeautifulSoup
import re
import os
import json
import sqlite3
from datetime import datetime
from pathlib import Path

ONION_REGEX = r"http[s]?://[a-zA-Z0-9\-\.]{10,100}\.onion"
SNAPSHOT_DIR = Path("data/snapshots")
SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)

WATCHLIST_PATH = Path("data/watchlist.json")
with open(WATCHLIST_PATH, "r", encoding="utf-8") as f:
    watchlist = json.load(f)
    keywords = [item for sublist in watchlist.values() for item in sublist]

# DB for discovered onions
DB_PATH = Path("data/onion_sources.db")
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS onions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE,
    source TEXT,
    tag TEXT,
    live INTEGER DEFAULT 1,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

def extract_onions(text):
    return list(set(re.findall(ONION_REGEX, text)))

def classify_onion(url):
    if "forum" in url: return "forum"
    if "paste" in url: return "paste"
    if "market" in url or "store" in url: return "market"
    if "leak" in url or "dump" in url: return "leak"
    return "unknown"

def crawl_onion(url):
    try:
        headers = {'User-Agent': 'Ghostcrawler/1.0'}
        response = requests.get(url, headers=headers, timeout=15)
        soup = BeautifulSoup(response.text, "html.parser")
        text = soup.get_text()

        # 🔎 Keyword matching
        matches = [kw for kw in keywords if re.search(re.escape(kw), text, re.IGNORECASE)]

        # 💾 Save snapshot
        fname = f"{url.replace('http://', '').replace('https://', '').replace('/', '_')}.html"
        with open(SNAPSHOT_DIR / fname, "w", encoding="utf-8") as f:
            f.write(response.text)

        # 🧅 Recursive discovery
        found_onions = extract_onions(response.text)
        for o in found_onions:
            tag = classify_onion(o)
            cursor.execute("INSERT OR IGNORE INTO onions (url, source, tag) VALUES (?, ?, ?)", (o, "recursive", tag))

        conn.commit()

        return {
            "url": url,
            "matches": matches,
            "found_onions": found_onions,
            "snapshot_file": fname
        }
    except Exception as e:
        return {
            "url": url,
            "error": str(e)
        }

# Optional: CLI entrypoint for testing
if __name__ == "__main__":
    test_url = "http://exampleonion123.onion"
    result = crawl_onion(test_url)
    print(json.dumps(result, indent=2))
