import requests
from requests_tor import RequestsTor
from bs4 import BeautifulSoup
import re
import sqlite3
from pathlib import Path


ONION_REGEX = r"http[s]?://[a-zA-Z0-9\-\.]{10,100}\.onion"
HEADERS = {"User-Agent": "GhostcrawlerBot/1.0"}
SAVE_PATH = Path("data/seed_onions.txt")
DB_PATH = Path("data/onion_sources.db")


sources = {
    "dark.fail":"",
    "tor66":"",
    "ahima":"",
    "onion.live":"",
    "onion.directory":"",
    # Add more aggregators as found
}


SAVE_PATH.parent.mkdir(parents=True, exist_ok=True)
SAVE_PATH.write_text("") # Clean slate


# SETUP DB
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
    # Primitive tagging based on patterns
    if any(x in url for x in ["hub","forum","dread"]):
        return "forum"
    if "paste" in url:
        return "paste"
    if "market" in url or "store" in url:
        return "market"
    if "leak" in url or "dump" in url:
        return "leak"
    return "unknown"

for source, url in sources.items():
    print(f"[+] Crawling {source} - {url}")
    try:
        response = requests.get(url, headers=HEADERS, timeout=15)
        onions = extract_onions(response.text)
        for o in onions:
            tag = classify_onion(o)
            SAVE_PATH.write_text(o + "\n", append=True)
            cursor.execute("INSERT OR IGNORE INTO onions (url, source, tag) VALUES (?, ?, ?)", (o, source, tag))
    except Exception as e:
        print(f"[!] Error with {url}: {e}")


conn.commit()
conn.close()
print("✓ Onion list updated and stored.")
