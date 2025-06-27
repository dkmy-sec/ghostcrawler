import re
import sqlite3
import requests
from pathlib import Path
from bs4 import BeautifulSoup

ONION_REGEX = r"http[s]?://[a-zA-Z0-9\-\.]{10,100}\.onion"
SAVE_PATH = Path("data/seed_onions.txt")
DB_PATH = Path("data/onion_sources.db")

SAVE_PATH.parent.mkdir(parents=True, exist_ok=True)

# --- Extract function ---
def extract_onions(text):
    return list(set(re.findall(ONION_REGEX, text)))

# --- DB Setup ---
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS onions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE,
    source TEXT,
    tag TEXT DEFAULT 'unknown',
    live INTEGER DEFAULT 1,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

# --- Sources ---
GITHUB_RAW_SOURCES = [
    "https://raw.githubusercontent.com/alecmuffett/real-world-onion-sites/master/README.md",
    "https://raw.githubusercontent.com/Giddyspurz/Dark-Web-Links/refs/heads/main/Ransomware-Sites.txt",
    "https://raw.githubusercontent.com/Giddyspurz/Dark-Web-Links/refs/heads/main/Marketplaces.txt",
]

REDDIT_THREAD_URLS = [
    "https://www.reddit.com/r/onions/comments/15dszqz/megathread_working_onion_sites_july_2023/"
]

headers = {"User-Agent": "GhostcrawlerBot/1.0"}

# --- GitHub Pull ---
for url in GITHUB_RAW_SOURCES:
    print(f"[GH] Fetching {url}")
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        links = extract_onions(resp.text)
        for o in links:
            with SAVE_PATH.open("a", encoding="utf-8") as f:
                f.write(o + "\n")
            cursor.execute("INSERT OR IGNORE INTO onions (url, source, tag) VALUES (?, ?, ?)", (o, url, "github"))
    except Exception as e:
        print(f"[!] Github fetch error: {e}")

# --- Reddit Pull ---
for thread_url in REDDIT_THREAD_URLS:
    print(f"[Reddit] Scraping {thread_url}")
    try:
        resp = requests.get(thread_url, headers=headers, timeout=15)
        soup = BeautifulSoup(resp.text, "html.parser")
        text = soup.get_text()
        onions = extract_onions(text)
        for o in onions:
            with SAVE_PATH.open("a", encoding="utf-8") as f:
                f.write(o + "\n")
            cursor.execute("INSERT OR IGNORE INTO onions (url, source, tag) VALUES (?, ?, ?)",
                           (o, thread_url, "reddit"))
    except Exception as e:
        print(f"[!] Reddit fetch failed: {e}")

conn.commit()
conn.close()
print("[✓] Onion aggregation complete.")
