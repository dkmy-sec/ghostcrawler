import requests
import re
import sqlite3
from pathlib import Path
from bs4 import BeautifulSoup


# Output Paths
SEED_FILE = Path("data/seed_onions.txt")
DB_FILE = Path("data/onion_sources.db")
SEED_FILE.parent.mkdir(parents=True, exist_ok=True)


ONION_REGEX = r"http[s]?://[a-zA-Z0-9\-\.]{10,100}\.onion"


# Github repos with raw onion data
GITHUB_RAW_SOURCES = [
    "https://raw.githubusercontent.com/alecmuffett/real-world-onion-sites/master/README.md",
    "https://raw.githubusercontent.com/Giddyspurz/Dark-Web-Links/refs/heads/main/Ransomware-Sites.txt",
    "https://raw.githubusercontent.com/Giddyspurz/Dark-Web-Links/refs/heads/main/Marketplaces.txt",

]


# Reddit posts to scrape (use RSS or manually curated links)
REDDIT_THREAD_URLS = [
    "https://www.reddit.com/r/onions/comments/15dszqz/megathread_working_onion_sites_july_2023/"
]


# DB Setup
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS onions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE,
    source TEXT,
    tags TEXT,
    live INTEGER DEFAULT 1,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")


def extract_onion(text):
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


def save_onions(onions, source):
    new_onions = []
    for o in onions:
        tag = classify_onion(o)
        cursor.execute("INSERT OR IGNORE INTO onions (url, source, tag) VALUES (?, ?, ?)", (o, source, tag))
        new_onions.append(o)
        if new_onions:
            with SEED_FILE.open("a", encoding="utf-8") as f:
                for o in new_onions:
                    f.write(o + "\n")


# Pull from Github raw markdown/plaintext lists
for url in GITHUB_RAW_SOURCES:
    print(f"[GH] Fetching {url}")
    try:
        resp = requests.get(url, timeout=10)
        links = extract_onion(resp.text)
        save_onions(links, "github")
    except Exception as e:
        print(f"[!] Github fetch error: {e}")


# Pull from Reddit post HTML pages (can switch to PRAW later)
for url in REDDIT_THREAD_URLS:
    print(f"[Reddit] Scraping {url}")
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")
        text = soup.get_text()
        links = extract_onions(text)
        save_onions(links, "reddit")
    except Exception as e:
        print(f"[!] Reddit fetch failed: {e}")


conn.commit()
conn.close()
print("[✓] Onion aggregation complete.")