from requests_tor import RequestsTor
from identity import rotate_identity
import re
import sqlite3
import json
from bs4 import BeautifulSoup
from datetime import datetime
from pathlib import Path

HEADERS = {'User-Agent': 'Mozilla/5.0'}
DB_PATH = Path("data/onion_links.db")
WATCHLIST_PATH = Path("data/watchlist.json")
SEED_PATH = Path("data/seed_onions.txt")

# Load watchlist
with open(WATCHLIST_PATH) as f:
    watchlist = json.load(f)
    keywords = [item for sublist in watchlist.values() for item in sublist]

# Create DB connection
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS onion_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE,
    source TEXT,
    keyword TEXT,
    found_match TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

# Setup Tor session
session = RequestsTor(tor_ports=(9050,), autochange_id=False)
rotate_interval = 5
counter = 0

# Util to extract .onion links
def extract_onions(text):
    return set(re.findall(r"http[s]?://[\w\.-]+\.onion", text))

# Util to scan a page for watchlist hits
def scan_page_for_hits(url):
    global counter
    if counter > 0 and counter % rotate_interval == 0:
        rotate_identity(session)
    counter += 1
    try:
        response = session.get(url, headers=HEADERS, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')
        content = soup.get_text()
        matches = [kw for kw in keywords if re.search(re.escape(kw), content, re.IGNORECASE)]
        return matches
    except Exception as e:
        print(f"[!] Failed to scan {url}: {e}")
        return []

# 1. Load seed .onion list manually retrieved
if SEED_PATH.exists():
    with open(SEED_PATH) as f:
        seed_onions = [line.strip() for line in f if ".onion" in line]
else:
    print("[!] No seed_onions.txt file found.")
    seed_onions = []

# 2. Brute-scan each .onion for homepage content + matches
for url in seed_onions:
    print(f"[*] Scanning: {url}")
    matches = scan_page_for_hits(url)
    for kw in matches:
        cursor.execute(
            "INSERT OR IGNORE INTO onion_links (url, source, keyword, found_match) VALUES (?, ?, ?, ?)",
            (url, "seed_list", kw, kw)
        )
        print(f" [+] Match found for '{kw}' on {url}")

# Commit and close
conn.commit()
conn.close()
print("[✓] Onion scan completed.")
