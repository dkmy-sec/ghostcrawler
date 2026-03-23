import sys
from requests_tor import RequestsTor
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))
from core.identity import rotate_identity
from bs4 import BeautifulSoup

import sqlite3
import json
import re
import time

HEADERS = {'User-Agent': 'Mozilla/5.0'}
DB_PATH = Path("data/onion_links.db")
SEED_PATH = Path("data/seed_onions.txt")


# Setup database
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
ROTATE_EVERY = 5
counter = 0

# Load .onion seed URLs
with open(SEED_PATH) as f:
    seed_onions = [line.strip() for line in f if ".onion" in line]

# Scan homepage content for matches
def scan_homepage(url):
    global counter
    if counter > 0 and counter % ROTATE_EVERY == 0:
        rotate_identity(session)
    counter += 1

    try:
        res = session.get(url, headers=HEADERS, timeout=15)
        soup = BeautifulSoup(res.text, 'html.parser')
        content = soup.get_text()
        matches = [kw for kw in keywords if re.search(re.escape(kw), content, re.IGNORECASE)]
        return matches
    except Exception as e:
        print(f"[!] Failed to scan {url}: {e}")
        return []

# Start scan loop
for url in seed_onions:
    print(f"[*] Scanning: {url}")
    matches = scan_homepage(url)
    for kw in matches:
        cursor.execute(
            "INSERT OR IGNORE INTO onion_links (url, source, keyword, found_match) VALUES (?, ?, ?, ?)",
            (url, "seed_list", kw, kw)
        )
        print(f"[+] Match: '{kw}' on {url}")
    time.sleep(0.5)

conn.commit()
conn.close()
print("[✓] Mass scan complete.")
