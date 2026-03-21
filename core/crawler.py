import json, re, sqlite3, threading
import logging
from pathlib import Path
from queue import Queue
import sys
from datetime import datetime, timezone
import time
from bs4 import BeautifulSoup
from requests_tor import RequestsTor

sys.path.append(str(Path(__file__).resolve().parent.parent))
from core.identity import rotate_identity
from core.utils import DATA_DIR
from core.safeguard import is_high_risk

SAVE_PATH = DATA_DIR / "seed_onions.txt"
SNAPSHOT_DIR = DATA_DIR / "snapshots"
WATCHLIST_PATH = DATA_DIR / "watchlist.json"
DB_PATH = DATA_DIR / "onion_sources.db"
FLAG_LOG = DATA_DIR / "csam_alerts.json"

SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)

# --- Watchlist ---
with open(WATCHLIST_PATH, "r", encoding="utf-8") as f:
    watchlist = json.load(f)
    keywords = [item for sublist in watchlist.values() for item in sublist]

# --- DB Setup ---
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Table for onions
cursor.execute("""
               CREATE TABLE IF NOT EXISTS onions
               (
                   id
                   INTEGER
                   PRIMARY
                   KEY
                   AUTOINCREMENT,
                   url
                   TEXT
                   UNIQUE,
                   source
                   TEXT,
                   tag
                   TEXT,
                   live
                   INTEGER
                   DEFAULT
                   1,
                   last_seen
                   TIMESTAMP
                   DEFAULT
                   CURRENT_TIMESTAMP,
                   depth
                   INTEGER
                   DEFAULT
                   0
               )
               """)

# Table for harvested data leaks
cursor.execute("""
               CREATE TABLE IF NOT EXISTS data_leaks
               (
                   id
                   INTEGER
                   PRIMARY
                   KEY
                   AUTOINCREMENT,
                   url
                   TEXT,
                   leak_type
                   TEXT,
                   value
                   TEXT,
                   snippet
                   TEXT,
                   timestamp
                   TIMESTAMP
                   DEFAULT
                   CURRENT_TIMESTAMP
               )
               """)
conn.commit()

session = RequestsTor(tor_ports=(9050,), autochange_id=False)
rotate_interval = 5
counter = 0

# --- Regex Patterns for OSINT ---
ONION_REGEX = r"http[s]?://[a-zA-Z0-9\-\.]{10,100}\.onion"
FILE_LINK_REGEX = r'href="([^"]+\.(txt|sql|csv|json|db))"'

EMAIL_REGEX = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
API_KEY_REGEX = r'(?i)(api[_-]?key|apikey|secret|token)[\s:]*["\']?([A-Za-z0-9\-._~+/]+=*)["\']?'
HASH_REGEX = r'(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})'
PRIVATE_KEY_REGEX = r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'
CC_REGEX = r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'


def extract_onions(text, include_files=False):
    if include_files:
        return list(set(re.findall(FILE_LINK_REGEX, text)))
    return list(set(re.findall(ONION_REGEX, text)))


def classify_onion(url):
    if "forum" in url: return "forum"
    if "paste" in url: return "paste"
    if "market" in url or "store" in url: return "market"
    if "leak" in url or "dump" in url: return "leak"
    return "unknown"


def harvest_leaks(text, url):
    """Extracts sensitive data from text and returns a list of dicts."""
    results = []

    # Find Emails
    for email in re.findall(EMAIL_REGEX, text):
        results.append({
            'type': 'email',
            'value': email,
            'snippet': text[text.find(email):text.find(email) + 50] if len(text) > 50 else text
        })

    # Find API Keys
    for match in re.finditer(API_KEY_REGEX, text):
        key = match.group(2)
        results.append({
            'type': 'api_key',
            'value': key,
            'snippet': match.group(0)
        })

    # Find Hashes
    for hash_val in re.findall(HASH_REGEX, text):
        results.append({
            'type': 'hash',
            'value': hash_val,
            'snippet': text[text.find(hash_val):text.find(hash_val) + 20]
        })

    # Find Private Keys
    for match in re.finditer(PRIVATE_KEY_REGEX, text):
        results.append({
            'type': 'private_key',
            'value': match.group(0),
            'snippet': match.group(0)
        })

    return results


def crawl_onion(url, depth=0, max_depth=4):
    global counter
    try:
        if counter > 0 and counter % rotate_interval == 0:
            rotate_identity(session)
        counter += 1

        headers = {'User-Agent': 'Ghostcrawler/1.0'}
        resp = session.get(url, headers=headers, timeout=20)
        html = resp.text

        # Quarantine check
        if is_high_risk(url, html):
            cursor.execute(
                "UPDATE onions SET quarantined=1, reason=? WHERE url=?",
                ("high_risk", url)
            )
            conn.commit()
            return {"url": url, "error": "quarantined", "found_onions": []}

        soup = BeautifulSoup(html, "html.parser")
        text = soup.get_text(" ", strip=True)

        # Snapshot
        fname = f"{url.replace('http://', '').replace('https://', '').replace('/', '_')}.html"
        (SNAPSHOT_DIR / fname).write_text(html, encoding="utf-8", errors="ignore")

        # --- DATA HARVESTING INTEGRATION ---
        leak_data = harvest_leaks(text, url)

        # Save Leaks to DB
        for leak in leak_data:
            cursor.execute("""
                           INSERT INTO data_leaks (url, leak_type, value, snippet)
                           VALUES (?, ?, ?, ?)
                           """, (url, leak['type'], leak['value'], leak['snippet']))

        conn.commit()
        # --- END HARVESTING ---

        # Determine what to extract based on depth
        is_deep_crawl = depth > 0
        found_links = extract_onions(text, include_files=is_deep_crawl)

        # Write discoveries to DB
        for link in found_links:
            tag = classify_onion(link)
            cursor.execute(
                "INSERT OR IGNORE INTO onions (url, source, tag, depth, quarantined) VALUES (?, ?, ?, ?, 0)",
                (link, url, tag, depth + 1)
            )

        conn.commit()

        # RECURSION
        if depth < max_depth:
            for link in found_links:
                if not link.endswith(('.txt', '.sql', '.json', '.csv', '.db')):
                    crawl_onion(link, depth + 1, max_depth)

        return {"url": url, "snapshot_file": fname, "found_onions": len(found_links)}

    except Exception as e:
        logging.error(f"Error crawling {url}: {e}")
        return {"url": url, "error": str(e), "found_onions": []}


# Threaded control
MAX_THREADS = 10
onion_queue = Queue()


def threaded_worker():
    while not onion_queue.empty():
        onion_url = onion_queue.get()
        crawl_onion(onion_url)
        onion_queue.task_done()


def threaded_crawl(onion_list):
    for url in onion_list:
        onion_queue.put(url)

    threads = []
    for _ in range(min(MAX_THREADS, len(onion_list))):
        t = threading.Thread(target=threaded_worker)
        t.daemon = True
        t.start()
        threads.append(t)

    onion_queue.join()
    for t in threads:
        t.join()


if __name__ == "__main__":
    # Start with a seed list
    seed_list = [
        "http://vice2rsunli3mauak6wppu4poycjco4aj4h7rcgmf7p6eyiqzywxglid.onion",
        "http://w5uxy4q6j6c3j4y6u2xk5zq7o8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z.onion"  # Example seed
    ]
    threaded_crawl(seed_list)