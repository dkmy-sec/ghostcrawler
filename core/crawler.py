import json
import re
import sqlite3
import threading
from pathlib import Path
from queue import Queue

from bs4 import BeautifulSoup
from requests_tor import RequestsTor

sys.path.append(str(Path(__file__).resolve().parent.parent))
from core.identity import rotate_identity

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
               CREATE TABLE IF NOT EXISTS onions
               (
                   id        INTEGER PRIMARY KEY AUTOINCREMENT,
                   url       TEXT UNIQUE,
                   source    TEXT,
                   tag       TEXT,
                   live      INTEGER   DEFAULT 1,
                   last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
               )
               """)

# Setup Tor session with optional identity rotation
session = RequestsTor(tor_ports=(9050), autochange_id=False)
rotate_interval = 5
counter = 0


def extract_onions(text):
    return list(set(re.findall(ONION_REGEX, text)))


def classify_onion(url):
    if "forum" in url: return "forum"
    if "paste" in url: return "paste"
    if "market" in url or "store" in url: return "market"
    if "leak" in url or "dump" in url: return "leak"
    return "unknown"


def crawl_onion(url):
    global counter
    try:
        # Identity rotation every N requests
        if counter > 0 and counter % rotate_interval == 0:
            rotate_identity(session)
        counter += 1
        print(f"[-] Crawling {url} via Tor")
        headers = {'User-Agent': 'Ghostcrawler/1.0'}
        response = session.get(url, headers=headers, timeout=20)
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


# Optional: limit concurrency to prevent overload or bans
MAX_THREADS = 10
onion_queue = Queue()


def threaded_worker():
    while not onion_queue.empty():
        onion_url = onion_queue.get()
        result = crawl_onion(onion_url)
        if result.get("matches"):
            print(f"[+] {onion_url} matched: {result['matches']}")
        elif result.get("error"):
            print(f"[!] {onion_url} failed: {result['error']}")
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


# Optional: CLI entrypoint for testing
if __name__ == "__main__":
    test_url = "http://exampleonion123.onion"
    result = crawl_onion(test_url)
    print(json.dumps(result, indent=2))
