import json, re, sqlite3, threading
from pathlib import Path
from queue import Queue
import sys
from datetime import datetime, timezone


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

# --- DB ---
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS onions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE,
    source TEXT,
    tag TEXT,
    live INTEGER DEFAULT 1,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    depth INTEGER DEFAULT 0
)
""")
conn.commit()

session = RequestsTor(tor_ports=(9050,), autochange_id=False)
rotate_interval = 5
counter = 0

ONION_REGEX = r"http[s]?://[a-zA-Z0-9\-\.]{10,100}\.onion"

def extract_onions(text):
    return list(set(re.findall(ONION_REGEX, text)))

def classify_onion(url):
    if "forum" in url: return "forum"
    if "paste" in url: return "paste"
    if "market" in url or "store" in url: return "market"
    if "leak" in url or "dump" in url: return "leak"
    return "unknown"

def crawl_onion(url, depth=0, max_depth=3):
    global counter
    try:
        if counter > 0 and counter % rotate_interval == 0:
            rotate_identity(session)
        counter += 1

        headers = {'User-Agent': 'Ghostcrawler/1.0'}
        resp = session.get(url, headers=headers, timeout=20)
        html = resp.text

        # Quarantine check (don’t store snapshot if risky)
        if is_high_risk(url, html):
            cursor.execute(
                "UPDATE onions SET quarantined=1, reason=? WHERE url=?",
                ("high_risk", url)
            )
            conn.commit()
            return {"url": url, "error": "quarantined", "found_onions": []}

        soup = BeautifulSoup(html, "html.parser")
        text = soup.get_text(" ", strip=True)

        # snapshot (only safe pages)
        fname = f"{url.replace('http://','').replace('https://','').replace('/','_')}.html"
        (SNAPSHOT_DIR / fname).write_text(html, encoding="utf-8", errors="ignore")

        found = extract_onions(html)

        # write discoveries to DB (no recursion here, frontier handles it)
        for link in found:
            tag = classify_onion(link)
            cursor.execute(
                "INSERT OR IGNORE INTO onions (url, source, tag, depth, quarantined) VALUES (?, ?, ?, ?, 0)",
                (link, url, tag, depth + 1)
            )

        conn.commit()
        return {"url": url, "snapshot_file": fname, "found_onions": found}

    except Exception as e:
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
    test_url = "http://vice2rsunli3mauak6wppu4poycjco4aj4h7rcgmf7p6eyiqzywxglid.onion"
    crawl_onion(test_url)
