import json, re, sqlite3, threading
from pathlib import Path
from queue import Queue
import sys

from bs4 import BeautifulSoup
from requests_tor import RequestsTor

sys.path.append(str(Path(__file__).resolve().parent.parent))
from core.identity import rotate_identity
from core.utils import DATA_DIR

SAVE_PATH = DATA_DIR / "seed_onions.txt"
SNAPSHOT_DIR = DATA_DIR / "snapshots"
WATCHLIST_PATH = DATA_DIR / "watchlist.json"
DB_PATH = DATA_DIR / "onion_sources.db"

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

def crawl_onion(url, depth=2, max_depth=3):
    global counter
    try:
        if counter > 0 and counter % rotate_interval == 0:
            rotate_identity(session)
        counter += 1

        print(f"[-] Crawling {url} (depth {depth})")
        headers = {'User-Agent': 'Ghostcrawler/1.0'}
        response = session.get(url, headers=headers, timeout=20)
        soup = BeautifulSoup(response.text, "html.parser")
        text = soup.get_text()

        # Save snapshot
        fname = f"{url.replace('http://', '').replace('https://', '').replace('/', '_')}.html"
        with open(SNAPSHOT_DIR / fname, "w", encoding="utf-8") as f:
            f.write(response.text)

        # Match keywords
        matches = [kw for kw in keywords if re.search(re.escape(kw), text, re.IGNORECASE)]

        # Extract & store .onion links
        found_onions = extract_onions(response.text)
        for link in found_onions:
            tag = classify_onion(link)
            cursor.execute(
                "INSERT OR IGNORE INTO onions (url, source, tag, depth) VALUES (?, ?, ?, ?)",
                (link, url, tag, depth + 1)
            )
            with SAVE_PATH.open("a", encoding="utf-8") as f:
                f.write(link + "\n")
            print(f"[+] Found .onion link: {link} (depth {depth + 1})")

            # Recursive crawl
            if depth + 1 <= max_depth:
                crawl_onion(link, depth + 1, max_depth)

        conn.commit()

        return {
            "url": url,
            "matches": matches,
            "snapshot_file": fname
        }

    except Exception as e:
        return {"url": url, "error": str(e)}

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
