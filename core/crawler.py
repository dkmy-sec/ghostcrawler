import os
import re
import json
import threading
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from requests_tor import RequestsTor
from core.identity import rotate_identity
from pathlib import Path
from datetime import datetime

# Setup
WATCHLIST_PATH = Path("data/watchlist.json")
SNAPSHOT_DIR = Path("data/snapshots")
ALERTS_PATH = Path("data/alerts.json")
SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)

# Load watchlist
with open(WATCHLIST_PATH) as f:
    watchlist = json.load(f)
    keywords = [item for sub in watchlist.values() for item in sub]

# Initialize shared alert log
lock = threading.Lock()
if ALERTS_PATH.exists():
    with open(ALERTS_PATH) as f:
        alerts = json.load(f)
else:
    alerts = []

def crawl_onion(url, session, rotate_every=5):
    visited = set()
    to_visit = [url]
    hits = []
    counter = 0

    while to_visit:
        current = to_visit.pop()
        if current in visited or not current.startswith("http"):
            continue

        if counter > 0 and counter % rotate_every == 0:
            rotate_identity(session)
        counter += 1

        try:
            response = session.get(current, timeout=15)
            soup = BeautifulSoup(response.text, "html.parser")
            text = soup.get_text()

            found = [kw for kw in keywords if re.search(re.escape(kw), text, re.IGNORECASE)]
            if found:
                print(f"[+] Match on {current}: {found}")
                with lock:
                    alerts.append({
                        "url": current,
                        "base": url,
                        "matched": found,
                        "timestamp": datetime.utcnow().isoformat()
                    })

            # Save snapshot
            host = urlparse(url).netloc
            filename = f"{host}_{datetime.utcnow().timestamp()}.html"
            with open(SNAPSHOT_DIR / filename, "w", encoding="utf-8") as f:
                f.write(response.text)

            visited.add(current)

            # Enqueue new links
            for link in soup.find_all("a", href=True):
                abs_url = urljoin(current, link['href'])
                if ".onion" in abs_url and abs_url not in visited:
                    to_visit.append(abs_url)

        except Exception as e:
            print(f"[!] Error fetching {current}: {e}")

    # Save alert log
    with lock:
        with open(ALERTS_PATH, "w") as f:
            json.dump(alerts, f, indent=2)

# Entry point for threading or CLI
if __name__ == "__main__":
    test_url = input("Enter a .onion URL to crawl: ").strip()
    session = RequestsTor(tor_ports=(9050,), autochange_id=False)
    crawl_onion(test_url, session)
