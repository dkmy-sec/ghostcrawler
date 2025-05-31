# crawler logic
import os
import json
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from requests_tor import RequestsTor
from core.scanner import scan
from core.identity import rotate_identity

# Configs
EXPORT_DIR = "data"
SNAPSHOT_DIR = os.path.join(EXPORT_DIR, "snapshots")
LOG_PATH = os.path.join(EXPORT_DIR, "logs", "alerts.json")

os.makedirs(SNAPSHOT_DIR, exist_ok=True)
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

session = RequestsTor(tor_ports=(9050,), tor_cport=9051)
visited = set()
alerts = []

def is_onion(url):
    hostname = urlparse(url).hostname
    return hostname and hostname.endswith(".onion")

def save_snapshot(url, html):
    hostname = urlparse(url).hostname.replace(".", "_")
    with open(f"{SNAPSHOT_DIR}/{hostname}.html", "w", encoding="utf-8") as f:
        f.write(html)

def crawl_pages(start_url, watchlist, max_depth=3, auto_rotate=True):
    def crawl(url, depth):
        if url in visited or depth > max_depth:
            return
        visited.add(url)

        try:
            print(f"[+] Crawling: {url}")
            r = session.get(url, timeout=30)
            html = r.text
            soup = BeautifulSoup(html, "html.parser")
            save_snapshot(url, html)

            matches = scan(html, watchlist)
            if matches:
                print(f"[!] ALERT: Sensitive data found on {url}")
                alerts.append({"url": url, "matches": matches})
                for m in matches:
                    print("   ->", m)

            for a in soup.find_all("a", href=True):
                link = urljoin(url, a["href"])
                if is_onion(link):
                    crawl(link, depth + 1)

            if auto_rotate and len(visited) % 5 == 0:
                rotate_identity(session)

        except Exception as e:
            print(f"[x] Failed to crawl {url}: {e}")

    # Start crawl
    crawl(start_url, 0)

    # Save alerts
    with open(LOG_PATH, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)
