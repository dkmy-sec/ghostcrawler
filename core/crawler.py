import sqlite3
import re
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from requests_tor import RequestsTor
from pathlib import Path
import logging

# Import DATA_DIR from your project structure
try:
    from core.utils import DATA_DIR
except ImportError:
    # Fallback if run standalone
    DATA_DIR = Path(__file__).parent.parent / "data"

DB_PATH = DATA_DIR / "onion_sources.db"


# --- TOR SESSION SETUP ---
def get_tor_session():
    return RequestsTor(tor_ports=(9050,), autochange_id=False)


# --- REGEX PATTERNS ---
EMAIL_REGEX = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
API_KEY_REGEX = r'(?i)(api[_-]?key|apikey|secret|token)[\s:]*["\']?([A-Za-z0-9\-._~+/]+=*)["\']?'
HASH_REGEX = r'(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})'
PRIVATE_KEY_REGEX = r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'
CC_REGEX = r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'


def get_connection():
    return sqlite3.connect(DB_PATH)


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
    session = get_tor_session()

    try:
        # Identity Rotation
        if hasattr(session, 'reset_identity'):
            session.reset_identity()

        headers = {'User-Agent': 'Ghostcrawler/1.0'}
        resp = session.get(url, headers=headers, timeout=20)
        html = resp.text

        # Save Snapshot
        SNAPSHOT_DIR = DATA_DIR / "snapshots"
        fname = f"{url.replace('http://', '').replace('https://', '').replace('/', '_')}.html"
        (SNAPSHOT_DIR / fname).write_text(html, encoding="utf-8", errors="ignore")

        soup = BeautifulSoup(html, "html.parser")
        text = soup.get_text(" ", strip=True)

        # --- 1. DATA LEAK HARVESTING INTEGRATION ---
        leak_data = harvest_leaks(text, url)

        # Save Leaks to DB
        conn = get_connection()
        for leak in leak_data:
            try:
                conn.execute("""
                             INSERT INTO data_leaks (url, leak_type, value, snippet)
                             VALUES (?, ?, ?, ?)
                             """, (url, leak['type'], leak['value'], leak['snippet']))
            except sqlite3.Error as e:
                logging.error(f"DB Error saving leak: {e}")
        conn.commit()
        conn.close()
        # --- END HARVESTING ---

        # --- 2. LINK DISCOVERY ---
        found_links = []
        if ".onion" in url:
            # Find other onion links
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                if ".onion" in full_url:
                    found_links.append(full_url)
        else:
            # Clear web logic (optional, for future expansion)
            pass

        # Write discoveries to DB (onions table)
        conn = get_connection()
        for link in found_links:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR IGNORE INTO onions (url, source, tag, depth, quarantined) VALUES (?, ?, ?, ?, 0)",
                (link, url, 'unknown', depth + 1)
            )
        conn.commit()
        conn.close()

        # --- 3. RECURSION ---
        if depth < max_depth:
            for link in found_links:
                crawl_onion(link, depth + 1, max_depth)

        return {"url": url, "snapshot_file": fname, "found_onions": len(found_links)}

    except Exception as e:
        logging.error(f"Error crawling {url}: {e}")
        return {"url": url, "error": str(e), "found_onions": []}