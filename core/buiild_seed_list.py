import requests
from requests_tor import RequestsTor
from bs4 import BeautifulSoup
import re
import sqlite3
from pathlib import Path


ONION_REGEX = r"http[s]?://[a-zA-Z0-9\-\.]{10,100}\.onion"
HEADERS = {"User-Agent": "GhostcrawlerBot/1.0"}
SAVE_PATH = Path("data/seed_onions.txt")
DB_PATH = Path("data/onion_sources.db")


sources = {
    "dark.fail": "http://darkfailenbsdla5mal2mxn2uz66od5vtzd5qozslagrfzachha3f3id.onion/",
    "tor66": "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/",
    "ahmia": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/",
    "deeplinksdump": "http://deepqelxz6iddqi5obzla2bbwh5ssyqqobxin27uzkr624wtubhto3ad.onion/",
    "bobby": "http://bobby64o755x3gsuznts6hf6agxqjcz5bop6hs7ejorekbm7omes34ad.onion/",
    "torch": "http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion/cgi-bin/omega/omega",
    "haystack": "http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/",
    "deepsearch": "http://search7tdrcvri22rieiwgi5g46qnwsesvnubqav2xakhezv4hjzkkad.onion/",
    "tordex": "http://tordexpmg4xy32rfp4ovnz7zq5ujoejwq2u26uxxtkscgo5u3losmeid.onion/",
    "vormweb": "http://volkancfgpi4c7ghph6id2t7vcntenuly66qjt6oedwtjmyj4tkk5oqd.onion/",
    "excavator": "http://2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad.onion/",
    "torland": "http://torlgu6zhhtwe73fdu76uiswgnkfvukqfujofxjfo7vzoht2rndyhxyd.onion/",
    # Add more aggregators as found
}


SAVE_PATH.parent.mkdir(parents=True, exist_ok=True)
SAVE_PATH.write_text("") # Clean slate


# SETUP DB
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS onions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE,
    source TEXT,
    tag TEXT,
    live INTEGER DEFAULT 1,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")


def extract_onions(text):
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

for source, url in sources.items():
    print(f"[+] Crawling {source} - {url}")
    try:
        response = requests.get(url, headers=HEADERS, timeout=15)
        onions = extract_onions(response.text)
        for o in onions:
            tag = classify_onion(o)
            SAVE_PATH.write_text(o + "\n", append=True)
            cursor.execute("INSERT OR IGNORE INTO onions (url, source, tag) VALUES (?, ?, ?)", (o, source, tag))
    except Exception as e:
        print(f"[!] Error with {url}: {e}")


conn.commit()
conn.close()
print("✓ Onion list updated and stored.")
