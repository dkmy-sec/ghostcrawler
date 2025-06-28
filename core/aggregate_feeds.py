# aggregate_feeds.py  (place in core/ or top-level – your choice)
import re, json, sqlite3, requests, time
from pathlib import Path
from bs4 import BeautifulSoup

from core.utils       import DATA_DIR          # <- project-root aware
from core.crawler     import classify_onion    # reuse your tag logic
from core.safeguard   import is_high_risk, BAD_WORDS   # skip nasty stuff

# ---------- Constants ----------
ONION_RGX = re.compile(r"http[s]?://[a-zA-Z0-9\-\.]{10,100}\.onion")
DB_PATH   = DATA_DIR / "onion_sources.db"
SEED_TXT  = DATA_DIR / "seed_onions.txt"
HEADERS   = {"User-Agent": "GhostcrawlerBot/2.0"}

SEED_TXT.parent.mkdir(exist_ok=True)
SEED_TXT.touch(exist_ok=True)

# Load existing seeds to avoid dupes
seen_seeds = set(SEED_TXT.read_text(encoding="utf-8").splitlines())

# ---------- Source Definitions ----------
SOURCES = {
    # --- GitHub / GitLab raw text lists ---
    "github:alecmuffett": "https://raw.githubusercontent.com/alecmuffett/real-world-onion-sites/master/README.md",
    "github:giddy-ransom": "https://raw.githubusercontent.com/Giddyspurz/Dark-Web-Links/main/Ransomware-Sites.txt",
    "github:giddy-market": "https://raw.githubusercontent.com/Giddyspurz/Dark-Web-Links/main/Marketplaces.txt",

    # --- Paste + text dumps (raw) ---
    "pastebin:masterdump": "https://pastebin.com/raw/qW6i44bE",
    "hastebin:mirrors":    "https://hastebin.com/raw/ozogawuxup",

    # --- HTML onion directories (surface net) ---
    "dir:tordir":    "https://tordir.org/",
    "dir:tor.taxi":  "https://onion.taxi/",

    # --- Surface-net scrape ---
    "dir:darkwebinformer": "https://darkwebinformer.com/",

    # --- Telegram groups (only if credentials present) ---
    # Format:  tg:<channel_username>
    "tg:onion_updates":  "tg://onion_updates_channel",
    "tg:darkwebinformer":  "tg://darkwebinformer",

}

# ---------- Telegram (optional) ----------
TELEGRAM_ACTIVE = False
try:
    from telethon import TelegramClient     # pip install telethon
    from telethon.errors import SessionPasswordNeededError
    import os

    API_ID   = int(os.getenv("TG_API_ID", 0))
    API_HASH = os.getenv("TG_API_HASH", "")
    if API_ID and API_HASH:
        TELEGRAM_ACTIVE = True
        tg_client = TelegramClient("ghostcrawler", API_ID, API_HASH)
except ImportError:
    pass   # Telethon not installed – skip TG sources gracefully


# ---------- Helper ----------
def extract_onions(text: str):
    return set(ONION_RGX.findall(text))

def fetch_http(url):
    r = requests.get(url, headers=HEADERS, timeout=20)
    r.raise_for_status()
    return r.text

def save_onion(url:str, source:str, cursor):
    if url in seen_seeds:
        return
    if is_high_risk(url, url):          # quick keyword check on URL
        return
    tag = classify_onion(url)
    cursor.execute(
        "INSERT OR IGNORE INTO onions (url, source, tag) VALUES (?, ?, ?)",
        (url, source, tag)
    )
    with SEED_TXT.open("a", encoding="utf-8") as f:
        f.write(url + "\n")
    seen_seeds.add(url)

# ---------- DB Setup ----------
conn = sqlite3.connect(DB_PATH)
cur  = conn.cursor()
cur.execute("""
CREATE TABLE IF NOT EXISTS onions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE,
    source TEXT,
    tag TEXT,
    live INTEGER DEFAULT 1,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")
conn.commit()

# ---------- Main Loop ----------
total_new = 0
for name, link in SOURCES.items():
    print(f"[+] {name} → {link}")
    try:
        if link.startswith("tg://"):
            if not TELEGRAM_ACTIVE:
                print("    ↳  Telegram disabled (no creds). Skipping.")
                continue
            channel = link[5:]
            tg_client.start()
            async def grab_tg():
                async for msg in tg_client.iter_messages(channel, limit=200):
                    onions = extract_onions(msg.message or "")
                    for o in onions:
                        save_onion(o, name, cur)
                await tg_client.disconnect()
            tg_client.loop.run_until_complete(grab_tg())
        else:
            raw = fetch_http(link)
            if link.endswith(".html") or "<html" in raw.lower():
                raw = BeautifulSoup(raw, "html.parser").get_text()
            onions = extract_onions(raw)
            for o in onions:
                save_onion(o, name, cur)
        conn.commit()
        print(f"    ↳  {len(onions)} onions harvested")
        total_new += len(onions)
    except Exception as e:
        print(f"    [!] Error: {e}")

cur.close()
conn.close()

print(f"\n[✓] Onion aggregation complete — {total_new} new URLs saved.")
