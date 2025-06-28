# core/clean_data.py
import sqlite3, requests, time, os
from pathlib import Path
from requests_tor import RequestsTor
from whoosh import index
from whoosh.qparser import QueryParser
from core.utils import DATA_DIR
from core.safeguard import is_high_risk


DB_PATH      = DATA_DIR / "onion_sources.db"
SEED_TXT     = DATA_DIR / "seed_onions.txt"
SNAP_DIR     = DATA_DIR / "snapshots"
INDEX_DIR    = DATA_DIR / "index"


session = RequestsTor(tor_ports=(9050,), autochange_id=False)
HEADERS = {"User-Agent": "GhostcrawlerClean/1.0"}


def live_check(url, attempts=2):
    try:
        resp = session.get(url, headers=HEADERS, timeout=15)
        return resp.status_code in (200, 301, 302)
    except Exception:
        return False


def clean_db():
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        # Deduplicate by lowest id per url
        cur.execute("DELETE FROM onions WHERE id NOT IN (SELECT MIN(id) FROM onions GROUP BY url)")
        conn.commit()

        # Health-check
        cur.execute("SELECT url FROM onions WHERE live=1 AND quarantined=0")
        urls = [r[0] for r in cur.fetchall()]
        for u in urls:
            ok = live_check(u)
            cur.execute("UPDATE onions SET live=? WHERE url=?", (1 if ok else 0, u))
            time.sleep(0.3)   # be polite
        conn.commit()

        # Build fresh seed list
        cur.execute("SELECT url FROM onions WHERE live=1 AND quarantined=0")
        fresh = [r[0] for r in cur.fetchall()]

    SEED_TXT.write_text("\n".join(fresh) + "\n")
    print(f"[✓] seed_onions.txt rebuilt with {len(fresh)} live links")


def purge_snapshots():
    valid_names = set()
    for url in SEED_TXT.read_text().splitlines():
        fname = url.replace("http://","").replace("https://","").replace("/","_") + ".html"
        valid_names.add(fname)

    removed = 0
    for f in SNAP_DIR.glob("*.html"):
        if f.name not in valid_names or is_high_risk(f.name, f.read_text(errors='ignore')):
            f.unlink(); removed += 1
    print(f"[✓] Purged {removed} orphan / risky snapshots")


def reindex_whoosh():
    if not INDEX_DIR.exists():
        print("[i] No index folder yet; skipping reindex")
        return
    ix = index.open_dir(INDEX_DIR)
    qp = QueryParser("url", ix.schema)
    with ix.writer() as writer:
        for doc in list(ix.all_documents()):
            snap = SNAP_DIR / doc['url']
            if not snap.exists():
                writer.delete_document(docnum=doc.docnum)
        # writer.commit() handled by context
    print("[✓] Whoosh index synced with snapshots")


if __name__ == "__main__":
    clean_db()
    purge_snapshots()
    reindex_whoosh()
    print("[✓] All clean!")
