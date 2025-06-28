from whoosh import index
from whoosh.fields import Schema, TEXT, ID
from bs4 import BeautifulSoup
from pathlib import Path

from whoosh.index import open_dir
from whoosh.qparser import QueryParser

INDEX_DIR = Path("data/index")
SNAPSHOT_DIR = Path("data/snapshots")

schema = Schema(
    url=ID(stored=True, unique=True),
    content=TEXT(stored=False)
)


def build_index():
    # Create or open index safely
    if not INDEX_DIR.exists():
        INDEX_DIR.mkdir(parents=True)
        ix = index.create_in(INDEX_DIR, schema)
    else:
        ix = index.open_dir(INDEX_DIR)

    # One writer context, one commit
    with ix.writer(limitmb=256, procs=1, multisegment=True) as writer:
        for html_file in SNAPSHOT_DIR.glob("*.html"):
            try:
                raw = html_file.read_text(encoding="utf-8", errors="ignore")
                text = BeautifulSoup(raw, "html.parser").get_text(" ", strip=True)

                # update_document overwrites if url already indexed
                writer.update_document(
                    url=html_file.name,
                    content=text
                )
                print(f"[+] Indexed {html_file.name}")
            except Exception as e:
                # Log but DO NOT close writer; continue loop
                print(f"[!] Skipped {html_file.name}: {e}")

    # After the with-block, writer is committed & closed automatically
    print("[✓] Rebuild complete.")


def search(query_string):
    ix = open_dir(INDEX_DIR)
    qp = QueryParser("content", ix.schema)
    q = qp.parse(query_string)
    with ix.searcher() as s:
        results = s.search(q, limit=20)
        return [(r['url'], r['timestamp']) for r in results]
