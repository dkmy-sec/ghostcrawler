from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from whoosh import index
from whoosh.fields import DATETIME, ID, TEXT, Schema
from whoosh.index import exists_in, open_dir
from whoosh.qparser import MultifieldParser

from core.utils import DATA_DIR

INDEX_DIR = DATA_DIR / "index"
SNAPSHOT_DIR = DATA_DIR / "snapshots"

schema = Schema(
    url=ID(stored=True, unique=True),
    title=TEXT(stored=True),
    snapshot_file=ID(stored=True),
    content=TEXT(stored=False),
    indexed_at=DATETIME(stored=True),
)


def _open_or_create_index():
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    if not exists_in(INDEX_DIR):
        return index.create_in(INDEX_DIR, schema)
    try:
        return open_dir(INDEX_DIR)
    except Exception:
        # Recreate the index if an older schema is incompatible.
        return index.create_in(INDEX_DIR, schema)


def _snapshot_url(html_file: Path) -> str:
    name = html_file.name
    if name.endswith(".html"):
        name = name[:-5]
    return name.replace("_", "/")


def build_index():
    ix = _open_or_create_index()
    indexed = 0

    with ix.writer(limitmb=256, procs=1, multisegment=True) as writer:
        for html_file in SNAPSHOT_DIR.glob("*.html"):
            try:
                raw = html_file.read_text(encoding="utf-8", errors="ignore")
                soup = BeautifulSoup(raw, "html.parser")
                text = soup.get_text(" ", strip=True)
                title = (soup.title.string or "").strip() if soup.title and soup.title.string else html_file.stem
                indexed_at = datetime.fromtimestamp(html_file.stat().st_mtime, tz=timezone.utc)

                writer.update_document(
                    url=_snapshot_url(html_file),
                    title=title,
                    snapshot_file=html_file.name,
                    content=text,
                    indexed_at=indexed_at,
                )
                indexed += 1
            except Exception as exc:
                print(f"[!] Skipped {html_file.name}: {exc}")

    print(f"[✓] Rebuild complete. Indexed {indexed} snapshots.")


def search(query_string: str, limit: int = 20):
    if not INDEX_DIR.exists():
        return []

    ix = _open_or_create_index()
    parser = MultifieldParser(["title", "content", "url"], schema=ix.schema)
    query = parser.parse(query_string)

    with ix.searcher() as searcher:
        results = searcher.search(query, limit=limit)
        return [
            {
                "url": hit["url"],
                "title": hit.get("title") or hit["url"],
                "snapshot_file": hit.get("snapshot_file", ""),
                "indexed_at": hit.get("indexed_at"),
            }
            for hit in results
        ]
