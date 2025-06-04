from whoosh.index import create_in, open_dir
from whoosh.fields import Schema, TEXT, ID, DATETIME
from whoosh.qparser import QueryParser
from pathlib import Path
from bs4 import BeautifulSoup
from datetime import datetime


from core.crawler import SNAPSHOT_DIR

# Import Paths
SNAPSHOT_DIR = Path("data/snapshots")
INDEX_DIR = Path("data/index")


schema = Schema(
    url=ID(stored=True, unique=True),
    content=TEXT(stored=True),
    timestamp=DATETIME(stored=True),
)


def build_index():
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    ix = create_in(INDEX_DIR, schema=schema)
    writer = ix.writer()

    for html_file in SNAPSHOT_DIR.glob("*.html"):
        with open(html_file, "r", encoding="utf-8") as f:
            soup = BeautifulSoup(f, "html.parser")
            text = soup.get_text()
            url = html_file.stem.replace("_", ".") # Example: onion_site.onion
            writer.add_document(url=url, content=text)
            timestamp = datetime.fromtimestamp(html_file.stat().st_mtime).isoformat()
            writer.commit()


def search(query_string):
    ix = open_dir(INDEX_DIR)
    qp = QueryParser("content", ix.schema)
    q = qp.parse(query_string)
    with ix.searcher() as s:
        results = s.search(q, limite=20)
        return [(r['url'], r['timestamp']) for r in results]
