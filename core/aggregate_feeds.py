import sqlite3
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

try:
    from core.crawler import classify_onion
    from core.intel_schema import DB_PATH, MULTI_NETWORK_SEEDS, ensure_database
    from core.network_catalog import classify_network, network_label
    from core.url_intake import UrlIntakeSummary, format_skip_summary, normalize_fetchable_url
    from core.utils import DATA_DIR
except ImportError:
    from crawler import classify_onion
    from intel_schema import DB_PATH, MULTI_NETWORK_SEEDS, ensure_database
    from network_catalog import classify_network, network_label
    from url_intake import UrlIntakeSummary, format_skip_summary, normalize_fetchable_url
    from utils import DATA_DIR


SEED_TXT = DATA_DIR / "seed_onions.txt"


def sync_catalog() -> int:
    ensure_database(DB_PATH)
    SEED_TXT.parent.mkdir(exist_ok=True)
    SEED_TXT.touch(exist_ok=True)
    existing = set(SEED_TXT.read_text(encoding="utf-8").splitlines())
    inserted = 0
    skipped = UrlIntakeSummary()

    with sqlite3.connect(DB_PATH) as conn:
        for seed in MULTI_NETWORK_SEEDS:
            intake = normalize_fetchable_url(seed["url"])
            if intake.accepted:
                url = intake.normalized_url or seed["url"].strip()
            else:
                skipped.record(intake)
                url = seed["url"].strip()
            conn.execute(
                """
                INSERT OR IGNORE INTO onions (url, source, tag, network, collector, priority)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    url,
                    seed.get("source", "seed_catalog"),
                    seed.get("tag") or classify_onion(url),
                    seed.get("network") or classify_network(url),
                    "catalog_sync",
                    "priority",
                ),
            )
            if intake.accepted and url not in existing:
                with SEED_TXT.open("a", encoding="utf-8") as handle:
                    handle.write(url + "\n")
                existing.add(url)
                inserted += 1
                print(f"[+] Added {network_label(classify_network(url))} seed: {url}")

        conn.commit()
    if skipped.skipped:
        print(f"[i] Catalog seed URL intake skipped for crawl file: {format_skip_summary(skipped)}")
    return inserted


if __name__ == "__main__":
    count = sync_catalog()
    print(f"[✓] Multi-network catalog sync complete. Added {count} new seed(s).")
