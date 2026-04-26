# core/load_seeds_to_frontier.py
import sqlite3

from pathlib import Path

from core.url_intake import UrlIntakeSummary, format_skip_summary, normalize_fetchable_url
from core.utils import DATA_DIR

DB = DATA_DIR / "onion_sources.db"
SEED = DATA_DIR / "seed_onions.txt"


def load_seeds_to_frontier(seed_path: Path = SEED, db_path: Path = DB) -> dict:
    seeds = [line.strip() for line in seed_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    with sqlite3.connect(db_path) as conn:
        return load_seed_urls_to_frontier(seeds, conn)


def load_seed_urls_to_frontier(seeds: list[str], conn: sqlite3.Connection) -> dict:
    skipped = UrlIntakeSummary()
    accepted = 0
    inserted = 0

    cur = conn.cursor()
    for seed in seeds:
        intake = normalize_fetchable_url(seed)
        if not intake.accepted:
            skipped.record(intake)
            continue
        accepted += 1
        cur.execute(
            """
            INSERT OR IGNORE INTO frontier(url, source, depth, status, network)
            VALUES (?, 'seedfile', 0, 'pending', ?)
            """,
            (intake.normalized_url, intake.network),
        )
        inserted += cur.rowcount
    conn.commit()

    return {
        "read": len(seeds),
        "accepted": accepted,
        "inserted": inserted,
        "skipped": skipped.as_dict(),
    }


if __name__ == "__main__":
    stats = load_seeds_to_frontier()
    print(
        f"[✓] Loaded {stats['inserted']} new seed URL(s) into frontier "
        f"({stats['accepted']} accepted from {stats['read']} line(s))."
    )
    if stats["skipped"]:
        print(f"[i] Seed URL intake skipped: {format_skip_summary(stats['skipped'])}")
