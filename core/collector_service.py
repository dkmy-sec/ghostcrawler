from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from core.aggregate_feeds import sync_catalog
from core.analyst_workbench import refresh_analyst_signals
from core.crawler import crawl_seed_batch
from core.frontier_crawl import frontier_crawl
from core.intel_schema import DB_PATH, ensure_database
from core.search_engine import build_index


LOG_LEVEL = os.getenv("GHOSTCRAWLER_LOG_LEVEL", "INFO").upper()
COLLECTOR_INTERVAL = int(os.getenv("GHOSTCRAWLER_COLLECTOR_INTERVAL_SECONDS", "900"))
SEED_BATCH_LIMIT = int(os.getenv("GHOSTCRAWLER_SEED_BATCH_LIMIT", "12"))
SEED_BATCH_DEPTH = int(os.getenv("GHOSTCRAWLER_SEED_BATCH_DEPTH", "3"))
ENABLE_FRONTIER = os.getenv("GHOSTCRAWLER_ENABLE_FRONTIER", "true").strip().lower() in {"1", "true", "yes", "on"}


logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
)


def run_cycle() -> None:
    ensure_database(DB_PATH)
    added = sync_catalog()
    logging.info("Catalog sync complete. Added %s new seeds.", added)

    batch_results = crawl_seed_batch(limit=SEED_BATCH_LIMIT, max_depth=SEED_BATCH_DEPTH)
    successes = sum(1 for row in batch_results if not row.get("error"))
    logging.info("Seed batch finished. %s/%s successful crawls.", successes, len(batch_results))

    if ENABLE_FRONTIER:
        frontier_crawl()

    build_index()
    stats = refresh_analyst_signals()
    logging.info("Analyst refresh complete: %s", stats)


def main() -> None:
    logging.info("Collector service starting. Interval=%ss DB=%s", COLLECTOR_INTERVAL, DB_PATH)
    while True:
        try:
            run_cycle()
        except Exception as exc:
            logging.exception("Collector cycle failed: %s", exc)
        time.sleep(COLLECTOR_INTERVAL)


if __name__ == "__main__":
    main()
