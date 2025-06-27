import sqlite3
import csv
import json
from pathlib import Path
from datetime import datetime


DB_PATH = Path("../data/onion_sources.db")
CSV_PATH = Path("../data/quarantined_report.csv")
JSON_PATH = Path("../data/quarantined_report.json")


def export_quarantined():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT url, source, tag, last_seen, depth FROM onions
        WHERE quarantined = 1
    """)
    rows = cursor.fetchall()
    conn.close()

    headers = ["url", "source", "tag", "last_seen", "depth"]

    # Export to CSV
    with CSV_PATH.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    print(f"[✓] Exported CSV: {CSV_PATH}")

    # Export to JSON
    records = [dict(zip(headers, row)) for row in rows]
    for rec in records:
        rec["exported_at"] = datetime.utcnow().isoformat()

    with JSON_PATH.open("w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)
    print(f"[✓] Exported JSON: {JSON_PATH}")


if __name__ == "__main__":
    export_quarantined()
