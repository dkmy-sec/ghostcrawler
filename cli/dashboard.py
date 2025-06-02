import streamlit as st
import json
import os
import subprocess
from pathlib import Path
from whoosh.index import open_dir, exists_in
from whoosh.qparser import QueryParser
import matplotlib.pyplot as plt
import pandas as pd

# --- CONFIG ---
DATA_DIR = Path("data")
ALERTS_FILE = DATA_DIR / "logs" / "alerts.json"
INDEX_DIR = DATA_DIR / "index"
LOG_DIR = DATA_DIR / "logs"
SNAPSHOT_DIR = DATA_DIR / "snapshots"
REPORT_PATH = LOG_DIR / "threat_report.md"

# --- PAGE SETTINGS ---
st.set_page_config(page_title="DarkWeb Intel Dashboard", layout="wide")
st.title("DarkWeb Threat Intel Dashboard")
st.markdown("Stay vigilant in the neon abyss. Track your exposure on the dark web.")

# --- FULL CONTROL PANEL ---
st.sidebar.title("🕹 Control Panel")
if st.sidebar.button("🚀 Run Full Scan"):
    with st.spinner("Scanning the deep grid..."):
        result = subprocess.run(["python", "cli/run_scan.py"], capture_output=True, text=True)
        st.sidebar.success("Scan completed!")
        st.code(result.stdout)

if st.sidebar.button("🧼 Reset Alerts and Snapshots"):
    for folder in [LOG_DIR, SNAPSHOT_DIR, INDEX_DIR]:
        for file in folder.glob("*"):
            file.unlink()
    st.sidebar.warning("All alert logs and snapshots cleared.")

# --- STATS ---
st.subheader("Scan Stats")
num_alerts = 0
num_snapshots = len(list(SNAPSHOT_DIR.glob("*.html"))) if SNAPSHOT_DIR.exists() else 0
if ALERTS_FILE.exists():
    with open(ALERTS_FILE) as f:
        alerts = json.load(f)
        num_alerts = len(alerts)

st.metric("Snapshots Collected", num_snapshots)
st.metric("Alerts Detected", num_alerts)

# --- THREAT REPORT GENERATION ---
st.subheader("📄 Threat Report")
if ALERTS_FILE.exists():
    with open(ALERTS_FILE) as f:
        alerts = json.load(f)
    report_lines = ["# Threat Report\n"]
    for a in alerts:
        report_lines.append(f"## {a['url']}")
        for match in a["matches"]:
            report_lines.append(f"- {match}")
    REPORT_PATH.write_text("\n".join(report_lines))
    with open(REPORT_PATH, "r") as f:
        st.download_button("⬇️ Download Threat Report (Markdown)", f, file_name="threat_report.md")
else:
    st.info("No alert data to generate report.")

# --- ALERT VIEWER ---
st.subheader("Detected Threats")
if ALERTS_FILE.exists():
    with open(ALERTS_FILE) as f:
        alerts = json.load(f)
        if alerts:
            for a in alerts:
                with st.expander(f"[!] Leak on {a['url']}"):
                    for match in a["matches"]:
                        st.error(match)
        else:
            st.success("No dark web leaks detected in this scan.")
else:
    st.warning("No alerts file found. Run a scan first.")

# --- SEARCH INTERFACE ---
st.subheader("Search Dark Web Index")
query = st.text_input("Enter keyword (e.g. email, domain, term)")

if query:
    if INDEX_DIR.exists() and exists_in(INDEX_DIR):
        ix = open_dir(INDEX_DIR)
        with ix.searcher() as searcher:
            parser = QueryParser("body", ix.schema)
            parsed_query = parser.parse(query)
            results = searcher.search(parsed_query, limit=10)
            if not results:
                st.info("No results found.")
            else:
                for r in results:
                    st.write(f"**{r['title']}**")
                    st.caption(r["url"])
    else:
        st.warning("Search index not found. Run a scan first.")

# --- FOOTER ---
st.markdown("---")
st.caption("Cyberpunk-style dark web awareness dashboard. Built with love & paranoia.")
