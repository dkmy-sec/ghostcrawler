import streamlit as st
import json
import os
import subprocess
from pathlib import Path
from whoosh.index import open_dir
from whoosh.qparser import QueryParser
import matplotlib.pyplot as plt

# --- CONFIG ---
DATA_DIR = Path("data")
ALERTS_FILE = DATA_DIR / "logs" / "alerts.json"
INDEX_DIR = DATA_DIR / "index"
LOG_DIR = DATA_DIR / "logs"
SNAPSHOT_DIR = DATA_DIR / "snapshots"

# --- TITLE ---
st.set_page_config(page_title="DarkWeb Intel Dashboard", layout="wide")
st.title("DarkWeb Threat Intel Dashboard")
st.markdown("Stay vigilant in the neon abyss. Track your exposure on the dark web.")

# --- SCAN LAUNCHER ---
st.subheader("Launch a Dark Web Scan")
if st.button("🚀 Run Scan Now"):
    with st.spinner("Scanning the deep grid..."):
        result = subprocess.run(["python", "cli/run_scan.py"], capture_output=True, text=True)
        st.code(result.stdout)
        st.success("Scan completed!")

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
    if INDEX_DIR.exists():
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
        st.error("Search index not found. Run a scan to create it.")


# --- WATCHLIST EDITOR ---
st.subheader("🛡️ Watchlist Manager")
watchlist_path = Path("data/watchlist.json")

# Load current watchlist
if watchlist_path.exists():
    with open(watchlist_path, "r") as f:
        watchlist = json.load(f)
else:
    watchlist = {"emails": [], "ssns": [], "credit_cards": [], "company": []}

category = st.selectbox("Select category", ["emails", "ssns", "credit_cards", "company"])
new_item = st.text_input("Add item to watchlist")

if st.button("➕ Add to Watchlist") and new_item:
    if new_item not in watchlist[category]:
        watchlist[category].append(new_item)
        with open(watchlist_path, "w") as f:
            json.dump(watchlist, f, indent=2)
        st.success(f"Added to {category}: {new_item}")
    else:
        st.warning("Item already in watchlist.")

# Display and delete entries
st.markdown("### Current Watchlist")
for cat, items in watchlist.items():
    st.markdown(f"**{cat.capitalize()}**")
    for item in items:
        col1, col2 = st.columns([6, 1])
        col1.write(item)
        if col2.button("🗑️", key=f"delete_{cat}_{item}"):
            watchlist[cat].remove(item)
            with open(watchlist_path, "w") as f:
                json.dump(watchlist, f, indent=2)
            st.success(f"Removed {item} from {cat}")
            st.experimental_rerun()


# --- FOOTER ---
st.markdown("---")
st.caption("Cyberpunk-style dark web awareness dashboard. Built with love & paranoia.")
