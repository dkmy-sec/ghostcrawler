
import json
import sqlite3
import subprocess
import threading
import time

import pandas as pd
import streamlit as st
from fpdf import FPDF
from requests_tor import RequestsTor

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))
from core.crawler import crawl_onion
from core.search_engine import build_index, search
from core.identity import rotate_identity
from core.utils import DATA_DIR


# Paths
PDF_REPORT = DATA_DIR / "data/reports/threat_report.pdf"
DB_PATH = DATA_DIR / "onion_sources.db"
SNAPSHOT_DIR = DATA_DIR / "snapshots"
ALERTS_PATH = DATA_DIR / "alerts.json"
WATCHLIST_PATH = DATA_DIR / "watchlist.json"


# Session state config
if "rotate_every" not in st.session_state:
    st.session_state.rotate_every = 5

st.set_page_config(layout="wide")
st.title("👻 Ghostcrawler Darknet Intel Toolkit")

# Sidebar Controls
st.sidebar.header("🛠️ Controls")
st.sidebar.slider("Rotate Identity Every N Requests", 1, 20, st.session_state.rotate_every, key="rotate_every")

# Refresh Aggregation Control
st.markdown("## 🧅 Seed Aggregation Control")

if st.button("⚡ Refresh Aggregated Seeds"):
    with st.spinner("Running aggregation module..."):
        subprocess.run(["python", "core/aggregate_feeds.py"])
    st.success("Seed list and source DB updated!")

# Onion source breakdown stats
try:
    conn = sqlite3.connect(str(DB_PATH))
    df = pd.read_sql_query("SELECT tag, COUNT(*) as count FROM onions GROUP BY tag", conn)
    conn.close()

    if not df.empty:
        st.markdown("### 🔍 Onion Source Breakdown")
        st.dataframe(df, use_container_width=True)
    else:
        st.warning("No entries found in onion_sources.db yet.")
except Exception as e:
    st.error(f"Failed to load onion source breakdown: {e}")

# Edit Watchlist Sidebar
WATCHLIST_PATH = DATA_DIR / "watchlist.json"
st.sidebar.markdown("## 🧠 Edit Watchlist")
if WATCHLIST_PATH.exists():
    with open(WATCHLIST_PATH) as f:
        watchlist = json.load(f)
else:
    watchlist = {"emails": [], "keywords": [], "domains": []}

for category in watchlist:
    current = watchlist[category]
    new_list = st.sidebar.text_area(
        f"{category.capitalize()} (comma-separated)",
        ", ".join(current),
        key=category
    )
    watchlist[category] = [x.strip() for x in new_list.split(",") if x.strip()]

if st.sidebar.button("💾 Save Watchlist"):
    with open(WATCHLIST_PATH, "w") as f:
        json.dump(watchlist, f, indent=2)
    st.sidebar.success("Watchlist updated.")

if st.sidebar.button("🕷️ Run Mass .onion Scan"):
    with st.spinner("Scanning onion homepages..."):
        subprocess.run(["python", "core/mass_onion_scanner.py"])
    st.success("Mass scan complete.")

st.sidebar.markdown("## 🎯 Deep Crawl Targets")
onion_urls = []
if DB_PATH.exists():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT url FROM onions")
    onion_urls = [row[0] for row in cursor.fetchall()]
    conn.close()

selected_urls = st.sidebar.multiselect(f"Select .onions to Deep Crawl ({len(onion_urls)} found)", onion_urls)

def run_crawlers(urls):
    progress = st.progress(0)
    session = RequestsTor(tor_ports=(9050,), autochange_id=False)

    def crawl_target(url):
        crawl_onion(url, session, rotate_every=st.session_state.rotate_every)

    threads = []
    for i, url in enumerate(urls):
        thread = threading.Thread(target=crawl_target, args=(url,))
        thread.start()
        threads.append(thread)
        time.sleep(0.5)

    for i, t in enumerate(threads):
        t.join()
        progress.progress((i + 1) / len(urls))

    st.success("Deep crawl complete.")
    generate_pdf_report()

if st.sidebar.button("🚀 Deep Crawl Selected"):
    if selected_urls:
        run_crawlers(selected_urls)
    else:
        st.warning("No .onion URLs selected.")

st.sidebar.subheader("📦 Index Builder")
if st.sidebar.button("Build Darknet Index"):
    with st.spinner("Parsing snapshots and building index..."):
        build_index()
        st.sidebar.success("Index built successfully.")

st.subheader("‍🧙 One-Button Mode: Darknet Exposure Scan‍️")
user_input = st.text_input("Enter your email, domain, or sensitive keyword:")

if st.button("🔍 Search the Darknet"):
    if not user_input:
        st.warning("Please enter something to search")
    else:
        st.info("💾 Stage 1: Running mass .onion scan...")
        subprocess.run(["python", "core/mass_onion_scanner.py"])
        time.sleep(1)
        st.info("🕷️ Stage 2: Running deep crawler on matched onions...")
        subprocess.run(["python", "core/crawler.py"])
        time.sleep(1)
        st.info("📦 Stage 3: Building index from crawled snapshots...")
        build_index()
        st.info("🔍 Stage 4: Searching for exposures...")
        results = search(user_input)
        if results:
            df = pd.DataFrame(results, columns=[".onion URL", "TimeStamp"])
            st.success(f"💀 {len(results)} potential exposures found.")
            st.dataframe(df)
            with st.expander(": Export"):
                st.download_button("Download as CSV", df.to_csv(index=False), "darknet_results.csv")
                st.download_button("Download as JSON", df.to_json(orient="records"), "darknet_results.json")
        else:
            st.warning("⚠️ No exposures found in the current scan.")

st.subheader("🔎 Darknet Search")
query = st.text_input("Enter a keyword, email or phrase to search snapshots: ")
if query:
    with st.spinner(f"Searching indexed content for: {query}..."):
        results = search(query)
        if results:
            df = pd.DataFrame(results, columns=[".onion URL", "TimeStamp"])
            st.success(f"Found {len(results)} results.")
            st.dataframe(df)
            with st.expander(': Export'):
                st.download_button("Download as CSV", df.to_csv(index=False), "darknet_results.csv")
                st.download_button("Download as JSON", df.to_json(orient="records"), "darknet_results.json")
        else:
            st.warning("No matches found.")

st.subheader("📄 HTML Snapshots")
SNAPSHOT_DIR = DATA_DIR / "snapshots"
snap_files = sorted(SNAPSHOT_DIR.glob("*.html"))

if snap_files:
    snap_names = [f.name for f in snap_files]
    snap_select = st.selectbox("Select snapshot to view", snap_names)
    if snap_select:
        content = (SNAPSHOT_DIR / snap_select).read_text(encoding="utf-8")
        st.components.v1.html(content, height=500, scrolling=True)
else:
    st.info("No snapshots found.")


st.subheader("📄 Latest Threat PDF Report")
if PDF_REPORT.exists():
    with open(PDF_REPORT, "rb") as f:
        st.download_button("Download Threat Report PDF", f, file_name="threat_report.pdf")
else:
    st.info("No threat report generated yet.")

def generate_pdf_report():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.set_text_color(255, 0, 255)
    pdf.set_fill_color(0, 0, 0)
    pdf.cell(200, 10, "Ghostcrawler Threat Report", ln=True, align="C")

    if ALERTS_PATH.exists():
        with open(ALERTS_PATH) as f:
            data = json.load(f)
        grouped = {}
        for entry in data:
            grouped.setdefault(entry['base'], []).extend(entry['matched'])
        for site, terms in grouped.items():
            pdf.set_text_color(0, 255, 255)
            pdf.cell(200, 10, f"Site: {site}", ln=True)
            pdf.set_text_color(255, 255, 255)
            pdf.multi_cell(0, 10, f"Matched Terms: {', '.join(set(terms))}")
    else:
        pdf.cell(200, 10, "No alerts found.", ln=True)

    PDF_REPORT.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(PDF_REPORT))

st.subheader("🚨 Threat Alerts")
if ALERTS_PATH.exists():
    with open(ALERTS_PATH) as f:
        alert_data = json.load(f)
    df = pd.DataFrame(alert_data)
    if not df.empty:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        st.dataframe(df[['url', 'matched', 'timestamp']].sort_values(by="timestamp", ascending=False))
        st.download_button("Download as CSV", df.to_csv(index=False), file_name="threat_alerts.csv")
    else:
        st.info("No alerts yet. Run a scan.")
else:
    st.info("No alerts file found.")

st.markdown("<div class=footer>Made with 💌 and paranoia by Kei Nova ©️ 2025 </div>", unsafe_allow_html=True)
