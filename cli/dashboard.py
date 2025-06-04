import streamlit as st
from pathlib import Path
import sqlite3
import subprocess
import threading
import json
import time
from core.crawler import crawl_onion
from requests_tor import RequestsTor
from core.identity import rotate_identity
from datetime import datetime
from fpdf import FPDF
import pandas as pd


# Paths
DB_PATH = Path("data/onion_links.db")
SNAPSHOT_DIR = Path("data/snapshots")
PDF_REPORT = Path("data/reports/threat_report.pdf")
ALERTS_PATH = Path("data/alerts.json")

# Session state config
if "rotate_every" not in st.session_state:
    st.session_state.rotate_every = 5

st.set_page_config(layout="wide")
st.title("🧠 Ghostcrawler Darknet Intel Toolkit")

# Sidebar Controls
st.sidebar.header("🛠️ Controls")
st.sidebar.slider("Rotate Identity Every N Requests", 1, 20, st.session_state.rotate_every, key="rotate_every")

WATCHLIST_PATH = Path("data/watchlist.json")

st.sidebar.markdown("## 🧠 Edit Watchlist")

# Load watchlist
if WATCHLIST_PATH.exists():
    with open(WATCHLIST_PATH) as f:
        watchlist = json.load(f)
else:
    watchlist = {"emails": [], "keywords": [], "domains": []}

# Editable fields
for category in watchlist:
    current = watchlist[category]
    new_list = st.sidebar.text_area(
        f"{category.capitalize()} (comma-separated)",
        ", ".join(current),
        key=category
    )
    watchlist[category] = [x.strip() for x in new_list.split(",") if x.strip()]

# Save button
if st.sidebar.button("💾 Save Watchlist"):
    with open(WATCHLIST_PATH, "w") as f:
        json.dump(watchlist, f, indent=2)
    st.sidebar.success("Watchlist updated.")


# --- Mass Scan Trigger ---
if st.sidebar.button("🕷️ Run Mass .onion Scan"):
    with st.spinner("Scanning onion homepages..."):
        subprocess.run(["python", "core/mass_onion_scanner.py"])
    st.success("Mass scan complete.")

# --- Checklist for Deep Crawl ---
st.sidebar.markdown("## 🎯 Deep Crawl Targets")
onion_urls = []

if DB_PATH.exists():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT url FROM onion_links")
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

# --- Launch Crawl ---
if st.sidebar.button("🚀 Deep Crawl Selected"):
    if selected_urls:
        run_crawlers(selected_urls)
    else:
        st.warning("No .onion URLs selected.")

# --- Snapshot Viewer ---
st.subheader("📄 HTML Snapshots")
snap_files = sorted(SNAPSHOT_DIR.glob("*.html"))
snap_names = [f.name for f in snap_files]
if snap_names:
    snap_select = st.selectbox("Select snapshot to view", snap_names)
    if snap_select:
        content = (SNAPSHOT_DIR / snap_select).read_text(encoding="utf-8")
        st.components.v1.html(content, height=500, scrolling=True)

# --- PDF Viewer ---
st.subheader("📄 Latest Threat PDF Report")
if PDF_REPORT.exists():
    with open(PDF_REPORT, "rb") as f:
        st.download_button("Download Threat Report PDF", f, file_name="threat_report.pdf")
else:
    st.info("No threat report generated yet.")

# --- Generate PDF Function ---
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
ALERTS_PATH = Path("data/alerts.json")

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