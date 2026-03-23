import json
import sqlite3
import subprocess
import threading
from datetime import datetime
from pathlib import Path
import scrapy
import requests
from requests_tor import RequestsTor
import pandas as pd
import streamlit as st
from fpdf import FPDF

import sys

sys.path.append(str(Path(__file__).resolve().parent.parent))

from core.crawler import crawl_onion
from core.search_engine import build_index, search
from core.utils import DATA_DIR

DB_PATH = DATA_DIR / "onion_sources.db"
SNAPSHOT_DIR = DATA_DIR / "snapshots"
ALERTS_PATH = DATA_DIR / "alerts.json"
PDF_REPORT = DATA_DIR / "reports" / "threat_report.pdf"
APP_ROOT = Path(__file__).resolve().parent.parent

# --- TOR SESSION SETUP ---
# Initialize Tor once at the start

def get_tor_session():
    return RequestsTor(tor_ports=(9050,), autochange_id=False)

session_tor = get_tor_session()


def get_clear_session():
    return requests.Session()

session_web = get_clear_session()

def run_python(script_path: Path):
    return subprocess.run([sys.executable, str(script_path)], cwd=APP_ROOT, check=False)


def process_url(url, session):
    """Processes a single URL and saves harvested data to the DB."""
    try:
        print(f"Processing: {url}")
        response = session.get(url, timeout=15)
        html = response.text
        soup = BeautifulSoup(html, "html.parser")
        text = soup.get_text(" ", strip=True)

        # --- HARVESTING LOGIC ---
        conn = sqlite3.connect(DB_PATH)

        # Regex Patterns
        EMAIL_REGEX = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        API_KEY_REGEX = r'(?i)(api[_-]?key|apikey|secret|token)[\s:]*["\']?([A-Za-z0-9\-._~+/]+=*)["\']?'
        HASH_REGEX = r'(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})'

        results = []

        # Extract Emails
        for email in re.findall(EMAIL_REGEX, text):
            results.append(('email', email, text[text.find(email):text.find(email) + 50]))

        # Extract API Keys
        for match in re.finditer(API_KEY_REGEX, text):
            key = match.group(2)
            results.append(('api_key', key, match.group(0)))

        # Extract Hashes
        for hash_val in re.findall(HASH_REGEX, text):
            results.append(('hash', hash_val, text[text.find(hash_val):text.find(hash_val) + 20]))

        # Save to DB
        for leak_type, value, snippet in results:
            conn.execute("""
                         INSERT INTO data_leaks (url, leak_type, value, snippet)
                         VALUES (?, ?, ?, ?)
                         """, (url, leak_type, value, snippet))

        conn.commit()
        conn.close()
        # --- END HARVESTING ---

        return {"status": "success", "url": url}

    except Exception as e:
        print(f"Error processing {url}: {e}")
        return {"status": "error", "url": url, "error": str(e)}


def get_connection():
    return sqlite3.connect(DB_PATH)


def table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    if not table_exists(conn, table_name):
        return set()
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row[1] for row in rows}


def classify_scope(url: str) -> str:
    return "Dark Web" if ".onion" in (url or "").lower() else "Clear Net"


def apply_scope_filter(frame: pd.DataFrame, scope: str, url_column: str = "url") -> pd.DataFrame:
    if frame.empty or scope == "All Sources" or url_column not in frame.columns:
        return frame
    scope_value = "Dark Web" if scope == "Dark Web" else "Clear Net"
    return frame[frame[url_column].fillna("").map(classify_scope) == scope_value].copy()


def generate_pdf_report():
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_title("Ghostcrawler Exposure Report")
    pdf.set_font("Arial", "B", 18)
    pdf.cell(0, 10, "Ghostcrawler Exposure Report", ln=True)
    pdf.set_font("Arial", "", 11)
    pdf.multi_cell(
        0,
        6,
        "Threat-hunter dashboard export. Review and retain only data you are authorized to monitor, store, or investigate.",
    )
    pdf.cell(0, 8, f"Generated: {datetime.utcnow().isoformat()} UTC", ln=True)
    pdf.ln(4)

    if not DB_PATH.exists():
        pdf.cell(0, 8, "No telemetry database found.", ln=True)
    else:
        try:
            with get_connection() as conn:
                if table_exists(conn, "data_leaks"):
                    findings = pd.read_sql_query(
                        "SELECT url, leak_type, value FROM data_leaks ORDER BY timestamp DESC LIMIT 50",
                        conn,
                    )
                else:
                    findings = pd.DataFrame()

            if findings.empty:
                pdf.cell(0, 8, "No evidence records were available for export.", ln=True)
            else:
                for _, row in findings.iterrows():
                    pdf.set_font("Arial", "B", 11)
                    pdf.cell(0, 7, f"{row['leak_type']}: {row['value']}", ln=True)
                    pdf.set_font("Arial", "", 10)
                    pdf.multi_cell(0, 6, f"Source: {row['url']}")
                    pdf.ln(1)
        except Exception as exc:
            pdf.cell(0, 8, f"Report generation error: {exc}", ln=True)

    PDF_REPORT.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(PDF_REPORT))


def load_overview_data():
    sources = pd.DataFrame(columns=["url", "source", "tag", "last_seen"])
    findings = pd.DataFrame(columns=["url", "leak_type", "value", "snippet", "timestamp"])
    frontier = pd.DataFrame(columns=["status", "count"])

    if not DB_PATH.exists():
        return sources, findings, frontier

    with get_connection() as conn:
        if table_exists(conn, "onions"):
            source_columns = table_columns(conn, "onions")
            select_parts = []
            for column in ["url", "source", "tag", "last_seen"]:
                select_parts.append(column if column in source_columns else f"NULL AS {column}")
            sources = pd.read_sql_query(f"SELECT {', '.join(select_parts)} FROM onions", conn)

        if table_exists(conn, "data_leaks"):
            leak_columns = table_columns(conn, "data_leaks")
            select_parts = []
            for column in ["url", "leak_type", "value", "snippet", "timestamp"]:
                select_parts.append(column if column in leak_columns else f"NULL AS {column}")
            findings = pd.read_sql_query(
                f"SELECT {', '.join(select_parts)} FROM data_leaks ORDER BY timestamp DESC",
                conn,
            )

        if table_exists(conn, "frontier"):
            frontier = pd.read_sql_query(
                "SELECT status, COUNT(*) AS count FROM frontier GROUP BY status ORDER BY status",
                conn,
            )

    return sources, findings, frontier


def search_evidence(term: str):
    records = []
    if not term or not DB_PATH.exists():
        return pd.DataFrame(columns=["type", "url", "summary", "timestamp"])

    with get_connection() as conn:
        if table_exists(conn, "data_leaks"):
            frame = pd.read_sql_query(
                """
                SELECT
                    leak_type,
                    url,
                    value,
                    snippet,
                    timestamp
                FROM data_leaks
                WHERE value LIKE ? OR snippet LIKE ? OR url LIKE ?
                ORDER BY timestamp DESC
                LIMIT 100
                """,
                conn,
                params=(f"%{term}%", f"%{term}%", f"%{term}%"),
            )
            if not frame.empty:
                frame["type"] = frame["leak_type"].fillna("finding")
                frame["summary"] = frame["value"].fillna("") + " " + frame["snippet"].fillna("")
                records.append(frame[["type", "url", "summary", "timestamp"]])

    return pd.concat(records, ignore_index=True) if records else pd.DataFrame(columns=["type", "url", "summary", "timestamp"])


def run_selected_crawls(urls: list[str], max_depth: int):
    progress = st.progress(0.0)
    results = []

    def worker(target_url: str):
        results.append(crawl_onion(target_url, depth=0, max_depth=max_depth))

    threads = []
    for index, url in enumerate(urls, start=1):
        thread = threading.Thread(target=worker, args=(url,))
        thread.start()
        threads.append(thread)
        progress.progress(index / len(urls))

    for thread in threads:
        thread.join()

    generate_pdf_report()
    return results


st.set_page_config(
    page_title="Ghostcrawler Threat Intel Console",
    page_icon="GC",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    :root {
        --bg: #08111c;
        --panel: #0f1b2b;
        --panel-alt: #132338;
        --ink: #e6edf6;
        --muted: #8fa6bf;
        --accent: #54d2a0;
        --accent-2: #7ec8ff;
        --danger: #ff7b72;
        --border: rgba(126, 200, 255, 0.18);
    }
    .stApp {
        background:
            radial-gradient(circle at top right, rgba(84, 210, 160, 0.12), transparent 28%),
            radial-gradient(circle at top left, rgba(126, 200, 255, 0.10), transparent 30%),
            linear-gradient(180deg, #07101a 0%, #0a1521 100%);
        color: var(--ink);
    }
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #09111b 0%, #0d1622 100%);
        border-right: 1px solid var(--border);
    }
    .hero {
        border: 1px solid var(--border);
        background: linear-gradient(135deg, rgba(15, 27, 43, 0.95), rgba(8, 17, 28, 0.92));
        padding: 1.4rem 1.6rem;
        border-radius: 18px;
        margin-bottom: 1.1rem;
        box-shadow: 0 18px 50px rgba(0, 0, 0, 0.24);
    }
    .hero h1 {
        margin: 0;
        font-size: 2.1rem;
        letter-spacing: 0.02em;
    }
    .hero p {
        color: var(--muted);
        margin: 0.5rem 0 0 0;
    }
    .metric-card {
        background: linear-gradient(180deg, rgba(15, 27, 43, 0.95), rgba(19, 35, 56, 0.92));
        border: 1px solid var(--border);
        border-radius: 16px;
        padding: 1rem 1.1rem;
        min-height: 118px;
    }
    .metric-label {
        color: var(--muted);
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
    }
    .metric-value {
        font-size: 2rem;
        margin-top: 0.35rem;
        color: var(--ink);
        font-weight: 700;
    }
    .metric-foot {
        color: var(--accent-2);
        margin-top: 0.4rem;
        font-size: 0.9rem;
    }
    .panel-note {
        border-left: 4px solid var(--accent);
        background: rgba(84, 210, 160, 0.08);
        padding: 0.8rem 1rem;
        border-radius: 10px;
        color: var(--ink);
        margin-bottom: 1rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

if "crawl_depth" not in st.session_state:
    st.session_state.crawl_depth = 2

sources_df, findings_df, frontier_df = load_overview_data()

st.sidebar.markdown("## Collection Scope")
scope = st.sidebar.radio("View", ["Dark Web", "Clear Net", "All Sources"], index=0)
st.sidebar.caption("The scope toggle changes views and search slices. Only monitor sources you are authorized to collect and retain.")


st.sidebar.markdown("## Operations")
if st.sidebar.button("Refresh Known Sources", width='stretch'):
    with st.spinner("Refreshing aggregated source list..."):
        run_python(APP_ROOT / "core" / "aggregate_feeds.py")
    st.sidebar.success("Source refresh finished.")
if st.sidebar.button("Run Targeted Crawl", width='stretch'):
    with st.spinner("Processing queued targets..."):
        run_python(APP_ROOT / "core" / "crawler.py")
    st.sidebar.success("Target crawl finished.")
if st.sidebar.button("Run Frontier Crawl", width='stretch'):
    with st.spinner("Processing queued targets..."):
        run_python(APP_ROOT / "core" / "frontier_crawl.py")
    st.sidebar.success("Frontier crawl finished.")

if st.sidebar.button("Run Homepage Scan", width='stretch'):
    with st.spinner("Scanning known homepages..."):
        run_python(APP_ROOT / "mass_onion_scanner.py")
    st.sidebar.success("Homepage scan finished.")

if st.sidebar.button("Build Search Index", width='stretch'):
    with st.spinner("Indexing snapshots for analyst search..."):
        build_index()
    st.sidebar.success("Search index rebuilt.")

if st.sidebar.button("Generate PDF Report", width='stretch'):
    generate_pdf_report()
    st.sidebar.success("Report generated.")
st.sidebar.markdown("## Manual Harvest")
SEED_URL = st.sidebar.text_input("Enter Seed URL", value="http://vfnmxpa6fo4jdpyq3yneqhglluweax2uclvxkytfpmpkp5rsl75ir5qd.onion")

if st.sidebar.button("Start Harvesting"):
    if ".onion" in SEED_URL:
        # Use Tor Session
        with st.spinner(f"Crawling Darkweb site {SEED_URL} with Tor..."):
            process_url(SEED_URL, session_tor)
        st.sidebar.success("Darkweb Harvesting Complete!")
    else:
        # Use Standard Session
        with st.spinner(f"Crawling Clearweb site {SEED_URL}..."):
            process_url(SEED_URL, session_web)
        st.success("Clearweb Harvesting Complete!")


scoped_sources = apply_scope_filter(sources_df, scope)
scoped_findings = apply_scope_filter(findings_df, scope)

latest_seen = "No data"
if not scoped_sources.empty and "last_seen" in scoped_sources.columns:
    valid_seen = pd.to_datetime(scoped_sources["last_seen"], errors="coerce").dropna()
    if not valid_seen.empty:
        latest_seen = valid_seen.max().strftime("%Y-%m-%d %H:%M UTC")

snapshot_count = len(list(SNAPSHOT_DIR.glob("*.html")))
source_count = len(scoped_sources.index)
finding_count = len(scoped_findings.index)
high_signal_types = scoped_findings["leak_type"].nunique() if "leak_type" in scoped_findings.columns and not scoped_findings.empty else 0

st.markdown(
    f"""
    <div class="hero">
        <h1>Ghostcrawler Threat Intel Console</h1>
        <p>Threat-hunter and OSINT-inspired workspace for triaging indexed evidence, reviewing crawl coverage, and pivoting between dark-web and clear-net monitoring views.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

metric_cols = st.columns(4)
metrics = [
    ("Sources in Scope", source_count, scope),
    ("Snapshots Indexed", snapshot_count, "Local evidence cache"),
    ("Evidence Records", finding_count, "Exposure artifacts"),
    ("Signal Categories", high_signal_types, latest_seen),
]
for column, (label, value, foot) in zip(metric_cols, metrics):
    column.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
            <div class="metric-foot">{foot}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

overview_tab, search_tab, evidence_tab, ops_tab = st.tabs(
    ["Overview", "Search", "Evidence", "Collection Ops"]
)

with overview_tab:
    st.markdown(
        """
        <div class="panel-note">
            Keep this workspace focused on authorized intelligence collection, breach-notification support, and defensive analysis. The dashboard surfaces what is already present in your local dataset rather than encouraging indiscriminate dump harvesting.
        </div>
        """,
        unsafe_allow_html=True,
    )

    left, right = st.columns((1.15, 0.85))

    with left:
        st.subheader("Source Coverage")
        if scoped_sources.empty:
            st.info("No sources are available in the current scope yet.")
        else:
            scoped_sources = scoped_sources.copy()
            scoped_sources["scope"] = scoped_sources["url"].fillna("").map(classify_scope)

            tag_counts = (
                scoped_sources["tag"].fillna("unknown").value_counts().rename_axis("tag").reset_index(name="count")
            )
            st.dataframe(tag_counts, use_container_width=True, hide_index=True)

            source_preview = scoped_sources[["url", "source", "tag", "last_seen"]].copy()
            st.dataframe(source_preview.sort_values(by="last_seen", ascending=False), use_container_width=True, hide_index=True)

    with right:
        st.subheader("Frontier Queue")
        if frontier_df.empty:
            st.info("Frontier queue table is not available yet.")
        else:
            st.dataframe(frontier_df, use_container_width=True, hide_index=True)

        st.subheader("Recent Snapshots")
        snapshot_files = sorted(SNAPSHOT_DIR.glob("*.html"), key=lambda path: path.stat().st_mtime, reverse=True)[:12]
        if not snapshot_files:
            st.info("No snapshots found yet.")
        else:
            snapshot_table = pd.DataFrame(
                [
                    {
                        "snapshot": item.name,
                        "scope": classify_scope(item.name),
                        "updated": datetime.utcfromtimestamp(item.stat().st_mtime).strftime("%Y-%m-%d %H:%M UTC"),
                    }
                    for item in snapshot_files
                ]
            )
            st.dataframe(snapshot_table, use_container_width=True, hide_index=True)

with search_tab:
    st.subheader("Analyst Search")
    st.caption("Searches your local Whoosh index and evidence records. This is useful for monitoring indicators, domains, aliases, or organization names already present in your collected dataset.")
    query = st.text_input("Indicator or keyword", placeholder="email, domain, alias, org, hash fragment", key="search_query")

    if query:
        index_results = pd.DataFrame(search(query))
        evidence_results = search_evidence(query)

        if not index_results.empty:
            index_results = apply_scope_filter(index_results, scope)
            if not index_results.empty:
                index_results["indexed_at"] = pd.to_datetime(index_results["indexed_at"], errors="coerce")
                st.markdown("#### Snapshot Matches")
                st.dataframe(index_results, use_container_width=True, hide_index=True)

        if not evidence_results.empty:
            evidence_results = apply_scope_filter(evidence_results, scope)
            if not evidence_results.empty:
                st.markdown("#### Evidence Matches")
                st.dataframe(evidence_results, use_container_width=True, hide_index=True)

        if index_results.empty and evidence_results.empty:
            st.warning("No local matches were found in the current scope.")

with evidence_tab:
    st.subheader("Exposure Artifacts")
    st.caption("Review records extracted from previously crawled pages. Treat all data here as sensitive and handle it under your legal and operational controls.")

    if scoped_findings.empty:
        st.info("No evidence records are available yet.")
    else:
        finding_types = ["All types"] + sorted(scoped_findings["leak_type"].dropna().unique().tolist())
        selected_type = st.selectbox("Filter by type", finding_types)

        filtered_findings = scoped_findings.copy()
        if selected_type != "All types":
            filtered_findings = filtered_findings[filtered_findings["leak_type"] == selected_type]

        st.dataframe(filtered_findings, use_container_width=True, hide_index=True)
        st.download_button(
            "Download evidence CSV",
            filtered_findings.to_csv(index=False),
            file_name="ghostcrawler_evidence.csv",
            use_container_width=True,
        )

        evidence_summary = (
            filtered_findings["leak_type"]
            .fillna("unknown")
            .value_counts()
            .rename_axis("type")
            .reset_index(name="count")
        )
        st.markdown("#### Evidence Type Summary")
        st.dataframe(evidence_summary, use_container_width=True, hide_index=True)

    st.subheader("Threat Alerts")
    if ALERTS_PATH.exists():
        alerts_df = pd.DataFrame(json.loads(ALERTS_PATH.read_text(encoding="utf-8")))
        alerts_df = apply_scope_filter(alerts_df, scope)
        if alerts_df.empty:
            st.info("No alerts were found in the current scope.")
        else:
            st.dataframe(alerts_df, use_container_width=True, hide_index=True)
    else:
        st.info("No alert feed has been generated yet.")

    st.subheader("Latest PDF Report")
    if PDF_REPORT.exists():
        st.download_button(
            "Download PDF report",
            PDF_REPORT.read_bytes(),
            file_name="ghostcrawler_threat_report.pdf",
            use_container_width=True,
        )
    else:
        st.info("Generate a report from the sidebar when you are ready.")

with ops_tab:
    st.subheader("Targeted Collection")
    st.caption("Use analyst-led collection to deepen coverage for sources you explicitly select. This keeps the workflow closer to a threat-hunting queue instead of uncontrolled crawling.")

    st.session_state.crawl_depth = st.slider("Max depth", min_value=1, max_value=5, value=st.session_state.crawl_depth)

    candidate_sources = scoped_sources.copy()
    if not candidate_sources.empty:
        available_urls = candidate_sources["url"].dropna().unique().tolist()
    else:
        available_urls = []

    selected_urls = st.multiselect(
        f"Select targets ({len(available_urls)} available in scope)",
        options=available_urls,
    )

    if st.button("Run Targeted Crawl", width='stretch'):
        if not selected_urls:
            st.warning("Select at least one target to crawl.")
        else:
            with st.spinner("Running targeted crawl..."):
                results = run_selected_crawls(selected_urls, st.session_state.crawl_depth)
            st.success(f"Completed {len(results)} crawl job(s).")
            st.dataframe(pd.DataFrame(results), use_container_width=True, hide_index=True)

    st.subheader("Snapshot Viewer")
    snapshot_files = sorted(SNAPSHOT_DIR.glob("*.html"))
    if not snapshot_files:
        st.info("No snapshots are available yet.")
    else:
        selected_snapshot = st.selectbox("Open snapshot", [path.name for path in snapshot_files])
        snapshot_path = SNAPSHOT_DIR / selected_snapshot
        html = snapshot_path.read_text(encoding="utf-8", errors="ignore")
        st.components.v1.html(html, height=640, scrolling=True)
