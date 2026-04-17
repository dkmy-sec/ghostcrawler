import json
import re
import sqlite3
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path

import pandas as pd
import requests
import streamlit as st
from bs4 import BeautifulSoup
from fpdf import FPDF
from requests_tor import RequestsTor

sys.path.append(str(Path(__file__).resolve().parent.parent))

from core.crawler import crawl_onion
from core.analyst_workbench import (
    add_saved_hunt,
    add_watchlist,
    load_analyst_alerts,
    load_saved_hunts,
    load_watchlist_hits,
    load_watchlists,
    refresh_analyst_signals,
)
from core.intel_schema import ensure_database
from core.network_catalog import classify_network, classify_scope, network_label, supports_fetch
from core.search_engine import build_index, search
from core.utils import DATA_DIR

DB_PATH = DATA_DIR / "onion_sources.db"
SNAPSHOT_DIR = DATA_DIR / "snapshots"
ALERTS_PATH = DATA_DIR / "alerts.json"
PDF_REPORT = DATA_DIR / "reports" / "threat_report.pdf"
APP_ROOT = Path(__file__).resolve().parent.parent
SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1}
MAP_CLUSTERS = {
    "tor": [("North Atlantic Relay Mesh", 64.1466, -21.9426), ("Amsterdam Exchange", 52.3676, 4.9041)],
    "freenet": [("Berlin Research Grid", 52.52, 13.4050)],
    "gnunet": [("Zurich Mesh Exchange", 47.3769, 8.5417)],
    "riffle": [("Singapore Privacy Transit", 1.3521, 103.8198)],
    "i2p": [("Frankfurt Privacy Hub", 50.1109, 8.6821)],
    "clearnet": [("Virginia Internet Exchange", 39.0438, -77.4874), ("Dublin Cloud Corridor", 53.3498, -6.2603)],
    "unknown": [("Analyst Triage Queue", 41.8781, -87.6298)],
}

ensure_database(DB_PATH)


def get_tor_session():
    return RequestsTor(tor_ports=(9050,), autochange_id=False)


session_tor = get_tor_session()
session_web = requests.Session()


def run_python(script_path: Path):
    return subprocess.run([sys.executable, str(script_path)], cwd=APP_ROOT, check=False)


def process_url(url, session):
    try:
        response = session.get(url, timeout=15)
        text = BeautifulSoup(response.text, "html.parser").get_text(" ", strip=True)
        network = classify_network(url)
        results = []
        for email in re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text):
            results.append(("email", email, text[text.find(email):text.find(email) + 50]))
        for match in re.finditer(r"(?i)(api[_-]?key|apikey|secret|token)[\s:]*[\"']?([A-Za-z0-9\-._~+/]+=*)[\"']?", text):
            results.append(("api_key", match.group(2), match.group(0)))
        with sqlite3.connect(DB_PATH) as conn:
            for leak_type, value, snippet in results:
                conn.execute(
                    "INSERT INTO data_leaks (url, leak_type, value, snippet, network) VALUES (?, ?, ?, ?, ?)",
                    (url, leak_type, value, snippet, network),
                )
            conn.commit()
        return {"status": "success", "url": url, "network": network}
    except Exception as exc:
        return {"status": "error", "url": url, "error": str(exc)}


def get_connection():
    return sqlite3.connect(DB_PATH)


def table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,)).fetchone()
    return row is not None


def table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall() if table_exists(conn, table_name) else []
    return {row[1] for row in rows}


def apply_scope_filter(frame: pd.DataFrame, scope: str, url_column: str = "url") -> pd.DataFrame:
    if frame.empty or scope == "All Sources" or url_column not in frame.columns:
        return frame
    wanted = "Dark Web" if scope == "Dark Web" else "Clear Net"
    return frame[frame[url_column].fillna("").map(classify_scope) == wanted].copy()


def severity_score(value: str) -> int:
    return SEVERITY.get((value or "").lower(), 1)


def fmt_ts(value) -> str:
    parsed = pd.to_datetime(value, errors="coerce", utc=True)
    return "Unknown" if pd.isna(parsed) else parsed.strftime("%Y-%m-%d %H:%M UTC")


def load_overview_data():
    sources = pd.DataFrame(columns=["url", "source", "tag", "network", "collector", "priority", "last_seen"])
    findings = pd.DataFrame(columns=["url", "leak_type", "value", "snippet", "network", "timestamp"])
    frontier = pd.DataFrame(columns=["status", "count"])
    zero_day = pd.DataFrame(columns=["title", "signal_type", "indicator", "severity", "confidence", "url", "network", "last_seen"])
    if not DB_PATH.exists():
        return sources, findings, frontier, zero_day
    with get_connection() as conn:
        if table_exists(conn, "onions"):
            cols = table_columns(conn, "onions")
            parts = [c if c in cols else f"NULL AS {c}" for c in ["url", "source", "tag", "network", "collector", "priority", "last_seen"]]
            sources = pd.read_sql_query(f"SELECT {', '.join(parts)} FROM onions", conn)
        if table_exists(conn, "data_leaks"):
            cols = table_columns(conn, "data_leaks")
            parts = [c if c in cols else f"NULL AS {c}" for c in ["url", "leak_type", "value", "snippet", "network", "timestamp"]]
            findings = pd.read_sql_query(f"SELECT {', '.join(parts)} FROM data_leaks ORDER BY timestamp DESC", conn)
        if table_exists(conn, "frontier"):
            frontier = pd.read_sql_query("SELECT status, COUNT(*) AS count FROM frontier GROUP BY status ORDER BY status", conn)
        if table_exists(conn, "zero_day_signals"):
            zero_day = pd.read_sql_query("SELECT title, signal_type, indicator, severity, confidence, url, network, last_seen FROM zero_day_signals ORDER BY last_seen DESC", conn)
    return sources, findings, frontier, zero_day


def search_evidence(term: str):
    records = []
    if not term or not DB_PATH.exists():
        return pd.DataFrame(columns=["type", "url", "summary", "timestamp"])
    with get_connection() as conn:
        if table_exists(conn, "data_leaks"):
            frame = pd.read_sql_query(
                "SELECT leak_type, url, value, snippet, timestamp FROM data_leaks WHERE value LIKE ? OR snippet LIKE ? OR url LIKE ? ORDER BY timestamp DESC LIMIT 100",
                conn,
                params=(f"%{term}%", f"%{term}%", f"%{term}%"),
            )
            if not frame.empty:
                frame["type"] = frame["leak_type"].fillna("finding")
                frame["summary"] = frame["value"].fillna("") + " " + frame["snippet"].fillna("")
                records.append(frame[["type", "url", "summary", "timestamp"]])
        if table_exists(conn, "zero_day_signals"):
            frame = pd.read_sql_query(
                "SELECT signal_type, url, indicator, details, last_seen FROM zero_day_signals WHERE indicator LIKE ? OR details LIKE ? OR url LIKE ? ORDER BY last_seen DESC LIMIT 100",
                conn,
                params=(f"%{term}%", f"%{term}%", f"%{term}%"),
            )
            if not frame.empty:
                frame["type"] = frame["signal_type"].fillna("zero_day_signal")
                frame["summary"] = frame["indicator"].fillna("") + " " + frame["details"].fillna("")
                frame["timestamp"] = frame["last_seen"]
                records.append(frame[["type", "url", "summary", "timestamp"]])
    return pd.concat(records, ignore_index=True) if records else pd.DataFrame(columns=["type", "url", "summary", "timestamp"])


def build_threat_map(sources: pd.DataFrame, findings: pd.DataFrame, zero_day: pd.DataFrame):
    events = []
    for frame, weight_col in [(sources, None), (findings, None), (zero_day, "severity")]:
        if frame.empty:
            continue
        for row in frame.fillna("").to_dict("records"):
            network = row.get("network") or classify_network(row.get("url"))
            clusters = MAP_CLUSTERS.get(network, MAP_CLUSTERS["unknown"])
            choice = clusters[abs(hash((row.get("url") or row.get("title") or row.get("value") or "x"))) % len(clusters)]
            weight = 1.0 if weight_col is None else 2.0 + severity_score(row.get(weight_col))
            events.append({"cluster": choice[0], "latitude": choice[1], "longitude": choice[2], "weight": weight, "network": network_label(network)})
    if not events:
        return pd.DataFrame(), pd.DataFrame()
    points = pd.DataFrame(events)
    clusters = points.groupby(["cluster", "latitude", "longitude", "network"], as_index=False)["weight"].sum().sort_values("weight", ascending=False)
    clusters["pressure"] = clusters["weight"].round(1)
    return points, clusters


def build_velocity(findings: pd.DataFrame, zero_day: pd.DataFrame):
    parts = []
    if not findings.empty:
        a = findings.copy()
        a["date"] = pd.to_datetime(a["timestamp"], errors="coerce").dt.date
        parts.append(a.dropna(subset=["date"]).groupby("date").size().reset_index(name="evidence"))
    if not zero_day.empty:
        b = zero_day.copy()
        b["date"] = pd.to_datetime(b["last_seen"], errors="coerce").dt.date
        parts.append(b.dropna(subset=["date"]).groupby("date").size().reset_index(name="day_zero"))
    if not parts:
        return pd.DataFrame()
    velocity = parts[0]
    for frame in parts[1:]:
        velocity = velocity.merge(frame, on="date", how="outer")
    return velocity.fillna(0).sort_values("date").tail(21)


def build_priority_queue(findings: pd.DataFrame, zero_day: pd.DataFrame):
    rows = []
    if not zero_day.empty:
        temp = zero_day.copy()
        temp["score"] = temp["severity"].map(severity_score).fillna(1) * 25 + temp["confidence"].fillna(0)
        temp = temp.sort_values(["score", "last_seen"], ascending=[False, False]).head(8)
        for _, row in temp.iterrows():
            rows.append({"queue": "Day Zero", "priority": row["severity"].upper(), "title": row["title"], "network": network_label(row["network"]), "summary": row["indicator"], "timestamp": fmt_ts(row["last_seen"])})
    if not findings.empty:
        for _, row in findings.head(5).iterrows():
            rows.append({"queue": "Evidence", "priority": "MEDIUM", "title": f"{row['leak_type']} observed", "network": network_label(row["network"] or classify_network(row["url"])), "summary": row["value"], "timestamp": fmt_ts(row["timestamp"])})
    return pd.DataFrame(rows[:10])


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
    return results


def generate_pdf_report():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("Arial", "B", 18)
    pdf.cell(0, 10, "Ghostcrawler Threat Intel Report", ln=True)
    pdf.set_font("Arial", "", 11)
    pdf.multi_cell(0, 6, f"Generated: {datetime.utcnow().isoformat()} UTC")
    PDF_REPORT.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(PDF_REPORT))


st.set_page_config(page_title="Ghostcrawler Command Deck", page_icon="GC", layout="wide", initial_sidebar_state="expanded")
st.markdown(
    """
    <style>
    .stApp {background: radial-gradient(circle at 12% 18%, rgba(111,243,197,.12), transparent 22%), radial-gradient(circle at 86% 14%, rgba(107,184,255,.14), transparent 24%), linear-gradient(180deg, #04101a 0%, #081621 48%, #06111a 100%); color: #f5f7fb;}
    [data-testid="stSidebar"] {background: linear-gradient(180deg, #07111b 0%, #0b1723 100%);}
    .hero, .panel, .metric {border: 1px solid rgba(145,177,214,.18); border-radius: 20px; background: linear-gradient(180deg, rgba(8,18,29,.96), rgba(14,27,43,.92));}
    .hero {padding: 1.4rem 1.5rem; margin-bottom: 1rem;}
    .metric {padding: 1rem; min-height: 116px;}
    .panel {padding: 1rem; margin-bottom: 1rem;}
    .label {font-size: .8rem; letter-spacing: .12em; text-transform: uppercase; color: #8fa1bd;}
    .value {font-size: 2rem; font-weight: 700; margin-top: .3rem;}
    .foot {color: #d7e3f5; opacity: .85; margin-top: .4rem;}
    </style>
    """,
    unsafe_allow_html=True,
)

if "crawl_depth" not in st.session_state:
    st.session_state.crawl_depth = 4

sources_df, findings_df, frontier_df, zero_day_df = load_overview_data()
scope = st.sidebar.radio("Visibility", ["Dark Web", "Clear Net", "All Sources"], index=0)
lens = st.sidebar.selectbox("Lens", ["Threat Intel", "Zero-Day Watch", "Exposure Monitoring"])
st.sidebar.caption("Built for analyst-led threat research and authorized exposure monitoring.")

if st.sidebar.button("Refresh Source Catalog", use_container_width=True):
    run_python(APP_ROOT / "core" / "aggregate_feeds.py")
if st.sidebar.button("Run Seed Batch", use_container_width=True):
    run_python(APP_ROOT / "core" / "crawler.py")
if st.sidebar.button("Run Frontier Crawl", use_container_width=True):
    run_python(APP_ROOT / "core" / "frontier_crawl.py")
if st.sidebar.button("Build Search Index", use_container_width=True):
    build_index()
if st.sidebar.button("Generate Intel Report", use_container_width=True):
    generate_pdf_report()
if st.sidebar.button("Refresh Analyst Signals", use_container_width=True):
    refresh_stats = refresh_analyst_signals()
    st.sidebar.success(
        f"Rules refreshed: {refresh_stats['watchlist_matches']} watchlist hit(s), {refresh_stats['hunt_matches']} hunt hit(s)."
    )

seed_url = st.sidebar.text_input("Target URL", value="http://vfnmxpa6fo4jdpyq3yneqhglluweax2uclvxkytfpmpkp5rsl75ir5qd.onion")
seed_network = classify_network(seed_url)
st.sidebar.caption(f"Detected network: {network_label(seed_network)}")
if st.sidebar.button("Harvest Target", use_container_width=True):
    if not supports_fetch(seed_url):
        st.sidebar.warning(f"{network_label(seed_network)} needs a dedicated connector before live collection can run.")
    elif seed_network == "tor":
        process_url(seed_url, session_tor)
    else:
        process_url(seed_url, session_web)

scoped_sources = apply_scope_filter(sources_df, scope)
scoped_findings = apply_scope_filter(findings_df, scope)
scoped_zero_day = apply_scope_filter(zero_day_df, scope)
watchlists_df = load_watchlists()
saved_hunts_df = load_saved_hunts()
watchlist_hits_df = load_watchlist_hits()
analyst_alerts_df = load_analyst_alerts()

latest_seen = "No telemetry"
if not scoped_sources.empty:
    valid_seen = pd.to_datetime(scoped_sources["last_seen"], errors="coerce").dropna()
    if not valid_seen.empty:
        latest_seen = valid_seen.max().strftime("%Y-%m-%d %H:%M UTC")

map_points, map_clusters = build_threat_map(scoped_sources, scoped_findings, scoped_zero_day)
velocity = build_velocity(scoped_findings, scoped_zero_day)
priority_queue = build_priority_queue(scoped_findings, scoped_zero_day)
critical_zero_day = int((scoped_zero_day["severity"].fillna("").str.lower() == "critical").sum()) if not scoped_zero_day.empty else 0
fetch_ready = int(scoped_sources["url"].fillna("").map(supports_fetch).sum()) if not scoped_sources.empty else 0
coverage_pct = int(fetch_ready / len(scoped_sources.index) * 100) if len(scoped_sources.index) else 0
pending = int(frontier_df[frontier_df["status"] == "pending"]["count"].iloc[0]) if not frontier_df.empty and not frontier_df[frontier_df["status"] == "pending"].empty else 0

st.markdown(
    f"""
    <div class="hero">
        <div class="label">Ghostcrawler // Analyst Command Deck</div>
        <h1 style="margin:.2rem 0 0 0; font-size:2.35rem;">Threat intelligence workspace for researchers and security teams.</h1>
        <div style="color:#8fa1bd; margin-top:.6rem;">A cleaner command center for day-zero triage, darknet coverage mapping, source prioritization, and deeper analyst-led collection.</div>
        <div style="display:flex; gap:.5rem; flex-wrap:wrap; margin-top:1rem;">
            <div style="border:1px solid rgba(111,243,197,.18); padding:.35rem .7rem; border-radius:999px;">Scope: {scope}</div>
            <div style="border:1px solid rgba(111,243,197,.18); padding:.35rem .7rem; border-radius:999px;">Lens: {lens}</div>
            <div style="border:1px solid rgba(111,243,197,.18); padding:.35rem .7rem; border-radius:999px;">Latest Seen: {latest_seen}</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

metric_cols = st.columns(5)
cards = [
    ("Critical Day-Zero", critical_zero_day, "Immediate analyst queue"),
    ("Signals In Queue", len(scoped_zero_day.index), "Exploit and disclosure leads"),
    ("Evidence Records", len(scoped_findings.index), "Harvested exposure artifacts"),
    ("Fetch-Ready Coverage", f"{coverage_pct}%", f"{fetch_ready} sources collectable now"),
    ("Frontier Pending", pending, "Queued for deeper traversal"),
]
for column, (label, value, foot) in zip(metric_cols, cards):
    column.markdown(f'<div class="metric"><div class="label">{label}</div><div class="value">{value}</div><div class="foot">{foot}</div></div>', unsafe_allow_html=True)

command_tab, hunt_tab, rules_tab, evidence_tab, ops_tab = st.tabs(
    ["Command Deck", "Hunt Workbench", "Watchlists & Hunts", "Evidence Locker", "Collection Lab"]
)

with command_tab:
    left, right = st.columns((1.3, 0.9))
    with left:
        st.markdown('<div class="panel"><div class="label">Threat Pressure Map</div><div class="foot">Hotspots are analyst-attribution clusters derived from source network and signal severity, not exact actor geolocation.</div></div>', unsafe_allow_html=True)
        if map_points.empty:
            st.info("No mapped telemetry is available yet.")
        else:
            st.map(map_points[["latitude", "longitude"]], zoom=1, use_container_width=True)
            st.dataframe(map_clusters[["cluster", "network", "pressure"]], use_container_width=True, hide_index=True)
        st.markdown('<div class="panel"><div class="label">Signal Velocity</div><div class="foot">Daily throughput across evidence and day-zero detections.</div></div>', unsafe_allow_html=True)
        if velocity.empty:
            st.info("Signal velocity will appear once timestamps accumulate.")
        else:
            st.line_chart(velocity.set_index("date"), use_container_width=True, height=260)
    with right:
        st.markdown('<div class="panel"><div class="label">Priority Queue</div><div class="foot">High-signal items that deserve immediate analyst attention.</div></div>', unsafe_allow_html=True)
        if priority_queue.empty:
            st.info("No priority queue items yet.")
        else:
            st.dataframe(priority_queue, use_container_width=True, hide_index=True)
        st.markdown('<div class="panel"><div class="label">Rule Driven Alerts</div><div class="foot">Open analyst alerts generated from watchlists and saved hunts.</div></div>', unsafe_allow_html=True)
        if analyst_alerts_df.empty:
            st.info("No rule-driven alerts yet.")
        else:
            st.dataframe(analyst_alerts_df.head(8), use_container_width=True, hide_index=True)
        coverage = scoped_sources.copy()
        if not coverage.empty:
            coverage["network_name"] = coverage["network"].fillna(coverage["url"].map(classify_network)).map(network_label)
            coverage_matrix = coverage.groupby(["network_name", "tag"]).size().reset_index(name="count").sort_values(["network_name", "count"], ascending=[True, False])
            st.markdown('<div class="panel"><div class="label">Network Coverage</div><div class="foot">Where collection is concentrated today.</div></div>', unsafe_allow_html=True)
            st.dataframe(coverage_matrix.head(16), use_container_width=True, hide_index=True)

with hunt_tab:
    query = st.text_input("Indicator, actor alias, domain, CVE, or organization", placeholder="CVE-2026-12345, org name, alias, domain, hash fragment")
    if query:
        index_results = apply_scope_filter(pd.DataFrame(search(query)), scope)
        evidence_results = apply_scope_filter(search_evidence(query), scope)
        left, right = st.columns(2)
        with left:
            st.markdown("#### Indexed Snapshot Matches")
            st.dataframe(index_results, use_container_width=True, hide_index=True) if not index_results.empty else st.info("No indexed matches.")
        with right:
            st.markdown("#### Evidence and Signal Matches")
            st.dataframe(evidence_results, use_container_width=True, hide_index=True) if not evidence_results.empty else st.info("No evidence or signal matches.")
    else:
        st.info("Start with a CVE, org, domain, hash fragment, alias, or keyword to pivot through the local corpus.")

with rules_tab:
    st.subheader("Watchlists And Saved Hunts")
    st.caption("Create repeatable analyst rules, then refresh them into hits and alert records as new data lands.")

    create_left, create_right = st.columns(2)
    with create_left:
        st.markdown("#### Add IOC Watchlist")
        with st.form("watchlist_form", clear_on_submit=True):
            wl_name = st.text_input("Rule name", placeholder="VIP Domain Monitor")
            wl_indicator = st.text_input("Indicator", placeholder="example.com, actor alias, CVE, wallet, email")
            wl_type = st.selectbox("Indicator type", ["keyword", "domain", "email", "alias", "cve", "wallet", "url"])
            wl_severity = st.selectbox("Severity", ["critical", "high", "medium", "low"], index=2)
            wl_scope = st.selectbox("Scope", ["All Sources", "Dark Web", "Clear Net"], index=0)
            wl_tags = st.text_input("Tags", placeholder="vip, ransomware, identity")
            wl_fuzzy = st.checkbox("Enable fuzzy matching", value=True)
            wl_submit = st.form_submit_button("Save Watchlist", use_container_width=True)
        if wl_submit:
            if wl_name.strip() and wl_indicator.strip():
                add_watchlist(wl_name, wl_indicator, wl_type, wl_severity, wl_tags, wl_scope, wl_fuzzy)
                st.success("Watchlist saved.")
                st.rerun()
            else:
                st.warning("Name and indicator are required.")

    with create_right:
        st.markdown("#### Add Saved Hunt")
        with st.form("saved_hunt_form", clear_on_submit=True):
            hunt_name = st.text_input("Hunt name", placeholder="VPN Broker Chatter")
            hunt_query = st.text_input("Query", placeholder="vpn access broker or CVE-2026")
            hunt_description = st.text_area("Description", placeholder="Track broker chatter around enterprise remote access.")
            hunt_scope = st.selectbox("Hunt scope", ["All Sources", "Dark Web", "Clear Net"], index=0)
            hunt_severity = st.selectbox("Hunt severity", ["critical", "high", "medium", "low"], index=1)
            hunt_submit = st.form_submit_button("Save Hunt", use_container_width=True)
        if hunt_submit:
            if hunt_name.strip() and hunt_query.strip():
                add_saved_hunt(hunt_name, hunt_query, hunt_description, hunt_scope, hunt_severity)
                st.success("Saved hunt created.")
                st.rerun()
            else:
                st.warning("Name and query are required.")

    summary_cols = st.columns(4)
    summaries = [
        ("Active Watchlists", int(len(watchlists_df.index)), "Repeatable IOC monitors"),
        ("Saved Hunts", int(len(saved_hunts_df.index)), "Reusable analyst pivots"),
        ("Watchlist Hits", int(len(watchlist_hits_df.index)), "Matched artifacts and signals"),
        ("Analyst Alerts", int(len(analyst_alerts_df.index)), "Open rule-driven notifications"),
    ]
    for column, (label, value, foot) in zip(summary_cols, summaries):
        column.markdown(
            f'<div class="metric"><div class="label">{label}</div><div class="value">{value}</div><div class="foot">{foot}</div></div>',
            unsafe_allow_html=True,
        )

    top_left, top_right = st.columns((1.1, 0.9))
    with top_left:
        st.markdown("#### Current Watchlists")
        if watchlists_df.empty:
            st.info("No watchlists created yet.")
        else:
            st.dataframe(watchlists_df, use_container_width=True, hide_index=True)

        st.markdown("#### Recent Watchlist Hits")
        if watchlist_hits_df.empty:
            st.info("No watchlist hits yet. Refresh analyst signals after adding rules.")
        else:
            st.dataframe(watchlist_hits_df, use_container_width=True, hide_index=True)

    with top_right:
        st.markdown("#### Saved Hunts")
        if saved_hunts_df.empty:
            st.info("No saved hunts created yet.")
        else:
            st.dataframe(saved_hunts_df, use_container_width=True, hide_index=True)

        st.markdown("#### Analyst Alerts")
        if analyst_alerts_df.empty:
            st.info("No analyst alerts yet.")
        else:
            st.dataframe(analyst_alerts_df, use_container_width=True, hide_index=True)

with evidence_tab:
    left, right = st.columns(2)
    with left:
        st.markdown("#### Exposure Artifacts")
        if scoped_findings.empty:
            st.info("No evidence records are available yet.")
        else:
            st.dataframe(scoped_findings, use_container_width=True, hide_index=True)
            st.download_button("Export evidence CSV", scoped_findings.to_csv(index=False), file_name="ghostcrawler_evidence.csv", use_container_width=True)
    with right:
        st.markdown("#### Day-Zero Intelligence")
        if scoped_zero_day.empty:
            st.info("No day-zero signals are available yet.")
        else:
            zero_day_view = scoped_zero_day.copy()
            zero_day_view["network"] = zero_day_view["network"].fillna("unknown").map(network_label)
            st.dataframe(zero_day_view, use_container_width=True, hide_index=True)
            st.download_button("Export zero-day CSV", zero_day_view.to_csv(index=False), file_name="ghostcrawler_zero_day_signals.csv", use_container_width=True)
    st.markdown("#### Alert Feed")
    if ALERTS_PATH.exists():
        alerts_df = apply_scope_filter(pd.DataFrame(json.loads(ALERTS_PATH.read_text(encoding="utf-8"))), scope)
        st.dataframe(alerts_df, use_container_width=True, hide_index=True) if not alerts_df.empty else st.info("No alerts in this scope.")
    else:
        st.info("No alert feed has been generated yet.")
    if PDF_REPORT.exists():
        st.download_button("Download threat intel PDF", PDF_REPORT.read_bytes(), file_name="ghostcrawler_threat_report.pdf", use_container_width=True)

with ops_tab:
    ops_left, ops_right = st.columns(2)
    with ops_left:
        st.session_state.crawl_depth = st.slider("Deep Hunt Depth", min_value=1, max_value=8, value=st.session_state.crawl_depth, help="2-3 for recon, 4-6 for forums, 7-8 for deliberate archive sweeps.")
        available_urls = scoped_sources["url"].dropna().unique().tolist() if not scoped_sources.empty else []
        selected_urls = st.multiselect(f"Priority Targets ({len(available_urls)} available)", options=available_urls)
        if st.button("Run Deep Targeted Crawl", use_container_width=True):
            if not selected_urls:
                st.warning("Select at least one target to crawl.")
            else:
                results = run_selected_crawls(selected_urls, st.session_state.crawl_depth)
                st.dataframe(pd.DataFrame(results), use_container_width=True, hide_index=True)
    with ops_right:
        st.markdown("#### Crawl Profiles")
        st.dataframe(
            pd.DataFrame(
                [
                    {"profile": "Recon", "depth": "2-3", "best_for": "Fresh discovery and homepage validation"},
                    {"profile": "Forum Dive", "depth": "4-6", "best_for": "Communities, leaks, broker chatter"},
                    {"profile": "Archive Sweep", "depth": "7-8", "best_for": "Large directories and old mirrors"},
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )
        st.info("The UI is now oriented around signal density and analyst workflow, which is the right direction if you want this to feel premium later.")
    st.markdown("#### Snapshot Viewer")
    snapshot_files = sorted(SNAPSHOT_DIR.glob("*.html"))
    if not snapshot_files:
        st.info("No snapshots are available yet.")
    else:
        selected_snapshot = st.selectbox("Open snapshot", [path.name for path in snapshot_files])
        html = (SNAPSHOT_DIR / selected_snapshot).read_text(encoding="utf-8", errors="ignore")
        st.components.v1.html(html, height=660, scrolling=True)
