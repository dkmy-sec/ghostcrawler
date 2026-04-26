# ghostcrawler - Threat Intel and Exposure Monitoring Console

**ghostcrawler** is a modular threat-intelligence workspace for cybersecurity analysts, threat hunters, and OSINT teams. It combines source tracking, local snapshot indexing, zero-day signal triage, evidence review, and dashboard-driven workflows for authorized monitoring.

---

### Features

- Watchlist support for emails, keywords, and domains
- Network-aware source catalog for Tor, I2P, Freenet, Gnunet, Riffle, and adjacent darknet connectors
- Zero-day signal queue for exploit chatter, active-exploitation language, and critical-CVE mentions found in collected content
- Live crawling via Tor SOCKS, I2P HTTP proxy routing, Freenet gateway routing, and direct clearnet HTTP
- Local full-text search across indexed HTML snapshots
- Exposure evidence review from the local `data_leaks` table
- Streamlit dashboard with a professional threat-hunter layout
- Source scope toggle for `Dark Web`, `Clear Net`, or `All Sources`
- Coverage views that separate fetch-ready networks from catalog-only networks
- PDF export for analyst reporting
- Dockerized deployment path for a dashboard container, collector container, and Tor sidecar
---

### 🧪 Local Install

```bash
git clone https://github.com/yourhandle/ghostcrawler.git
cd ghostcrawler
pip install -r requirements.txt
```
Requires: tor, python3, streamlit, PySocks, whoosh

---

### 🚀 Run Collection Locally

```bash
python -m core.aggregate_feeds
python -m core.crawler
python -m core.frontier_crawl
python -m core.search_engine
```

---

### 🧭 Launch the Dashboard

```bash
streamlit run cli/dashboard.py
```

The dashboard now includes:

- Overview metrics for sources, snapshots, findings, and queue health
- Analyst search across local index and evidence records
- Evidence review with export controls
- A day-zero intelligence panel for urgent exploit telemetry
- Targeted collection controls instead of a single noisy one-shot workflow
- A clear-net toggle for source filtering and future expansion
- Multi-network source coverage for darknet ecosystems beyond Tor

---

### 🐳 Docker And VPS Launch

The production deployment uses:

- `dashboard`: Streamlit UI
- `collector`: scheduled background ingestion, indexing, and analyst refresh
- `tor`: SOCKS proxy sidecar for Tor collection

Copy the example env if you want to override defaults:

```bash
cp .env.example .env
```

Launch the stack:

```bash
docker compose up -d --build
```

If Tor, I2P, and Freenet are running as separate routed services on your server, set these in `.env` so the collector can use them:

```bash
GHOSTCRAWLER_TOR_SOCKS_HOST=tor
GHOSTCRAWLER_TOR_SOCKS_PORT=9050
GHOSTCRAWLER_I2P_HTTP_PROXY=http://i2p:4444
GHOSTCRAWLER_FREENET_GATEWAY_URL=http://freenet:8888
GHOSTCRAWLER_CLEARNET_CROSS_HOST=false
```

`GHOSTCRAWLER_CLEARNET_CROSS_HOST=false` keeps clearnet crawling same-origin by default so a single seed does not fan out across the whole web. Set it to `true` only if you explicitly want cross-domain expansion.

Open the dashboard on:

```text
http://YOUR_VPS_IP:8501
```

Data is stored in the Docker volume `ghostcrawler_data`, so the DB, snapshots, index, and reports survive container restarts.

The production compose file disables demo content by default:

- `GHOSTCRAWLER_ENABLE_DEMO_CONTENT=false`
- seed catalog bootstrap stays on so the collector has initial sources

Useful ops commands:

```bash
docker compose logs -f collector
docker compose logs -f dashboard
docker compose logs -f tor
docker compose restart collector
```

Quick connector diagnostics from the collector runtime:

```bash
python -m core.check_connectors
python -m core.check_connectors --tor-url http://examplehiddenservice.onion --i2p-url http://example.i2p --freenet-url freenet:USK@example/site/1 --clearnet-url https://example.com
```

If you want to put this behind Nginx or Caddy on your VPS, reverse proxy port `8501` and restrict public access with auth before exposing it more broadly.

---
### 📂 Watchlist Format

```json
{
  "emails": ["you@example.com"],
  "keywords": ["leeaks, ssn, private"],
  "domains": ["google.com"]
}

supports: comma seperated emails, keywords, and dowmains
```

---

### Legal and Ethical Use
This toolkit is for defensive security, authorized intelligence collection, and exposure monitoring only. Do not use it to access illegal content, retain data you are not authorized to store, or perform unauthorized collection against third-party systems.

The multi-darknet catalog is intentionally connector-aware: Tor, I2P, Freenet, and clear-net HTTP collection work when their routed services are configured, while Gnunet, Riffle, ZeroNet, Lokinet, and similar ecosystems are still tracked in the schema and dashboard so dedicated transport adapters can be added without rewriting the app.

For production deployments, the dashboard should still be treated as an analyst console over collected telemetry. Only the transports you actually route and configure should be considered fetch-ready.


---

---

### 🛡️ Reasonable Depth Recommendation
| Depth | Use Case                                                                                                       |
| ----- | -------------------------------------------------------------------------------------------------------------- |
| `0`   | Just the seed link (homepage).                                                                                 |
| `1`   | Crawl links directly on that page. Good for most basic discovery.                                              |
| `2`   | Go one link deeper — useful for directory-style sites.                                                         |
| `3-4` | Deep forums, marketplaces, archives. Beyond this you need guardrails.                                          |
| `5+`  | Only do this with intelligent pruning, deduping, and domain filtering. Otherwise it’s crawling spaghetti hell. |



---

### 👤 Built by Kei Nova

---

### 📝 To-Do Tasks
- [ ] Add instructions on getting tor on Windows/Nix/MacOS
- [ x ] PDF Reports
- [ ] Threat Frequency Charts
- [ ] CSV + Excel alert export
- [ x ] Mass `.onion` scanning engine
- [ ] Go Public at some point.  Once totally dialed in. 
- [ ] Buiding my own Darkweb Aggregator to my own seed_onions.txt list
- [x] Add clearnet into the dashboard scope model.
- [ ] Adding depth to crawling
- [ ] Recursive crawling
