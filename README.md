# ghostcrawler - Threat Intel and Exposure Monitoring Console

**ghostcrawler** is a modular threat-intelligence workspace for cybersecurity analysts, threat hunters, and OSINT teams. It combines source tracking, local snapshot indexing, evidence review, and dashboard-driven triage for authorized monitoring workflows.

---

### Features

- Watchlist support for emails, keywords, and domains
- Dark-web source collection via Tor-based workflows already present in the repo
- Local full-text search across indexed HTML snapshots
- Exposure evidence review from the local `data_leaks` table
- Streamlit dashboard with a professional threat-hunter layout
- Source scope toggle for `Dark Web`, `Clear Net`, or `All Sources`
- PDF export for analyst reporting
---

### 🧪 Install

```bash
git clone https://github.com/yourhandle/ghostcrawler.git
cd ghostcrawler
pip install -r requirements.txt
```
Requires: tor, python3, streamlit, requests_tor, whoosh

---

### 🚀 Run a Scan

```bash
python cli/run_scan.py
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
- Targeted collection controls instead of a single noisy one-shot workflow
- A clear-net toggle for source filtering and future expansion

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
