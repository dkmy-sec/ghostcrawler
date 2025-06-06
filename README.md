# 👻 ghostcrawler — Cyberpunk Dark Web Threat Intel Toolkit

> “The net remembers. Let’s find out what it remembers about you."

**ghostcrawler** is a modular, hacker-themed dark web crawler and leak detection engine. Built for cybersecurity analysts, threat hunters, and netrunners who want visibility into the hidden grid.

---

### 🔥 Features

- 🧠 AI keyword fuzzing for emails, SSNs, credit cards, companies
- 🌐 Crawls darknet via Tor
- 🔄 Auto-rotates Tor identities
- 🕵️ Alerts you to leaks via CLI or dashboard
- 🔍 Full-text search on indexed `.onion` sites
- 📊 Streamlit frontend for threat visibility
- 🧙‍♂️ Aggregated super list of onion sites `seed_onions.txt`
- 
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

### 🛡️ Legal & Ethical
This toolkit is for ***educational*** and ***defensive cybersecurity*** purposes only. Do not use it to access illegal content.


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
- [ ] Add clearnet into the mix.