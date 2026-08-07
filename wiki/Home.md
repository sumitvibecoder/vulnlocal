# vulnlocal Wiki

**vulnlocal** is a local offline vulnerability intelligence correlator with a web UI and Nmap NSE scanning.

- Mirrors **official** bulk/JSON feeds only (no HTML scraping)
- Correlates CVE · NVD · Exploit-DB · Microsoft MSRC · CISA KEV and more
- Scan hosts via Nmap (**online API** or **offline `vulnlocal.pack`**)

For authorized research on systems you own or have permission to test.

| | |
|---|---|
| **Version** | 1.0.0 |
| **License** | MIT |
| **Repo** | https://github.com/sumitvibecoder/vulnlocal |
| **Default UI** | http://127.0.0.1:8088 |

---

## What it is / isn’t

| Claim | Reality |
|---|---|
| Commercial GUI vuln scanner | **No** — host checks are Nmap NSE + local correlator |
| Scrapes MSRC / Exploit-DB HTML | **No** — official APIs and archives only |
| Exploit runner | **No** — research correlation only |

---

## Wiki pages

| Page | Topic |
|---|---|
| [Installation](Installation) | Clone, venv, init-db, first start |
| [Web-UI](Web-UI) | Home, CVE detail, Manage, Settings |
| [Sync-and-Feeds](Sync-and-Feeds) | Sync DB, feeds, where URLs are stored |
| [Nmap-NSE](Nmap-NSE) | Online API and offline pack scanning |
| [Architecture](Architecture) | App DB vs NSE pack |
| [FAQ](FAQ) | Common questions |
| [Security](Security) | Safe use and hardening |

---

## Quick start

```bash
git clone https://github.com/sumitvibecoder/vulnlocal.git
cd vulnlocal
python -m venv .venv
# Windows PowerShell:  .venv\Scripts\Activate.ps1
# Linux/macOS:         source .venv/bin/activate
python -m pip install -r requirements.txt
python run.py init-db
python run.py --host 127.0.0.1 --port 8088
```

Then open **Manage → Sync DB**, and use [Nmap-NSE](Nmap-NSE) when the pack is ready.
