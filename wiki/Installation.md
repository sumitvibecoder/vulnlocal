# Installation

**Requirements:** Python **3.10+**, optional [Nmap](https://nmap.org/) for NSE. Works on Windows, Linux, and macOS.

---

## 1. Clone

```bash
git clone https://github.com/sumitvibecoder/vulnlocal.git
cd vulnlocal
```

---

## 2. Virtual environment

```bash
python -m venv .venv
```

Activate:

| OS | Command |
|---|---|
| Windows (cmd) | `.venv\Scripts\activate` |
| Windows (PowerShell) | `.venv\Scripts\Activate.ps1` |
| Linux / macOS | `source .venv/bin/activate` |

On Linux, if `python` is missing, use `python3`.

---

## 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

---

## 4. Initialize database and settings

```bash
python run.py init-db
```

This:

- Creates the local SQLite schema under `data/`
- Seeds `data/settings.json` with **default sync source URLs** (Settings page is pre-filled)

---

## 5. Start the web UI

```bash
python run.py --host 127.0.0.1 --port 8088
```

Open: http://127.0.0.1:8088

### Development mode (loopback only)

```bash
python run.py --dev --host 127.0.0.1 --port 8088
```

---

## 6. First sync

1. Open **Manage → Sync DB** (or run `python run.py ingest-all`)
2. Wait for feeds (large downloads; can take a long time)
3. Download the **NSE script + pack** from Manage when ready

See [Sync-and-Feeds](Sync-and-Feeds) and [Nmap-NSE](Nmap-NSE).

---

## Local folders (not in git)

| Path | Purpose |
|---|---|
| `data/vulnlocal.db` | App SQLite database (UI / search / sync) |
| `data/settings.json` | Proxy + feed URLs |
| `downloads/` | Feed download cache |
| `nse/db/vulnlocal.pack/` | Offline NSE index (built after Sync) |

These are regenerable / local-only and should not be committed to GitHub.
