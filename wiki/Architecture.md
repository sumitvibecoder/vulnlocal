# Architecture

```text
Official feeds
     │
     ▼
 Sync / ingest  ──►  data/vulnlocal.db   (Flask web UI, search, CVE pages)
     │
     ├── export ──►  nse/db/vulnlocal.pack/   (offline NSE)
     └── API    ──►  vulnlocal.api=http(s)://…  (online NSE)
```

---

## Components

| Component | Path | Role |
|---|---|---|
| Web app | `app/`, `run.py` | Flask UI, ingest, sync, export |
| App database | `data/vulnlocal.db` | SQLite for UI / search / sync |
| Settings | `data/settings.json` | Proxy + feed URLs |
| Feed cache | `downloads/` | Temporary archives |
| NSE script | `nse/vulnlocal.nse` | Nmap correlator |
| Offline NSE index | `nse/db/vulnlocal.pack/` | Lua-readable TSV pack |

---

## App DB vs NSE pack

| | App DB | NSE pack |
|---|---|---|
| Path | `data/vulnlocal.db` | `nse/db/vulnlocal.pack/` |
| Format | SQLite | Directory of TSV buckets + `META` |
| Used by | Web UI | Offline Nmap NSE |
| Size | Often multi‑GB | Large, but split into smaller files |
| In git? | No | No |

Do not push the app DB to GitHub (single-file limit is 100 MB; DB is typically much larger). Prefer Manage download / GitHub **Releases** for pack zips if you need to distribute offline data.
