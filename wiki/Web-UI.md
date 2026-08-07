# Web UI

Default address: **http://127.0.0.1:8088**

---

## Home

- Search CVEs and products
- Latest CVEs / latest exploits
- Microsoft **Patch Tuesday** view

---

## CVE detail

When feeds are synced, a CVE page can show:

- Patches and references
- Exploit-DB entries
- MSRC knowledge-base mappings
- Nuclei / Metasploit module maps
- Heuristic **YARA** / **Sigma** starters
- ATT&CK-related aids

---

## Manage

| Action | Description |
|---|---|
| Sync DB | Download and ingest threat feeds into the local app DB |
| Live status | Per-feed on/off toggles |
| Schedule | Optional timed Sync (disabled by default) |
| Backup & restore | Snapshots under `data/backups/` (optional settings) |
| NSE download | NSE script + offline **`vulnlocal.pack`** package |

---

## Settings

| Section | Description |
|---|---|
| Proxy | HTTP, HTTPS, SOCKS4, SOCKS5 for all sync downloads |
| Sync source URLs | Official feed endpoints (pre-filled on first run) |

Saved to: `data/settings.json`

Built-in defaults live in code (`app/config.py` / `app/settings_store.py`).

---

## In-app docs

The app also includes **Manual**, **FAQ**, and **About** pages in the navigation bar.
