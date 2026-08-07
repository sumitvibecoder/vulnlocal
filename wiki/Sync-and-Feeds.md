# Sync and Feeds

**Sync DB** pulls official bulk/JSON feeds into the local app database (`data/vulnlocal.db`).

---

## Feed families

| Area | Sources |
|---|---|
| CVE / NVD | CVE List V5, NVD JSON 2.0, CWE |
| Exploits | Exploit-DB exploits, shellcodes, papers |
| Microsoft | MSRC CVRF / CSAF / Update Guide RSS |
| KEV / scanners | CISA KEV, Nuclei templates, Metasploit CVE maps |
| Extra intel | CAPEC, Debian tracker, Ubuntu UCT / SOSS / VCF, OSV, GitHub Advisories, PoC-in-GitHub, 0xMarcio/cve |

Turn feeds on/off from **Manage → Live status**.

Edit URLs from **Settings → Sync source URLs**.

---

## Where URLs are stored

| Layer | Location |
|---|---|
| Built-in defaults | `app/config.py` constants → `DEFAULT_SETTINGS["urls"]` in `app/settings_store.py` |
| Runtime (UI) | `data/settings.json` → `"urls"` |

On first run, Settings is seeded so every sync URL field is pre-filled (except the optional licensed Nessus URL).

---

## CLI alternatives

```bash
python run.py ingest-all       # full ingest path
python run.py ingest-cve
python run.py ingest-edb
python run.py ingest-msrc
python run.py sync-cve         # CVE delta updates
python run.py export-nse       # rebuild offline NSE pack
python run.py clean-downloads  # clear downloads/ cache
```

---

## Tips

- First full sync is large and slow — normal for NVD + CVE List + EDB
- Use feed toggles if you only need a subset
- After Sync, export/download the NSE pack for offline Nmap use
