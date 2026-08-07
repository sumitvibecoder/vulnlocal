# FAQ

---

### Settings URLs are empty

Run the app once (`python run.py` or `python run.py init-db`). Defaults are written to `data/settings.json` and shown on the Settings page.

---

### Sync is very slow / downloads are huge

Expected for a full mirror (NVD, CVE List, Exploit-DB, etc.). Use **Manage** feed toggles to sync only what you need.

---

### What is the difference between `.db` and `.pack`?

| File / folder | Used for |
|---|---|
| `data/vulnlocal.db` | App SQLite (web UI) |
| `nse/db/vulnlocal.pack/` | Offline NSE index |

---

### Does offline NSE need `sqlite3.exe`?

**No.** Offline mode reads `vulnlocal.pack` directly from Lua.

---

### Why is the script-arg still called `vulnlocal.db`?

Legacy argument name. The **value** must be the pack **directory** path, not a `.db` file.

---

### Can I commit `data/vulnlocal.db` to GitHub?

**No.** It is typically multi‑GB. GitHub rejects files over 100 MB. Keep it local or share via Releases / other storage.

---

### Is vulnlocal an exploit framework?

**No.** It correlates advisories and research data only. It does not run exploits against targets.

---

### Which Python version?

Python **3.10** or newer.
