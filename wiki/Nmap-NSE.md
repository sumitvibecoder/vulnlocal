# Nmap NSE

Script file in the repo: `nse/vulnlocal.nse`

---

## Install the script package

Copy into Nmap’s scripts folder as a `vulnlocal/` package:

| OS | Install path |
|---|---|
| Linux | `/usr/share/nmap/scripts/vulnlocal/` |
| Windows | `C:\Program Files (x86)\Nmap\scripts\vulnlocal\` |

Then refresh the script database:

```bash
nmap --script-updatedb
```

---

## Online mode (local API)

Start vulnlocal first, then:

```bash
nmap -sV --script vulnlocal/vulnlocal \
  --script-args vulnlocal.api=http://127.0.0.1:8088 <authorized-target>
```

HTTPS is supported:

```bash
nmap -sV --script vulnlocal/vulnlocal \
  --script-args vulnlocal.api=https://127.0.0.1:8088 <authorized-target>
```

---

## Offline mode (`vulnlocal.pack`)

1. Run **Manage → Sync DB**
2. Download the NSE **pack** from Manage (or run `python run.py export-nse`)
3. Point the script at the **pack directory**

```bash
nmap -sV --script vulnlocal/vulnlocal \
  --script-args "vulnlocal.db=/path/to/vulnlocal.pack" <authorized-target>
```

### Windows example

Use **forward slashes** and quotes:

```text
nmap -sV --script vulnlocal/vulnlocal --script-args "vulnlocal.db=D:/path/to/vulnlocal.pack" <authorized-target>
```

### Important

| Topic | Detail |
|---|---|
| Script-arg name | Still `vulnlocal.db=…` |
| Script-arg value | Must be the **`vulnlocal.pack` directory** (or its `META` file) |
| sqlite3 CLI | **Not required** for offline mode |
| Format | Plain TSV buckets readable from Lua |

---

## Authorized use only

Scan only hosts you own or have written permission to assess. vulnlocal is **not** an exploit runner.
