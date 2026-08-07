# Security Policy

## Supported use

vulnlocal is a **local** offline vulnerability intelligence mirror. Default bind is `127.0.0.1`. It is not hardened as a multi-tenant internet-facing SaaS.

## Reporting issues

If you find a vulnerability in vulnlocal itself, open a GitHub issue with:

- Affected version / commit
- Steps to reproduce (authorized lab only)
- Impact (e.g. path traversal, SSRF via Settings URL, zip slip on restore)

Please do **not** attach exploit payloads aimed at third-party systems.

## Hardening checklist

1. Keep the app on loopback, or put authentication / VPN in front if binding to LAN.
2. Do not commit `data/`, `downloads/`, or `settings.json`.
3. Treat Settings sync URLs as trusted — they can cause the server to fetch remote resources (SSRF by design for feed mirrors). Only `http`/`https` URLs are accepted.
4. Backup restore only accepts files under `data/backups/` with safe names, and zip members are checked against path traversal.
5. Cross-origin browser POSTs to Manage/Settings APIs are blocked (Origin/Referer check) to reduce localhost CSRF risk.
6. Use `--dev` / `VULNLOCAL_DEV=1` only on loopback. Debug mode is refused on non-loopback binds.

vulnlocal does **not** use login secrets or API keys — all feeds are public bulk archives.

## Development mode

```bash
python run.py --dev --host 127.0.0.1 --port 8088
# or: set VULNLOCAL_DEV=1
```

Enables Flask debug, template auto-reload, and (by default) the Werkzeug reloader. Scheduler threads start only in the reloader child process. Add `--no-reloader` for a single debug process.

## Scope notes

- Exploit-DB / Metasploit / Nuclei data is for **correlation and research**, not remote exploitation.
- Generated YARA/Sigma templates are starting points — tune before production detection.
