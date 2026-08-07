# Security

vulnlocal is a **local** lab tool. Default bind is `127.0.0.1`. It is not hardened as multi-tenant internet-facing SaaS.

---

## Safe use

1. Keep the UI on loopback, or put VPN / auth in front if binding to a LAN.
2. Do not commit `data/`, `downloads/`, or `settings.json`.
3. Treat Settings sync URLs as trusted — the server fetches them (feed mirror design). Only `http` / `https` are accepted.
4. Use Nmap NSE only on **authorized** targets.
5. Use `--dev` only on loopback.

---

## Reporting issues

Open a GitHub issue with:

- Affected version / commit
- Steps to reproduce (authorized lab only)
- Impact (e.g. path traversal, SSRF via Settings URL, zip slip on restore)

Do **not** attach exploit payloads aimed at third-party systems.

Repo policy: [SECURITY.md](https://github.com/sumitvibecoder/vulnlocal/blob/main/SECURITY.md)

---

## Scope notes

- Exploit-DB / Metasploit / Nuclei data is for **correlation and research**, not remote exploitation
- Generated YARA / Sigma templates are starting points — tune before production detection
- No login secrets or API keys are required for public bulk feeds
