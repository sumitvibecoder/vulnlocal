# Changelog

## 1.0.0 — 2026-08-05

First public release of **vulnlocal**.

### Highlights
- Offline CVE List V5 + NVD JSON 2.0 + CWE mirror
- Exploit-DB indexes (exploits, shellcodes, papers) with app/article metadata
- Microsoft Security Update Guide offline ingest via official MSRC CVRF API
- Local plugin-archive metadata → CVE mapping (metadata only)
- CISA KEV, Nuclei templates, Metasploit module CVE maps
- Host scanning via **Nmap NSE** (service detection + offline/online correlation)
- Heuristic **YARA** (EDR) and **Sigma** (SIEM) detection templates on CVE pages
- Settings for proxy (HTTP/HTTPS/SOCKS4/SOCKS5) and all sync source URLs
- Docs pages: Manual, FAQ, About
- NSE package downloads from Manage

### Safety
- Official bulk/JSON APIs only (no HTML scraping of Exploit-DB / MSRC web UI)
- Use NSE only on systems you own or are authorized to assess
- Not an exploit runner
