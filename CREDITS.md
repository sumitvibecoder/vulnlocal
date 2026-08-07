# Credits

vulnlocal is built on the work of many open projects, standards bodies, and vendors.
Thank you to everyone who publishes vulnerability intelligence for defenders.

## Core application stack

| Project | Use in vulnlocal |
|---|---|
| [Python](https://www.python.org/) | Runtime |
| [Flask](https://flask.palletsprojects.com/) | Local web UI and JSON APIs |
| [Werkzeug](https://werkzeug.palletsprojects.com/) | WSGI utilities (Flask dependency) |
| [Requests](https://requests.readthedocs.io/) | Polite HTTPS downloads of official feeds |
| [threading (stdlib)](https://docs.python.org/3/library/threading.html) | Background Sync DB scheduler |
| [SQLite](https://www.sqlite.org/) | Offline vulnerability database |
| [Nmap](https://nmap.org/) / NSE | Host service detection + offline correlation script |

## Vulnerability intelligence sources

| Source | Credit / link | How it is used |
|---|---|---|
| CVE Project — CVE List V5 | [cve.org](https://www.cve.org/) · [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) | Primary CVE records & delta sync |
| NIST NVD | [nvd.nist.gov](https://nvd.nist.gov/) JSON 2.0 feeds | CVSS / CPE enrichment |
| Exploit-DB / Offensive Security | [exploit-db.com](https://www.exploit-db.com/) · GitLab/GitHub archives | Exploit metadata index (no payload runner) |
| Microsoft MSRC | [Security Update Guide](https://msrc.microsoft.com/update-guide) · [MSRC-Microsoft-Security-Updates-API](https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API) | Patch Tuesday / KB remediations (CVRF API) |
| CISA Known Exploited Vulnerabilities | [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | KEV flags |
| FIRST.org EPSS | [first.org/epss](https://www.first.org/epss/) | Exploit prediction scores (when online) |
| MITRE CWE | [cwe.mitre.org](https://cwe.mitre.org/) | Weakness catalog |
| ProjectDiscovery Nuclei templates | [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | CVE/exploit templates only (mapped to CVE IDs) |
| Rapid7 Metasploit Framework | [metasploit-framework](https://github.com/rapid7/metasploit-framework) | Module ↔ CVE map |
| CAPEC (MITRE) | [capec.mitre.org](https://capec.mitre.org/data/downloads.html) | Attack patterns linked via CWE |
| Debian Security Tracker | [security-tracker.debian.org](https://security-tracker.debian.org/tracker/) | Distro package status JSON |
| Ubuntu Security | [ubuntu.com/security](https://ubuntu.com/security/vulnerabilities/view-all) | CVE JSON API |
| OSV.dev | [osv.dev](https://osv.dev/list) | Ecosystem vulnerability zips |
| GitHub Advisory Database | [github.com/advisories](https://github.com/advisories) · [github/advisory-database](https://github.com/github/advisory-database) | OSV JSON zip (all GitHub-reviewed, incl. withdrawn) |
| nomi-sec PoC-in-GitHub | [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) | Public PoC repository index |
| Tenable (optional) | [tenable.com/plugins](https://www.tenable.com/plugins) public JSON APIs | Plugin metadata when configured |
| Nessus plugins (optional, licensed) | Tenable `all-2.0.tar.gz` | Local NASL CVE xref ingest |

## Detection / hunting formats

| Format | Credit |
|---|---|
| YARA | [VirusTotal/yara](https://github.com/VirusTotal/yara) — template generation for blue-team hunting |
| Sigma | [SigmaHQ](https://github.com/SigmaHQ/sigma) — SIEM-oriented rule sketches |

## Typography / UI

| Asset | Credit |
|---|---|
| IBM Plex Sans / Mono | [IBM/plex](https://github.com/IBM/plex) via Google Fonts |

## Inspiration & related work

Offline CVE correlation and local mirrors have a long history in the Nmap and vulnerability-research communities (SearchSploit, vulscan-style workflows, and many NSE authors). vulnlocal is an original implementation focused on official bulk/JSON feeds, a slim offline NSE SQLite database, and a local correlator UI — not a fork of those projects.

## Disclaimer

Third-party data remains under each publisher’s license and terms. vulnlocal does not claim ownership of CVE text, Exploit-DB titles, Microsoft advisories, Nuclei templates, Metasploit modules, or Nessus plugins. Use only on systems you own or are authorized to assess.
