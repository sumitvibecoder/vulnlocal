"""Application configuration."""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BASE_DIR.parent

DATA_DIR = BASE_DIR / "data"
DOWNLOAD_DIR = BASE_DIR / "downloads"
PACKAGE_DIR = DATA_DIR / "packages"
BACKUP_DIR = DATA_DIR / "backups"
# NSE script + offline DB (inside the vulnlocal project)
# Layout: vulnlocal/nse/vulnlocal.nse  +  vulnlocal/nse/db/vulnlocal.pack/
# Pack is plain TSV buckets readable by Lua NSE with no external sqlite3 CLI.
NSE_ROOT = BASE_DIR / "nse"
NSE_DB_DIR = NSE_ROOT / "db"
NSE_SCRIPT = NSE_ROOT / "vulnlocal.nse"
NSE_PACK_PATH = NSE_DB_DIR / "vulnlocal.pack"
NSE_SQLITE_PATH = NSE_DB_DIR / "vulnlocal.db"  # legacy optional; NSE prefers .pack

# Prefer an already-extracted tree next to the project, else a download under data/
LOCAL_CVE_TREE = PROJECT_ROOT / "cvelistV5-main"
CVE_EXTRACT_DIR = DATA_DIR / "cvelistV5"

SQLITE_PATH = DATA_DIR / "vulnlocal.db"

# Official bulk mirrors ONLY — never scrape www.exploit-db.com HTML pages.
# Canonical project: https://gitlab.com/exploit-database/exploitdb
EXPLOITDB_REPO_URL = "https://gitlab.com/exploit-database/exploitdb"
EXPLOITDB_ARCHIVE_URLS = [
    "https://gitlab.com/exploit-database/exploitdb/-/archive/main/exploitdb-main.zip",
    "https://gitlab.com/exploit-database/exploitdb/-/archive/master/exploitdb-master.zip",
    "https://codeload.github.com/offensive-security/exploitdb/zip/refs/heads/master",
]
EXPLOITDB_CSV_URLS = [
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
    "https://gitlab.com/exploit-database/exploitdb/-/raw/master/files_exploits.csv",
    "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv",
]
EXPLOITDB_SHELLCODE_URLS = [
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_shellcodes.csv",
    "https://gitlab.com/exploit-database/exploitdb/-/raw/master/files_shellcodes.csv",
    "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_shellcodes.csv",
]
# Papers live in a separate official repo (moved out of the main SearchSploit tree).
EXPLOITDB_PAPERS_ARCHIVE_URLS = [
    "https://gitlab.com/exploit-database/exploitdb-papers/-/archive/main/exploitdb-papers-main.zip",
    "https://codeload.github.com/offensive-security/exploitdb-papers/zip/refs/heads/master",
]
EXPLOITDB_PAPERS_URLS = [
    "https://gitlab.com/exploit-database/exploitdb-papers/-/raw/main/files_papers.csv",
    "https://raw.githubusercontent.com/offensive-security/exploitdb-papers/master/files_papers.csv",
]

# CVE bulk sources (official CVEProject mirrors / releases — not website crawling)
CVE_MAIN_ZIP_URL = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"
CVE_CODELOAD_ZIP_URL = "https://codeload.github.com/CVEProject/cvelistV5/zip/refs/heads/main"
CVE_DELTA_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json"
CVE_DELTA_LOG_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
CVE_RELEASES_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"

# FIRST.org EPSS API (per-CVE lookup; {cve_id} placeholder)
EPSS_API_URL = "https://api.first.org/data/v1/epss?cve={cve_id}"

# PoC-in-GitHub index (official raw JSON; {year} and {cve_id} placeholders)
POC_IN_GITHUB_INDEX_URL = (
    "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve_id}.json"
)

CVE_SYNC_INTERVAL_MINUTES = int(os.environ.get("CVE_SYNC_INTERVAL_MINUTES", "60"))
EDB_SYNC_INTERVAL_HOURS = int(os.environ.get("EDB_SYNC_INTERVAL_HOURS", "24"))

# NVD JSON 2.0 traditional feeds (official bulk — https://nvd.nist.gov/vuln/data-feeds)
# Year zips nvdcve-2.0-YYYY.json.zip from 2002 … current year, plus modified + recent.
NVD_FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
NVD_FEED_DIR = DOWNLOAD_DIR / "nvd_feeds"
NVD_FEED_FIRST_YEAR = 2002
NVD_SYNC_INTERVAL_HOURS = int(os.environ.get("NVD_SYNC_INTERVAL_HOURS", "6"))

# Sync DB feed toggles (Manage → Live status). Keys match pipeline step names.
SYNC_FEED_KEYS: tuple[str, ...] = (
    "edb",
    "cve",
    "cwe",
    "cisa",
    "capec",
    "debian",
    "ghsa",
    "poc_github",
    "ubuntu",
    "osv",
    "nvd",
    "nuclei",
    "metasploit",
    "nessus",
    "msrc",
)

# MITRE CWE catalog (official download, not HTML scrape)
CWE_XML_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CWE_DIR = DOWNLOAD_DIR / "cwe"

# Tenable public JSON APIs (same endpoints the Tenable website UI uses — not HTML scraping)
# https://www.tenable.com/plugins  https://www.tenable.com/cve  https://www.tenable.com/attack-path-techniques
TENABLE_PLUGIN_SEARCH_URL = "https://www.tenable.com/plugins/api/v1/search"
TENABLE_PLUGIN_DETAIL_URL = "https://www.tenable.com/plugins/api/v1/{sensor}/{plugin_id}"
TENABLE_CVE_URL = "https://www.tenable.com/cve/api/v1/{cve_id}"
TENABLE_ATTACK_SEARCH_URL = "https://www.tenable.com/attack-path-techniques/api/v1/search"
TENABLE_DIR = DOWNLOAD_DIR / "tenable"
TENABLE_HTTP_TIMEOUT = int(os.environ.get("TENABLE_HTTP_TIMEOUT", "30"))
TENABLE_PLUGIN_LIMIT = int(os.environ.get("TENABLE_PLUGIN_LIMIT", "12"))

# CISA Known Exploited Vulnerabilities Catalog (official bulk JSON/CSV)
# https://www.cisa.gov/known-exploited-vulnerabilities-catalog
CISA_KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_CSV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
CISA_KEV_DIR = DOWNLOAD_DIR / "cisa_kev"

# ProjectDiscovery nuclei-templates (official GitHub archive — not HTML scrape)
# https://github.com/projectdiscovery/nuclei-templates
NUCLEI_TEMPLATES_ZIP_URLS = [
    "https://codeload.github.com/projectdiscovery/nuclei-templates/zip/refs/heads/main",
    "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip",
]
NUCLEI_DIR = DOWNLOAD_DIR / "nuclei_templates"
NUCLEI_DETAIL_BASE = "https://github.com/projectdiscovery/nuclei-templates/blob/main"

# Metasploit Framework modules (official GitHub archive — not HTML scrape)
# https://github.com/rapid7/metasploit-framework
METASPLOIT_ZIP_URLS = [
    "https://codeload.github.com/rapid7/metasploit-framework/zip/refs/heads/master",
    "https://github.com/rapid7/metasploit-framework/archive/refs/heads/master.zip",
]
METASPLOIT_DIR = DOWNLOAD_DIR / "metasploit"
METASPLOIT_DETAIL_BASE = "https://github.com/rapid7/metasploit-framework/blob/master"

# Nessus / Tenable offline plugin feed (all-2.0.tar.gz) — local path or licensed URL
NESSUS_PLUGINS_DIR = DOWNLOAD_DIR / "nessus_plugins"
NESSUS_PLUGINS_DEFAULT_PATH = PROJECT_ROOT / "all-2.0.tar.gz"
NESSUS_PLUGIN_DETAIL_BASE = "https://www.tenable.com/plugins/nessus"

# Microsoft Security Update Guide — official CVRF API (not HTML scrape)
# https://msrc.microsoft.com/update-guide
# https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API
MSRC_UPDATES_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
MSRC_CVRF_BASE_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf"
MSRC_CSAF_BASE_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/csaf"
MSRC_RSS_URL = "https://api.msrc.microsoft.com/update-guide/rss"
MSRC_SWAGGER_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/swagger/v3/swagger.json"
# First year with Security Update Guide CVRF monthly IDs (yyyy-Mmm)
MSRC_FIRST_YEAR = 2016
MSRC_DIR = DOWNLOAD_DIR / "msrc"

# CAPEC (MITRE) — official XML downloads (not HTML scrape)
# https://capec.mitre.org/data/downloads.html
CAPEC_XML_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"
CAPEC_DIR = DOWNLOAD_DIR / "capec"

# Debian Security Tracker — official JSON dump
# https://security-tracker.debian.org/tracker/
DEBIAN_TRACKER_JSON_URL = "https://security-tracker.debian.org/tracker/data/json"
DEBIAN_DIR = DOWNLOAD_DIR / "debian"

# Ubuntu CVE data — GitHub bulk zips (UCT mirrors + Canonical SOSS/VCF).
# https://github.com/kees/ubuntu-cve-tracker
# https://github.com/nottrobin/ubuntu-cve-tracker
# https://github.com/canonical/soss-vulnerability-data
# https://github.com/canonical/vcf-ubuntu-vulnerabilities
UBUNTU_UCT_ZIP_URLS = [
    "https://codeload.github.com/kees/ubuntu-cve-tracker/zip/refs/heads/master",
    "https://codeload.github.com/nottrobin/ubuntu-cve-tracker/zip/refs/heads/master",
]
UBUNTU_SOSS_ZIP_URL = (
    "https://codeload.github.com/canonical/soss-vulnerability-data/zip/refs/heads/main"
)
UBUNTU_VCF_ZIP_URL = (
    "https://codeload.github.com/canonical/vcf-ubuntu-vulnerabilities/zip/refs/heads/main"
)
UBUNTU_DIR = DOWNLOAD_DIR / "ubuntu"

# OSV.dev — official ecosystem zip mirrors (GCS)
# https://osv.dev/list · https://google.github.io/osv.dev/
OSV_ECOSYSTEMS_URL = "https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt"
OSV_ECOSYSTEM_ZIP_TMPL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
OSV_ECOSYSTEMS = ("Go", "crates.io", "Maven", "npm", "PyPI", "Debian", "Ubuntu")
OSV_DIR = DOWNLOAD_DIR / "osv"

# GitHub Advisory Database — official OSV JSON repo zip (GitHub-reviewed)
# https://github.com/advisories · https://github.com/github/advisory-database
GITHUB_ADVISORY_DATABASE_ZIP_URL = (
    "https://codeload.github.com/github/advisory-database/zip/refs/heads/main"
)
# Legacy REST endpoint (unused by ingest; kept for old settings migration)
GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"
GHSA_DIR = DOWNLOAD_DIR / "ghsa"

# PoC GitHub indexes — official GitHub archives / raw indexes
# https://github.com/nomi-sec/PoC-in-GitHub
# https://github.com/0xMarcio/cve
POC_GITHUB_ZIP_URL = "https://codeload.github.com/nomi-sec/PoC-in-GitHub/zip/refs/heads/master"
POC_GITHUB_DIR = DOWNLOAD_DIR / "poc_github"
MARCIO_CVE_GITHUB_INDEX_URL = (
    "https://raw.githubusercontent.com/0xMarcio/cve/main/github-all.txt"
)
MARCIO_CVE_ZIP_URL = "https://codeload.github.com/0xMarcio/cve/zip/refs/heads/main"
MARCIO_CVE_DIR = DOWNLOAD_DIR / "marcio_cve"

APP_VERSION = "1.0.0"
APP_NAME = "vulnlocal"

# Ingest / download tuning
HTTP_TIMEOUT = int(os.environ.get("VULNLOCAL_HTTP_TIMEOUT", "600"))
HTTP_CHUNK_SIZE = int(os.environ.get("VULNLOCAL_HTTP_CHUNK", str(1024 * 1024)))
CVE_PARSE_WORKERS = int(os.environ.get("VULNLOCAL_CVE_WORKERS", str(max(2, (os.cpu_count() or 2)))))
CVE_BATCH_SIZE = int(os.environ.get("VULNLOCAL_CVE_BATCH", "1500"))
DELTA_FETCH_WORKERS = int(os.environ.get("VULNLOCAL_DELTA_WORKERS", "4"))
DELTA_FETCH_PAUSE_MS = int(os.environ.get("VULNLOCAL_DELTA_PAUSE_MS", "50"))

# Browser-like identity for CDN/archive downloads (not a site crawler signature)
HTTP_USER_AGENT = os.environ.get(
    "VULNLOCAL_UA",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 vulnlocal-mirror/1.1",
)

# Flask requires SECRET_KEY; vulnlocal does not use auth/sessions — fixed local value.
SECRET_KEY = "vulnlocal-no-auth-local-only"


def ensure_dirs() -> None:
    for path in (
        DATA_DIR,
        DOWNLOAD_DIR,
        PACKAGE_DIR,
        BACKUP_DIR,
        NSE_DB_DIR,
        CVE_EXTRACT_DIR,
        NVD_FEED_DIR,
        CWE_DIR,
        TENABLE_DIR,
        CISA_KEV_DIR,
        NUCLEI_DIR,
        METASPLOIT_DIR,
        NESSUS_PLUGINS_DIR,
        MSRC_DIR,
        CAPEC_DIR,
        DEBIAN_DIR,
        UBUNTU_DIR,
        OSV_DIR,
        GHSA_DIR,
        POC_GITHUB_DIR,
        MARCIO_CVE_DIR,
    ):
        path.mkdir(parents=True, exist_ok=True)
