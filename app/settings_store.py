"""Persistent UI/settings overrides (proxy, sync URLs)."""

from __future__ import annotations

import json
import threading
from copy import deepcopy
from pathlib import Path
from typing import Any

from . import config

_LOCK = threading.RLock()
_CACHE: dict[str, Any] | None = None

SETTINGS_PATH = config.DATA_DIR / "settings.json"

DEFAULT_SETTINGS: dict[str, Any] = {
    "proxy": {
        "enabled": False,
        "type": "http",  # http | https | socks4 | socks5
        "host": "",
        "port": "",
        "url": "",  # optional full override (legacy / advanced)
        "username": "",
        "password": "",
    },
    "urls": {
        "cve_main_zip": config.CVE_MAIN_ZIP_URL,
        "cve_codeload_zip": config.CVE_CODELOAD_ZIP_URL,
        "cve_delta": config.CVE_DELTA_URL,
        "cve_delta_log": config.CVE_DELTA_LOG_URL,
        "cve_releases_api": config.CVE_RELEASES_API,
        "exploitdb_archive": config.EXPLOITDB_ARCHIVE_URLS[0],
        "exploitdb_csv": config.EXPLOITDB_CSV_URLS[0],
        "exploitdb_shellcodes_csv": config.EXPLOITDB_SHELLCODE_URLS[0],
        "exploitdb_papers_archive": config.EXPLOITDB_PAPERS_ARCHIVE_URLS[0],
        "exploitdb_papers_csv": config.EXPLOITDB_PAPERS_URLS[0],
        "nvd_feed_base": config.NVD_FEED_BASE,
        "cwe_xml_zip": config.CWE_XML_ZIP_URL,
        "cisa_kev_json": config.CISA_KEV_JSON_URL,
        "cisa_kev_csv": config.CISA_KEV_CSV_URL,
        "nuclei_templates_zip": config.NUCLEI_TEMPLATES_ZIP_URLS[0],
        "metasploit_zip": config.METASPLOIT_ZIP_URLS[0],
        "nessus_plugins_url": "",
        "nessus_plugins_path": str(config.NESSUS_PLUGINS_DEFAULT_PATH),
        "msrc_updates": config.MSRC_UPDATES_URL,
        "msrc_cvrf_base": config.MSRC_CVRF_BASE_URL,
        "msrc_csaf_base": config.MSRC_CSAF_BASE_URL,
        "msrc_rss": config.MSRC_RSS_URL,
        "msrc_swagger": config.MSRC_SWAGGER_URL,
        "epss_api": config.EPSS_API_URL,
        "poc_in_github_index": config.POC_IN_GITHUB_INDEX_URL,
        "capec_xml": config.CAPEC_XML_URL,
        "debian_tracker_json": config.DEBIAN_TRACKER_JSON_URL,
        "ubuntu_uct_zips": ",".join(config.UBUNTU_UCT_ZIP_URLS),
        "ubuntu_soss_zip": config.UBUNTU_SOSS_ZIP_URL,
        "ubuntu_vcf_zip": config.UBUNTU_VCF_ZIP_URL,
        "osv_ecosystem_zip": config.OSV_ECOSYSTEM_ZIP_TMPL,
        "osv_ecosystems": ",".join(config.OSV_ECOSYSTEMS),
        "github_advisory_database_zip": config.GITHUB_ADVISORY_DATABASE_ZIP_URL,
        "poc_github_zip": config.POC_GITHUB_ZIP_URL,
        "marcio_cve_github_index": config.MARCIO_CVE_GITHUB_INDEX_URL,
        "marcio_cve_zip": config.MARCIO_CVE_ZIP_URL,
    },
    # Per-feed Sync DB switches (Manage Live status toggles). Default: all on.
    "sync_feeds": {key: True for key in config.SYNC_FEED_KEYS},
    "schedule": {
        "enabled": False,
        "frequency": "daily",  # hourly | daily | weekly | monthly | yearly | once
        "start_at": "",
        "next_run_at": "",
        "last_run_at": "",
    },
}


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    out = deepcopy(base)
    for key, val in (overlay or {}).items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], val)
        else:
            out[key] = val
    return out


def _backfill_url_defaults(data: dict[str, Any]) -> dict[str, Any]:
    """Fill missing/blank sync URL fields from built-in defaults (keeps Settings pre-filled)."""
    default_urls = DEFAULT_SETTINGS.get("urls") or {}
    urls = data.get("urls")
    if not isinstance(urls, dict):
        data["urls"] = deepcopy(default_urls)
        return data
    for key, default_val in default_urls.items():
        if not str(urls.get(key) or "").strip():
            urls[key] = default_val
    data["urls"] = urls
    return data


def load_settings(*, force: bool = False) -> dict[str, Any]:
    global _CACHE
    with _LOCK:
        if _CACHE is not None and not force:
            return deepcopy(_CACHE)
        data = deepcopy(DEFAULT_SETTINGS)
        if SETTINGS_PATH.is_file():
            try:
                raw = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    data = _deep_merge(data, raw)
                    data.pop("api_keys", None)
            except (OSError, json.JSONDecodeError):
                pass
        data.pop("api_keys", None)
        data = _backfill_url_defaults(data)
        _CACHE = data
        return deepcopy(data)


def save_settings(payload: dict[str, Any]) -> dict[str, Any]:
    global _CACHE
    with _LOCK:
        current = load_settings(force=True)
        incoming = payload if isinstance(payload, dict) else {}
        # Validate feed URLs before merge (blocks file:// / javascript: SSRF vectors)
        if isinstance(incoming.get("urls"), dict):
            from .security import sanitize_settings_urls

            incoming = dict(incoming)
            incoming["urls"] = sanitize_settings_urls(incoming["urls"])
        merged = _deep_merge(current, incoming)
        # Drop legacy API-key block — feeds use public bulk mirrors only.
        merged.pop("api_keys", None)
        # Never persist empty nested dicts that wipe structure
        SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        SETTINGS_PATH.write_text(json.dumps(merged, indent=2, sort_keys=True), encoding="utf-8")
        _CACHE = merged
        # Reset HTTP session so proxy changes apply
        try:
            from . import httputil

            httputil.reset_session()
        except Exception:
            pass
        # Wake sync scheduler if schedule changed
        if isinstance(incoming, dict) and "schedule" in incoming:
            try:
                from .sync.scheduler import reload_schedule

                reload_schedule()
            except Exception:
                pass
        return deepcopy(merged)


def get_url(key: str, default: str = "") -> str:
    urls = load_settings().get("urls") or {}
    val = str(urls.get(key) or "").strip()
    return val or default


def default_sync_feeds() -> dict[str, bool]:
    return {key: True for key in config.SYNC_FEED_KEYS}


def get_sync_feeds(*, force: bool = False) -> dict[str, bool]:
    """Enabled flags for Sync DB steps (missing keys default to True)."""
    raw = load_settings(force=force).get("sync_feeds")
    out = default_sync_feeds()
    if isinstance(raw, dict):
        for key in config.SYNC_FEED_KEYS:
            if key in raw:
                # Accept bool / 0 / 1 / "true" / "false"
                val = raw[key]
                if isinstance(val, str):
                    out[key] = val.strip().lower() not in {"0", "false", "off", "no", ""}
                else:
                    out[key] = bool(val)
    return out


def is_feed_enabled(name: str) -> bool:
    """Return False when Live status Sync switch is Off (always re-read settings)."""
    name = (name or "").strip()
    if not name:
        return True
    return bool(get_sync_feeds(force=True).get(name, True))


def save_sync_feeds(payload: dict[str, Any]) -> dict[str, bool]:
    """Merge toggle updates; unknown keys ignored. Persists to settings.json."""
    current = get_sync_feeds(force=True)
    incoming = payload if isinstance(payload, dict) else {}
    for key in config.SYNC_FEED_KEYS:
        if key in incoming:
            val = incoming[key]
            if isinstance(val, str):
                current[key] = val.strip().lower() not in {"0", "false", "off", "no", ""}
            else:
                current[key] = bool(val)
    save_settings({"sync_feeds": current})
    # Re-read from disk so Sync workers see the same flags immediately.
    return get_sync_feeds(force=True)


def ensure_default_settings_persisted() -> dict[str, Any]:
    """On first run, write settings.json with official sync source URLs pre-filled.

    Also backfills any blank URL keys in an existing file so Settings always
    shows usable defaults without requiring a manual Save.
    """
    global _CACHE
    with _LOCK:
        created = not SETTINGS_PATH.is_file()
        data = load_settings(force=True)
        data = _backfill_url_defaults(data)
        if not isinstance(data.get("sync_feeds"), dict) or not data.get("sync_feeds"):
            data["sync_feeds"] = default_sync_feeds()
        SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        # Always persist on first run; otherwise rewrite when we filled blank URLs
        # or when the file was missing.
        if created:
            SETTINGS_PATH.write_text(
                json.dumps(data, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            _CACHE = data
            return deepcopy(data)
        # Re-read disk to see if blank URLs need a one-time backfill write
        try:
            raw = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = {}
        disk_urls = raw.get("urls") if isinstance(raw, dict) else None
        needs_write = False
        if not isinstance(disk_urls, dict):
            needs_write = True
        else:
            for key, default_val in (DEFAULT_SETTINGS.get("urls") or {}).items():
                if not str(disk_urls.get(key) or "").strip() and default_val:
                    needs_write = True
                    break
        if needs_write or "sync_feeds" not in (raw or {}):
            SETTINGS_PATH.write_text(
                json.dumps(data, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            _CACHE = data
        return deepcopy(data)


def ensure_sync_feeds_persisted() -> dict[str, bool]:
    """Write default sync_feeds into settings.json if the key was never saved."""
    ensure_default_settings_persisted()
    data = load_settings(force=True)
    if not isinstance(data.get("sync_feeds"), dict) or not data.get("sync_feeds"):
        feeds = default_sync_feeds()
        save_settings({"sync_feeds": feeds})
        return feeds
    return get_sync_feeds(force=True)


def _normalize_proxy_type(raw: str) -> str:
    t = (raw or "http").strip().lower().replace("_", "")
    aliases = {
        "http": "http",
        "https": "https",
        "socks4": "socks4",
        "socks": "socks5",
        "socks5": "socks5",
        "socks5h": "socks5h",
    }
    return aliases.get(t, "http")


def _build_proxy_url(proxy: dict[str, Any]) -> str | None:
    """Build a requests-compatible proxy URL from settings."""
    from urllib.parse import quote, urlparse

    # Full URL override wins when set
    override = str(proxy.get("url") or "").strip()
    ptype = _normalize_proxy_type(str(proxy.get("type") or "http"))
    host = str(proxy.get("host") or "").strip()
    port = str(proxy.get("port") or "").strip()
    user = str(proxy.get("username") or "").strip()
    password = str(proxy.get("password") or "")

    if override:
        # If override lacks a scheme, prefix with selected type
        if "://" not in override:
            override = f"{ptype}://{override}"
        parsed = urlparse(override)
        # When type is set and override scheme is generic http, prefer selected type
        # unless override already uses socks/https explicitly matching intent
        scheme = parsed.scheme.lower() if parsed.scheme else ptype
        if ptype in {"socks4", "socks5", "socks5h"} and scheme in {"http", "https", ""}:
            scheme = ptype
        elif ptype == "https" and scheme == "http" and not host:
            scheme = "https"
        netloc = parsed.netloc or parsed.path
        if not netloc:
            return None
        if user and "@" not in netloc:
            netloc = f"{quote(user, safe='')}:{quote(password, safe='')}@{netloc}"
        path = parsed.path if parsed.netloc else ""
        return f"{scheme}://{netloc}{path}"

    if not host:
        return None
    # Strip accidental scheme from host field
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/")[0].rstrip("/")
    if not port:
        port = {
            "http": "8080",
            "https": "8443",
            "socks4": "1080",
            "socks5": "1080",
            "socks5h": "1080",
        }.get(ptype, "8080")
    auth = ""
    if user:
        auth = f"{quote(user, safe='')}:{quote(password, safe='')}@"
    return f"{ptype}://{auth}{host}:{port}"


def proxy_dict() -> dict[str, str] | None:
    proxy = load_settings().get("proxy") or {}
    if not proxy.get("enabled"):
        return None
    url = _build_proxy_url(proxy)
    if not url:
        return None
    # Route both HTTP and HTTPS traffic through the configured proxy
    return {"http": url, "https": url}


def public_settings() -> dict[str, Any]:
    """Settings safe to return to the browser (proxy password masked)."""
    data = load_settings()
    out = deepcopy(data)
    out.pop("api_keys", None)
    proxy = dict(out.get("proxy") or {})
    if proxy.get("password"):
        proxy["password"] = ""
        proxy["password_set"] = True
    else:
        proxy["password_set"] = False
    out["proxy"] = proxy
    return out
