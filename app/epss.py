"""EPSS score lookup (FIRST.org) with local cache."""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from . import config

log = logging.getLogger("vulnlocal.epss")

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.I)
_EPSS_TIMEOUT = 6
_CACHE_TTL_SEC = 60 * 60 * 24 * 7  # 7 days


def _epss_url_template() -> str:
    from .settings_store import get_url

    return get_url("epss_api", config.EPSS_API_URL)


def _cache_path(cve_id: str) -> Path:
    year = cve_id.split("-")[1] if "-" in cve_id else "unknown"
    return config.DOWNLOAD_DIR / "epss_cache" / year / f"{cve_id}.json"


def fetch_epss(cve_id: str) -> dict[str, Any] | None:
    """
    Return EPSS score/percentile for a CVE when reachable; else cached/offline None.

    Shape: {score, percentile, date, source}
    """
    cve_id = (cve_id or "").strip().upper()
    if not _CVE_RE.match(cve_id):
        return None

    cache = _cache_path(cve_id)
    if cache.is_file():
        try:
            age = time.time() - cache.stat().st_mtime
            payload = json.loads(cache.read_text(encoding="utf-8"))
            if age < _CACHE_TTL_SEC and isinstance(payload, dict) and "score" in payload:
                return payload
        except (OSError, json.JSONDecodeError, TypeError):
            pass

    try:
        from .httputil import session

        resp = session().get(_epss_url_template().format(cve_id=cve_id), timeout=_EPSS_TIMEOUT)
        if resp.status_code != 200:
            return _stale_or_none(cache)
        data = resp.json()
        rows = data.get("data") or []
        if not rows:
            # Cache negative briefly via empty marker
            empty = {"score": None, "percentile": None, "date": "", "source": "first.org", "empty": True}
            _write_cache(cache, empty)
            return None
        row = rows[0]
        out = {
            "score": float(row["epss"]) if row.get("epss") is not None else None,
            "percentile": float(row["percentile"]) if row.get("percentile") is not None else None,
            "date": str(row.get("date") or ""),
            "source": "first.org",
            "empty": False,
        }
        _write_cache(cache, out)
        return out
    except Exception as exc:
        log.debug("EPSS lookup failed for %s: %s", cve_id, exc)
        return _stale_or_none(cache)


def _write_cache(path: Path, payload: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
    except OSError:
        pass


def _stale_or_none(cache: Path) -> dict[str, Any] | None:
    if not cache.is_file():
        return None
    try:
        payload = json.loads(cache.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and payload.get("empty"):
            return None
        if isinstance(payload, dict) and "score" in payload:
            return payload
    except (OSError, json.JSONDecodeError):
        pass
    return None
