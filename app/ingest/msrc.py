"""Ingest Microsoft Security Update Guide data via the official MSRC CVRF API.

Source (web UI): https://msrc.microsoft.com/update-guide
API docs/samples: https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API
OpenAPI: https://api.msrc.microsoft.com/cvrf/v3.0/swagger/v3/swagger.json
CSAF docs (same bulletin IDs): https://msrc.microsoft.com/csaf · /cvrf/v3.0/csaf/{id}
Recent changes RSS: https://api.msrc.microsoft.com/update-guide/rss

Uses official JSON/XML feeds only — no HTML scraping of the Update Guide pages.
Primary offline mirror is CVRF JSON for every year (2016+) via /updates + /updates/{year}.
"""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import config
from ..db import db_session, log_job_finish, log_job_start, set_meta, utc_now
from ..httputil import http_get
from ..progress import JobCancelled, check_cancelled, set_progress
from ..settings_store import get_url

log = logging.getLogger("vulnlocal.msrc")

_KB_RE = re.compile(r"^(?:KB)?(\d{5,8})$", re.I)
_MONTHLY_ID_RE = re.compile(r"^(\d{4})-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$")
_MONTHLY_ID_FIND_RE = re.compile(r"\b(\d{4})-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b")
_MONTH_ORDER = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def _updates_url() -> str:
    return get_url("msrc_updates", config.MSRC_UPDATES_URL).rstrip("/")


def _cvrf_url(update_id: str) -> str:
    base = get_url("msrc_cvrf_base", config.MSRC_CVRF_BASE_URL).rstrip("/")
    return f"{base}/{update_id}"


def _text_val(obj: Any) -> str:
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj.strip()
    if isinstance(obj, dict):
        return str(obj.get("Value") or "").strip()
    return str(obj).strip()


def _as_list(val: Any) -> list[Any]:
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]


def _cve_ids(raw: Any) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in _as_list(raw):
        cve = str(item or "").strip().upper()
        if cve.startswith("CVE-") and cve not in seen:
            seen.add(cve)
            out.append(cve)
    return out


def _kb_support_url(kb: str) -> str:
    m = re.search(r"(\d{5,8})", kb or "")
    if m:
        return f"https://support.microsoft.com/help/{m.group(1)}"
    return ""


def _kb_catalog_url(kb: str) -> str:
    q = (kb or "security update").strip()
    return f"https://www.catalog.update.microsoft.com/Search.aspx?q={q}"


def _normalize_patch_url(kb: str, url: str = "") -> str:
    """Prefer vendor URL; otherwise Microsoft Support Help or Update Catalog."""
    u = (url or "").strip()
    if u.startswith("http://") or u.startswith("https://"):
        return u
    help_url = _kb_support_url(kb)
    if help_url:
        return help_url
    if kb:
        return _kb_catalog_url(kb)
    return ""


def _kb_from_remediation(item: dict[str, Any]) -> str:
    desc = _text_val(item.get("Description"))
    m = _KB_RE.match(desc.replace(" ", ""))
    if m:
        return f"KB{m.group(1)}"
    url = str(item.get("URL") or "")
    m2 = re.search(r"KB(\d{5,8})", url, re.I)
    if m2:
        return f"KB{m2.group(1)}"
    if desc.isdigit() and len(desc) >= 5:
        return f"KB{desc}"
    return desc[:80]


def _threat_value(vuln: dict[str, Any], threat_type: int) -> str:
    parts: list[str] = []
    for t in vuln.get("Threats") or []:
        if not isinstance(t, dict):
            continue
        if int(t.get("Type") or -1) != threat_type:
            continue
        val = _text_val(t.get("Description"))
        if val and val not in parts:
            parts.append(val)
    return ";".join(parts) if parts else ""


def _msrc_flag(exploit_status: str, key: str) -> str:
    """Parse Yes/No from strings like 'Publicly Disclosed:Yes;Exploited:No;...'."""
    text = str(exploit_status or "")
    m = re.search(rf"(?i){re.escape(key)}\s*:\s*(Yes|No)\b", text)
    if not m:
        return "—"
    return "Yes" if m.group(1).lower() == "yes" else "No"


def _csaf_url(update_id: str) -> str:
    """Alternate CSAF document URL for the same bulletin id (yyyy-Mmm)."""
    base = get_url("msrc_csaf_base", config.MSRC_CSAF_BASE_URL).rstrip("/")
    return f"{base}/{update_id}"


def _rss_url() -> str:
    return get_url("msrc_rss", config.MSRC_RSS_URL).rstrip("/")


def _normalize_update(item: dict[str, Any]) -> dict[str, Any] | None:
    update_id = str(item.get("ID") or item.get("id") or "").strip()
    if not update_id:
        return None
    return {
        "ID": update_id,
        "DocumentTitle": item.get("DocumentTitle") or item.get("Alias") or update_id,
        "InitialReleaseDate": item.get("InitialReleaseDate") or "",
        "CurrentReleaseDate": item.get("CurrentReleaseDate") or "",
        "CvrfUrl": item.get("CvrfUrl") or _cvrf_url(update_id),
    }


def _merge_updates(bucket: dict[str, dict[str, Any]], items: list[Any]) -> None:
    for item in items:
        if not isinstance(item, dict):
            continue
        norm = _normalize_update(item)
        if not norm:
            continue
        prev = bucket.get(norm["ID"])
        if not prev:
            bucket[norm["ID"]] = norm
            continue
        # Keep the newest CurrentReleaseDate
        if (norm.get("CurrentReleaseDate") or "") > (prev.get("CurrentReleaseDate") or ""):
            bucket[norm["ID"]] = norm


def _fetch_json_updates(url: str) -> list[Any]:
    resp = http_get(url, extra_headers={"Accept": "application/json"})
    if resp.status_code != 200:
        log.warning("MSRC index %s HTTP %s", url, resp.status_code)
        return []
    payload = resp.json()
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        value = payload.get("value")
        if isinstance(value, list):
            return value
        # Single update object keyed by year/CVE
        if payload.get("ID") or payload.get("id"):
            return [payload]
    return []


def _discover_update_index(*, deep: bool = False) -> list[dict[str, Any]]:
    """
    Build the Security Update Guide bulletin list.

    Incremental sync: one GET /updates (covers all years in the API index).
    Deep/full sync: also walk /updates/{year} for 2016..now (fills gaps).
    RSS is only consulted on deep sync (recent-change hints, not an archive).
    """
    bucket: dict[str, dict[str, Any]] = {}
    set_progress(phase="msrc", label="Fetching MSRC update index", detail=_updates_url())
    _merge_updates(bucket, _fetch_json_updates(_updates_url()))

    # Main /updates is usually complete; year walk only when empty/thin or deep=True
    need_years = deep or len(bucket) < 12
    if need_years:
        year_now = datetime.now(timezone.utc).year
        first_year = int(getattr(config, "MSRC_FIRST_YEAR", 2016) or 2016)
        for year in range(year_now, first_year - 1, -1):
            check_cancelled()
            set_progress(
                phase="msrc",
                label=f"MSRC year index {year}",
                detail=f"{_updates_url()}/{year}",
            )
            _merge_updates(bucket, _fetch_json_updates(f"{_updates_url()}/{year}"))
            time.sleep(0.05)

        try:
            set_progress(phase="msrc", label="MSRC RSS recent changes", detail=_rss_url())
            rss_resp = http_get(
                _rss_url(),
                extra_headers={"Accept": "application/rss+xml, application/xml, text/xml"},
            )
            if rss_resp.status_code == 200:
                text = rss_resp.text or ""
                for m in _MONTHLY_ID_FIND_RE.finditer(text):
                    uid = m.group(0)
                    if uid not in bucket:
                        bucket[uid] = {
                            "ID": uid,
                            "DocumentTitle": uid,
                            "InitialReleaseDate": "",
                            "CurrentReleaseDate": utc_now(),
                            "CvrfUrl": _cvrf_url(uid),
                        }
        except Exception as exc:  # noqa: BLE001
            log.warning("MSRC RSS probe failed: %s", exc)

    updates = list(bucket.values())
    updates.sort(
        key=lambda u: u.get("CurrentReleaseDate") or u.get("InitialReleaseDate") or u["ID"],
        reverse=True,
    )
    return updates


def _best_cvss(vuln: dict[str, Any]) -> tuple[float | None, str]:
    best_score: float | None = None
    best_vec = ""
    for row in vuln.get("CVSSScoreSets") or []:
        if not isinstance(row, dict):
            continue
        try:
            score = float(row.get("BaseScore"))
        except (TypeError, ValueError):
            continue
        if best_score is None or score > best_score:
            best_score = score
            best_vec = str(row.get("Vector") or "")
    return best_score, best_vec


def _product_map(doc: dict[str, Any]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    tree = doc.get("ProductTree") or {}
    for p in tree.get("FullProductName") or []:
        if not isinstance(p, dict):
            continue
        pid = str(p.get("ProductID") or "").strip()
        if not pid:
            continue
        out[pid] = {
            "name": str(p.get("Value") or "").strip(),
            "cpe": str(p.get("CPE") or "").strip(),
        }
    return out


def _parse_document(update_id: str, doc: dict[str, Any]) -> dict[str, Any]:
    products = _product_map(doc)
    tracking = doc.get("DocumentTracking") or {}
    title = _text_val(doc.get("DocumentTitle")) or update_id
    cve_rows: list[dict[str, Any]] = []
    rem_rows: list[dict[str, Any]] = []
    now = utc_now()

    for vuln in doc.get("Vulnerability") or []:
        if not isinstance(vuln, dict):
            continue
        cves = _cve_ids(vuln.get("CVE"))
        if not cves:
            continue
        title_v = _text_val(vuln.get("Title"))
        severity = _threat_value(vuln, 3)
        impact = _threat_value(vuln, 0)
        exploit_status = _threat_value(vuln, 1)
        cvss_score, cvss_vector = _best_cvss(vuln)
        for cve_id in cves:
            cve_rows.append(
                {
                    "cve_id": cve_id,
                    "update_id": update_id,
                    "title": title_v,
                    "severity": severity,
                    "impact": impact,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "exploit_status": exploit_status[:500],
                    "detail_url": f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}",
                    "updated_at": now,
                }
            )
            seen_rem: set[tuple[str, str]] = set()
            for rem in vuln.get("Remediations") or []:
                if not isinstance(rem, dict):
                    continue
                kb = _kb_from_remediation(rem)
                url = _normalize_patch_url(kb, str(rem.get("URL") or "").strip())
                key = (kb, url)
                if key in seen_rem:
                    continue
                seen_rem.add(key)
                pids = [str(x) for x in _as_list(rem.get("ProductID"))]
                names = [products[p]["name"] for p in pids if p in products and products[p]["name"]]
                rem_rows.append(
                    {
                        "cve_id": cve_id,
                        "update_id": update_id,
                        "kb": kb,
                        "url": url,
                        "subtype": str(rem.get("SubType") or ""),
                        "fixed_build": str(rem.get("FixedBuild") or ""),
                        "restart_required": _text_val(rem.get("RestartRequired")),
                        "product_names": "; ".join(names[:12]),
                    }
                )

    product_rows = [
        {
            "update_id": update_id,
            "product_id": pid,
            "name": meta["name"],
            "cpe": meta["cpe"],
        }
        for pid, meta in products.items()
    ]
    return {
        "title": title,
        "cves": cve_rows,
        "remediations": rem_rows,
        "products": product_rows,
    }


def _store_document(conn, update: dict[str, Any], parsed: dict[str, Any]) -> int:
    update_id = update["ID"]
    now = utc_now()
    conn.execute(
        """
        INSERT INTO msrc_updates(
            update_id, title, initial_release, current_release, cvrf_url,
            vuln_count, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(update_id) DO UPDATE SET
            title=excluded.title,
            initial_release=excluded.initial_release,
            current_release=excluded.current_release,
            cvrf_url=excluded.cvrf_url,
            vuln_count=excluded.vuln_count,
            updated_at=excluded.updated_at
        """,
        (
            update_id,
            parsed["title"],
            update.get("InitialReleaseDate") or "",
            update.get("CurrentReleaseDate") or "",
            update.get("CvrfUrl") or _cvrf_url(update_id),
            len(parsed["cves"]),
            now,
        ),
    )
    conn.execute("DELETE FROM msrc_products WHERE update_id = ?", (update_id,))
    conn.execute("DELETE FROM msrc_cves WHERE update_id = ?", (update_id,))
    conn.execute("DELETE FROM msrc_remediations WHERE update_id = ?", (update_id,))
    if parsed["products"]:
        conn.executemany(
            """
            INSERT OR REPLACE INTO msrc_products(update_id, product_id, name, cpe)
            VALUES (:update_id, :product_id, :name, :cpe)
            """,
            parsed["products"],
        )
    if parsed["cves"]:
        conn.executemany(
            """
            INSERT OR REPLACE INTO msrc_cves(
                cve_id, update_id, title, severity, impact, cvss_score, cvss_vector,
                exploit_status, detail_url, updated_at
            ) VALUES (
                :cve_id, :update_id, :title, :severity, :impact, :cvss_score, :cvss_vector,
                :exploit_status, :detail_url, :updated_at
            )
            """,
            parsed["cves"],
        )
    if parsed["remediations"]:
        conn.executemany(
            """
            INSERT INTO msrc_remediations(
                cve_id, update_id, kb, url, subtype, fixed_build, restart_required, product_names
            ) VALUES (
                :cve_id, :update_id, :kb, :url, :subtype, :fixed_build, :restart_required, :product_names
            )
            """,
            parsed["remediations"],
        )
    return len(parsed["cves"])


def _should_refresh(conn, update: dict[str, Any]) -> bool:
    update_id = update["ID"]
    row = conn.execute(
        "SELECT current_release FROM msrc_updates WHERE update_id = ?",
        (update_id,),
    ).fetchone()
    if not row:
        return True
    return (row["current_release"] or "") != (update.get("CurrentReleaseDate") or "")


def download_and_ingest(*, full: bool | None = None) -> dict[str, Any]:
    """
    Sync all MSRC Update Guide CVRF documents into SQLite for offline use.

    full=True forces re-download of every bulletin; otherwise skips unchanged
    CurrentReleaseDate values.
    """
    config.ensure_dirs()
    config.MSRC_DIR.mkdir(parents=True, exist_ok=True)
    with db_session() as conn:
        job_id = log_job_start(conn, "msrc_ingest")
        existing = conn.execute("SELECT COUNT(*) AS n FROM msrc_cves").fetchone()["n"]
    if full is None:
        full = existing == 0 or int(existing) < 5_000

    stats: dict[str, Any] = {
        "status": "ok",
        "updates": 0,
        "fetched": 0,
        "skipped": 0,
        "cves_upserted": 0,
        "full": bool(full),
        "deep_index": bool(full),
    }

    try:
        updates = _discover_update_index(deep=bool(full))
        stats["updates"] = len(updates)

        for idx, update in enumerate(updates, start=1):
            check_cancelled()
            if not isinstance(update, dict) or not update.get("ID"):
                continue
            update_id = str(update["ID"])
            set_progress(
                phase="msrc",
                label=f"MSRC {update_id}",
                current=idx,
                total=len(updates),
                unit="bulletins",
                detail=update.get("DocumentTitle") or update_id,
            )

            with db_session() as conn:
                need = full or _should_refresh(conn, update)
            if not need:
                stats["skipped"] += 1
                continue

            cache = config.MSRC_DIR / f"{update_id}.json"
            try:
                cvrf_resp = http_get(
                    _cvrf_url(update_id),
                    extra_headers={"Accept": "application/json"},
                )
                if cvrf_resp.status_code != 200:
                    log.warning("MSRC CVRF %s HTTP %s", update_id, cvrf_resp.status_code)
                    continue
                doc = cvrf_resp.json()
                cache.write_text(json.dumps(doc), encoding="utf-8")
            except Exception as exc:  # noqa: BLE001
                # Fall back to cached document when online fetch fails
                if cache.is_file():
                    log.warning("MSRC %s fetch failed (%s); using cache", update_id, exc)
                    doc = json.loads(cache.read_text(encoding="utf-8"))
                else:
                    log.warning("MSRC %s skipped: %s", update_id, exc)
                    continue

            parsed = _parse_document(update_id, doc)
            with db_session() as conn:
                n = _store_document(conn, update, parsed)
            stats["fetched"] += 1
            stats["cves_upserted"] += n
            # Only pace after a successful network fetch
            time.sleep(0.08)

        with db_session() as conn:
            set_meta(conn, "msrc_last_ingest", utc_now())
            count = conn.execute("SELECT COUNT(*) AS n FROM msrc_cves").fetchone()["n"]
            rem = conn.execute("SELECT COUNT(*) AS n FROM msrc_remediations").fetchone()["n"]
            stats["msrc_cves"] = count
            stats["msrc_remediations"] = rem
            log_job_finish(conn, job_id, "ok", json.dumps(stats)[:500])
        return stats
    except JobCancelled as exc:
        with db_session() as conn:
            log_job_finish(conn, job_id, "cancelled", str(exc))
        raise
    except Exception as exc:
        with db_session() as conn:
            log_job_finish(conn, job_id, "error", str(exc))
        raise


def get_msrc_for_cve(cve_id: str, *, limit: int = 40) -> dict[str, Any]:
    """Offline MSRC Update Guide rows for a CVE."""
    cve_id = (cve_id or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return {"cves": [], "remediations": [], "products": []}

    with db_session() as conn:
        rows = [
            dict(r)
            for r in conn.execute(
                """
                SELECT cve_id, update_id, title, severity, impact, cvss_score, cvss_vector,
                       exploit_status, detail_url
                FROM msrc_cves
                WHERE cve_id = ?
                ORDER BY update_id DESC
                LIMIT ?
                """,
                (cve_id, limit),
            ).fetchall()
        ]
        rems = [
            dict(r)
            for r in conn.execute(
                """
                SELECT cve_id, update_id, kb, url, subtype, fixed_build, restart_required, product_names
                FROM msrc_remediations
                WHERE cve_id = ?
                ORDER BY update_id DESC, kb
                LIMIT ?
                """,
                (cve_id, limit * 3),
            ).fetchall()
        ]
    # Dedupe remediations by KB/URL and ensure clickable Microsoft patch links
    seen: set[str] = set()
    rem_out: list[dict[str, Any]] = []
    for rem in rems:
        kb = rem.get("kb") or ""
        url = _normalize_patch_url(kb, rem.get("url") or "")
        rem["url"] = url
        rem["support_url"] = _kb_support_url(kb)
        rem["catalog_url"] = _kb_catalog_url(kb) if kb else ""
        key = f"{kb.lower()}|{url.lower()}"
        if key in seen:
            continue
        seen.add(key)
        rem_out.append(rem)
    return {
        "entries": rows,
        "remediations": rem_out[:limit],
        "detail_url": f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}",
    }


def _is_monthly_bulletin(update_id: str) -> bool:
    return bool(_MONTHLY_ID_RE.match(str(update_id or "").strip()))


def _bulletin_sort_key(update_id: str, initial_release: str = "") -> tuple:
    m = _MONTHLY_ID_RE.match(str(update_id or "").strip())
    if m:
        return (int(m.group(1)), _MONTH_ORDER[m.group(2)], initial_release or "")
    return (0, 0, initial_release or update_id or "")


_PATCH_TUESDAY_CACHE: dict[str, Any] = {"ts": 0.0, "limit": 0, "payload": None}
_PATCH_TUESDAY_TTL_SEC = 120.0


def invalidate_patch_tuesday_cache() -> None:
    _PATCH_TUESDAY_CACHE["payload"] = None
    _PATCH_TUESDAY_CACHE["ts"] = 0.0


def latest_patch_tuesday(*, limit: int = 15) -> dict[str, Any]:
    """
    CVEs from the newest monthly Patch Tuesday bulletin (update_id like 2025-Jun).

    Sourced from offline MSRC CVRF ingest — same data as
    https://msrc.microsoft.com/update-guide (not HTML scrape).
    """
    limit = max(1, min(int(limit or 15), 80))
    now = time.monotonic()
    cached = _PATCH_TUESDAY_CACHE.get("payload")
    if (
        cached is not None
        and int(_PATCH_TUESDAY_CACHE.get("limit") or 0) == limit
        and (now - float(_PATCH_TUESDAY_CACHE.get("ts") or 0.0)) < _PATCH_TUESDAY_TTL_SEC
    ):
        return cached

    with db_session() as conn:
        bulletins = [
            dict(r)
            for r in conn.execute(
                """
                SELECT update_id, title, initial_release, current_release, vuln_count, cvrf_url
                FROM msrc_updates
                """
            ).fetchall()
        ]
        monthly = [b for b in bulletins if _is_monthly_bulletin(b.get("update_id") or "")]
        if not monthly:
            return {
                "bulletin": None,
                "cves": [],
                "guide_url": "https://msrc.microsoft.com/update-guide/vulnerability",
            }
        monthly.sort(
            key=lambda b: _bulletin_sort_key(b.get("update_id") or "", b.get("initial_release") or ""),
            reverse=True,
        )
        bulletin = monthly[0]
        update_id = bulletin["update_id"]
        cves = [
            dict(r)
            for r in conn.execute(
                """
                SELECT
                    c.cve_id,
                    c.title,
                    c.severity,
                    c.impact,
                    c.cvss_score,
                    c.exploit_status,
                    c.detail_url
                FROM msrc_cves c
                WHERE c.update_id = ?
                ORDER BY
                    CASE lower(COALESCE(c.severity, ''))
                        WHEN 'critical' THEN 0
                        WHEN 'important' THEN 1
                        WHEN 'moderate' THEN 2
                        WHEN 'low' THEN 3
                        ELSE 4
                    END,
                    CASE
                        WHEN instr(lower(COALESCE(c.exploit_status,'')), 'exploited:yes') > 0 THEN 0
                        WHEN instr(lower(COALESCE(c.exploit_status,'')), 'publicly disclosed:yes') > 0 THEN 1
                        ELSE 2
                    END,
                    COALESCE(c.cvss_score, 0) DESC,
                    c.cve_id DESC
                LIMIT ?
                """,
                (update_id, limit),
            ).fetchall()
        ]
        rem_by_cve: dict[str, list[dict[str, str]]] = {}
        if cves:
            placeholders = ",".join("?" * len(cves))
            rem_rows = conn.execute(
                f"""
                SELECT cve_id, kb, url
                FROM msrc_remediations
                WHERE update_id = ?
                  AND cve_id IN ({placeholders})
                ORDER BY kb
                """,
                (update_id, *[c["cve_id"] for c in cves]),
            ).fetchall()
            for r in rem_rows:
                cid = r["cve_id"]
                kb = (r["kb"] or "").strip()
                if not kb:
                    continue
                url = _normalize_patch_url(kb, r["url"] or "")
                bucket = rem_by_cve.setdefault(cid, [])
                if any(x["kb"] == kb for x in bucket):
                    continue
                if len(bucket) >= 4:
                    continue
                bucket.append({"kb": kb, "url": url, "support_url": _kb_support_url(kb)})
        for row in cves:
            status = row.get("exploit_status") or ""
            row["publicly_disclosed"] = _msrc_flag(status, "Publicly Disclosed")
            row["exploited"] = _msrc_flag(status, "Exploited")
            patches = rem_by_cve.get(row["cve_id"]) or []
            row["kb_patches"] = patches
            row["kbs"] = ", ".join(p["kb"] for p in patches) if patches else ""
        sev_rows = conn.execute(
            """
            SELECT lower(COALESCE(severity, '')) AS sev, COUNT(*) AS n
            FROM msrc_cves
            WHERE update_id = ?
            GROUP BY lower(COALESCE(severity, ''))
            """,
            (update_id,),
        ).fetchall()
    sev_counts = {str(r["sev"] or ""): int(r["n"] or 0) for r in sev_rows}
    payload = {
        "bulletin": {
            "update_id": update_id,
            "title": bulletin.get("title") or update_id,
            "initial_release": (bulletin.get("initial_release") or "")[:10],
            "current_release": (bulletin.get("current_release") or "")[:10],
            "vuln_count": int(bulletin.get("vuln_count") or len(cves)),
            "cvrf_url": bulletin.get("cvrf_url") or _cvrf_url(update_id),
            "csaf_url": _csaf_url(update_id),
            "guide_url": f"https://msrc.microsoft.com/update-guide/release/{update_id}",
            "critical": sev_counts.get("critical", 0),
            "important": sev_counts.get("important", 0),
            "moderate": sev_counts.get("moderate", 0),
            "low": sev_counts.get("low", 0),
        },
        "cves": cves,
        "guide_url": "https://msrc.microsoft.com/update-guide/vulnerability",
    }
    _PATCH_TUESDAY_CACHE["payload"] = payload
    _PATCH_TUESDAY_CACHE["limit"] = limit
    _PATCH_TUESDAY_CACHE["ts"] = now
    return payload
