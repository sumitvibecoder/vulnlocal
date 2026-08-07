"""Ingest NVD JSON 2.0 feeds (official NIST data feeds — no HTML scraping).

Feeds: https://nvd.nist.gov/vuln/data-feeds#divJson20Feeds
  - Year zips: nvdcve-2.0-YYYY.json.zip (one-time / rare full sync)
  - modified + recent zips for incremental updates (~every 2 hours on NVD side)
"""

from __future__ import annotations

import json
import logging
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import config
from ..db import (
    db_session,
    get_meta,
    invalidate_nvd_product_counts,
    log_job_finish,
    log_job_start,
    refresh_overview,
    set_meta,
    utc_now,
)
from ..httputil import download_file, http_get
from ..progress import JobCancelled, check_cancelled, set_progress
from ..settings_store import get_url

log = logging.getLogger("vulnlocal.nvd")


def _year_feed_ids() -> list[str]:
    """Official NVD JSON 2.0 year feeds from FIRST_YEAR … current UTC year (incl. 2026+)."""
    year = datetime.now(timezone.utc).year
    first = int(getattr(config, "NVD_FEED_FIRST_YEAR", 2002) or 2002)
    return [str(y) for y in range(first, year + 1)]


def _feed_ids(*, full: bool) -> list[str]:
    """
    Feed id list for https://nvd.nist.gov/vuln/data-feeds#divJson20Feeds

    full → every year zip + modified + recent
    incremental → years not yet marked complete + modified + recent
    """
    years = _year_feed_ids()
    if full:
        return years + ["modified", "recent"]

    missing: list[str] = []
    with db_session() as conn:
        for y in years:
            if not get_meta(conn, f"nvd_feed_ok_{y}"):
                missing.append(y)
    # Always refresh churn feeds; backfill any year never successfully ingested.
    return missing + ["modified", "recent"]


def _bootstrap_year_metas_if_healthy(conn, existing: int) -> None:
    """
    On upgrade: mark years that already have a stored META sha as complete so we
    do not re-download every year. Years never synced (e.g. new 2026 zip) stay
    missing and are pulled on the next incremental Sync.
    """
    if int(existing) < 100_000:
        return
    if get_meta(conn, "nvd_years_bootstrapped"):
        return
    now = utc_now()
    for y in _year_feed_ids():
        if get_meta(conn, f"nvd_meta_sha_{y}"):
            set_meta(conn, f"nvd_feed_ok_{y}", now)
    set_meta(conn, "nvd_years_bootstrapped", now)


def _nvd_base() -> str:
    return get_url("nvd_feed_base", config.NVD_FEED_BASE).rstrip("/")


def _meta_url(feed_id: str) -> str:
    return f"{_nvd_base()}/nvdcve-2.0-{feed_id}.meta"


def _zip_url(feed_id: str) -> str:
    return f"{_nvd_base()}/nvdcve-2.0-{feed_id}.json.zip"


def _parse_meta(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def _fetch_meta(feed_id: str) -> dict[str, str] | None:
    try:
        resp = http_get(_meta_url(feed_id))
        if resp.status_code != 200:
            log.warning("NVD META %s HTTP %s", feed_id, resp.status_code)
            return None
        return _parse_meta(resp.text)
    except Exception as exc:
        log.warning("NVD META fetch failed for %s: %s", feed_id, exc)
        return None


def _pick_metric(cve: dict[str, Any]) -> dict[str, Any]:
    """Prefer CVSS v3.1 → v3.0 → v2 → v4."""
    metrics = cve.get("metrics") or {}
    for key, version in (
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
        ("cvssMetricV40", "4.0"),
    ):
        rows = metrics.get(key) or []
        if not rows or not isinstance(rows, list):
            continue
        # Prefer Primary / NVD
        chosen = rows[0]
        for r in rows:
            if not isinstance(r, dict):
                continue
            src = str(r.get("source") or "").lower()
            typ = str(r.get("type") or "").lower()
            if "nvd" in src or typ == "primary":
                chosen = r
                break
        data = (chosen.get("cvssData") or {}) if isinstance(chosen, dict) else {}
        score = data.get("baseScore")
        vector = data.get("vectorString") or ""
        severity = data.get("baseSeverity") or chosen.get("baseSeverity") or ""
        if score is None and chosen.get("cvssData"):
            continue
        return {
            "version": version,
            "score": float(score) if score is not None else None,
            "vector": str(vector),
            "severity": str(severity).upper() if severity else "",
        }
    return {"version": "", "score": None, "vector": "", "severity": ""}


def _english_description(cve: dict[str, Any]) -> str:
    for d in cve.get("descriptions") or []:
        if isinstance(d, dict) and str(d.get("lang") or "").lower() == "en":
            return str(d.get("value") or "").strip()
    for d in cve.get("descriptions") or []:
        if isinstance(d, dict) and d.get("value"):
            return str(d.get("value")).strip()
    return ""


def _cwe_ids(cve: dict[str, Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for block in cve.get("weaknesses") or []:
        if not isinstance(block, dict):
            continue
        for d in block.get("description") or []:
            if not isinstance(d, dict):
                continue
            val = str(d.get("value") or "").strip().upper()
            if not val.startswith("CWE-"):
                continue
            if val in seen:
                continue
            seen.add(val)
            out.append(val)
    return out


def _cpe_list(cve: dict[str, Any], *, limit: int = 40) -> list[str]:
    """Backward-compatible URI list (unique criteria strings). """
    out: list[str] = []
    for m in _cpe_matches(cve, limit=limit * 2):
        c = str(m.get("cpe") or "")
        if c and c not in out:
            out.append(c)
        if len(out) >= limit:
            break
    return out


def _soft_from_cpe(cpe: str) -> str:
    raw = (cpe or "").strip().lower().replace("cpe:/", "cpe:2.3:")
    parts = raw.split(":")
    if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
        return f"cpe:2.3:{parts[2]}:{parts[3]}:{parts[4]}"
    m = re.match(r"^(cpe:2\.3:[aho]:[^:]+:[^:]+)", raw)
    return m.group(1) if m else raw


def _cpe_matches(cve: dict[str, Any], *, limit: int = 120) -> list[dict[str, Any]]:
    """
    Extract NVD configuration cpeMatch rows including version range bounds.

    Each item:
      cpe, soft, version, update, ver_start_incl/excl, ver_end_incl/excl, vulnerable
    """
    out: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()

    def walk(node: Any) -> None:
        if len(out) >= limit:
            return
        if isinstance(node, dict):
            matches = node.get("cpeMatch")
            if isinstance(matches, list):
                for cm in matches:
                    if not isinstance(cm, dict):
                        continue
                    criteria = cm.get("criteria") or cm.get("cpe23Uri") or ""
                    criteria = str(criteria).strip()
                    if not criteria.startswith("cpe:"):
                        continue
                    soft = _soft_from_cpe(criteria)
                    parts = criteria.lower().replace("cpe:/", "cpe:2.3:").split(":")
                    version = parts[5] if len(parts) > 5 else ""
                    update = parts[6] if len(parts) > 6 else ""
                    row = {
                        "cpe": criteria,
                        "soft": soft,
                        "version": version,
                        "update": update,
                        "ver_start_incl": str(cm.get("versionStartIncluding") or ""),
                        "ver_start_excl": str(cm.get("versionStartExcluding") or ""),
                        "ver_end_incl": str(cm.get("versionEndIncluding") or ""),
                        "ver_end_excl": str(cm.get("versionEndExcluding") or ""),
                        "vulnerable": 1 if cm.get("vulnerable", True) else 0,
                    }
                    key = (
                        row["cpe"].lower(),
                        row["ver_start_incl"],
                        row["ver_start_excl"],
                        row["ver_end_incl"],
                        row["ver_end_excl"],
                        row["vulnerable"],
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(row)
                    if len(out) >= limit:
                        return
            # Also collect bare criteria nodes (rare) without ranges.
            criteria = node.get("criteria") or node.get("cpe23Uri")
            if criteria and str(criteria).startswith("cpe:") and "cpeMatch" not in node:
                c = str(criteria).strip()
                soft = _soft_from_cpe(c)
                parts = c.lower().replace("cpe:/", "cpe:2.3:").split(":")
                version = parts[5] if len(parts) > 5 else ""
                update = parts[6] if len(parts) > 6 else ""
                key = (c.lower(), "", "", "", "", 1)
                if key not in seen:
                    seen.add(key)
                    out.append(
                        {
                            "cpe": c,
                            "soft": soft,
                            "version": version,
                            "update": update,
                            "ver_start_incl": "",
                            "ver_start_excl": "",
                            "ver_end_incl": "",
                            "ver_end_excl": "",
                            "vulnerable": 1,
                        }
                    )
            for key in ("nodes", "children"):
                val = node.get(key)
                if isinstance(val, list):
                    for child in val:
                        walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(cve.get("configurations") or [])
    return out


def _refs(cve: dict[str, Any], *, limit: int = 30) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ref in cve.get("references") or []:
        if not isinstance(ref, dict):
            continue
        url = str(ref.get("url") or "").strip()
        if not url or url.lower() in seen:
            continue
        seen.add(url.lower())
        out.append({"url": url, "tags": list(ref.get("tags") or [])[:8]})
        if len(out) >= limit:
            break
    return out


def _row_from_vuln(item: dict[str, Any]) -> dict[str, Any] | None:
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict):
        return None
    cve_id = str(cve.get("id") or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return None
    metric = _pick_metric(cve)
    matches = _cpe_matches(cve)
    return {
        "cve_id": cve_id,
        "vuln_status": str(cve.get("vulnStatus") or ""),
        "source_id": str(cve.get("sourceIdentifier") or ""),
        "published": str(cve.get("published") or ""),
        "last_modified": str(cve.get("lastModified") or ""),
        "description": _english_description(cve),
        "cvss_version": metric["version"],
        "cvss_score": metric["score"],
        "cvss_vector": metric["vector"],
        "severity": metric["severity"],
        "cwe_ids": json.dumps(_cwe_ids(cve)),
        "cpes_json": json.dumps([m["cpe"] for m in matches]),
        "cpe_matches_json": json.dumps(matches),
        "references_json": json.dumps(_refs(cve)),
        "metrics_json": json.dumps(metric),
        "updated_at": utc_now(),
    }


def _upsert_rows(rows: list[dict[str, Any]]) -> int:
    if not rows:
        return 0
    with db_session() as conn:
        conn.executemany(
            """
            INSERT INTO nvd_cves(
                cve_id, vuln_status, source_id, published, last_modified, description,
                cvss_version, cvss_score, cvss_vector, severity,
                cwe_ids, cpes_json, cpe_matches_json, references_json, metrics_json, updated_at
            ) VALUES (
                :cve_id, :vuln_status, :source_id, :published, :last_modified, :description,
                :cvss_version, :cvss_score, :cvss_vector, :severity,
                :cwe_ids, :cpes_json, :cpe_matches_json, :references_json, :metrics_json, :updated_at
            )
            ON CONFLICT(cve_id) DO UPDATE SET
                vuln_status=excluded.vuln_status,
                source_id=excluded.source_id,
                published=excluded.published,
                last_modified=excluded.last_modified,
                description=excluded.description,
                cvss_version=excluded.cvss_version,
                cvss_score=excluded.cvss_score,
                cvss_vector=excluded.cvss_vector,
                severity=excluded.severity,
                cwe_ids=excluded.cwe_ids,
                cpes_json=excluded.cpes_json,
                cpe_matches_json=excluded.cpe_matches_json,
                references_json=excluded.references_json,
                metrics_json=excluded.metrics_json,
                updated_at=excluded.updated_at
            """,
            rows,
        )
    return len(rows)


def mirror_to_cves(*, also_products: bool = False) -> dict[str, Any]:
    """
    Copy NVD rows into the Manage “CVEs” table (`cves`) via upsert.

    Uses PRIMARY KEY cve_id — re-running never creates duplicates.
    """
    set_progress(phase="cve_nvd_mirror", label="Merging NVD into CVEs", detail="upsert by cve_id")
    # Inline timestamp — SQLite rejects bound "?" placeholders inside INSERT…SELECT…ON CONFLICT.
    now = utc_now().replace("'", "")
    with db_session() as conn:
        before = int(conn.execute("SELECT COUNT(*) AS n FROM cves").fetchone()["n"])
        conn.execute(
            f"""
            INSERT INTO cves(
                cve_id, state, description, date_published, date_updated,
                cvss_score, cvss_vector, severity, assigner, source_path, updated_at
            )
            SELECT
                n.cve_id,
                COALESCE(NULLIF(n.vuln_status, ''), 'PUBLISHED'),
                n.description,
                n.published,
                n.last_modified,
                n.cvss_score,
                n.cvss_vector,
                n.severity,
                n.source_id,
                'nvd:' || n.cve_id,
                COALESCE(NULLIF(n.updated_at, ''), '{now}')
            FROM nvd_cves AS n
            WHERE n.cve_id IS NOT NULL AND n.cve_id != ''
            ON CONFLICT(cve_id) DO UPDATE SET
                state=COALESCE(NULLIF(excluded.state, ''), cves.state),
                description=CASE
                    WHEN length(COALESCE(excluded.description, '')) >
                         length(COALESCE(cves.description, ''))
                    THEN excluded.description ELSE cves.description END,
                date_published=COALESCE(NULLIF(excluded.date_published, ''), cves.date_published),
                date_updated=CASE
                    WHEN COALESCE(excluded.date_updated, '') > COALESCE(cves.date_updated, '')
                    THEN excluded.date_updated ELSE cves.date_updated END,
                cvss_score=COALESCE(excluded.cvss_score, cves.cvss_score),
                cvss_vector=COALESCE(NULLIF(excluded.cvss_vector, ''), cves.cvss_vector),
                severity=COALESCE(NULLIF(excluded.severity, ''), cves.severity),
                assigner=COALESCE(NULLIF(excluded.assigner, ''), cves.assigner),
                source_path=CASE
                    WHEN cves.source_path LIKE 'nvd:%' OR cves.source_path IS NULL OR cves.source_path = ''
                    THEN excluded.source_path ELSE cves.source_path END,
                updated_at=excluded.updated_at
            """
        )
        after = int(conn.execute("SELECT COUNT(*) AS n FROM cves").fetchone()["n"])
        products_added = 0
        if also_products:
            # Seed sparse cve_products from NVD CPE product tokens when CVE List products are thin.
            prod_n = int(
                conn.execute(
                    "SELECT COUNT(*) AS n FROM cve_products"
                ).fetchone()["n"]
            )
            if prod_n < 10_000:
                rows = conn.execute(
                    """
                    SELECT cve_id, cpes_json FROM nvd_cves
                    WHERE cpes_json IS NOT NULL AND length(cpes_json) > 4
                    """
                ).fetchall()
                batch: list[tuple[str, str, str, str, str]] = []
                for r in rows:
                    try:
                        arr = json.loads(r["cpes_json"] or "[]")
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(arr, list):
                        continue
                    seen_local: set[tuple[str, str]] = set()
                    for cpe in arr[:12]:
                        parts = str(cpe).split(":")
                        if len(parts) < 5:
                            continue
                        vendor = parts[3] if parts[3] != "*" else ""
                        product = parts[4] if parts[4] != "*" else ""
                        version = parts[5] if len(parts) > 5 and parts[5] not in {"*", "-"} else ""
                        if not product:
                            continue
                        key = (vendor.lower(), product.lower())
                        if key in seen_local:
                            continue
                        seen_local.add(key)
                        batch.append((r["cve_id"], vendor, product, version, ""))
                    if len(batch) >= 2000:
                        conn.executemany(
                            """
                            INSERT INTO cve_products(cve_id, vendor, product, version, status)
                            SELECT ?, ?, ?, ?, ?
                            WHERE NOT EXISTS (
                              SELECT 1 FROM cve_products p
                              WHERE p.cve_id = ? AND lower(p.product) = lower(?)
                                AND lower(COALESCE(p.vendor,'')) = lower(?)
                            )
                            """,
                            [
                                (cid, v, p, ver, st, cid, p, v)
                                for cid, v, p, ver, st in batch
                            ],
                        )
                        products_added += len(batch)
                        batch.clear()
                if batch:
                    conn.executemany(
                        """
                        INSERT INTO cve_products(cve_id, vendor, product, version, status)
                        SELECT ?, ?, ?, ?, ?
                        WHERE NOT EXISTS (
                          SELECT 1 FROM cve_products p
                          WHERE p.cve_id = ? AND lower(p.product) = lower(?)
                            AND lower(COALESCE(p.vendor,'')) = lower(?)
                        )
                        """,
                        [(cid, v, p, ver, st, cid, p, v) for cid, v, p, ver, st in batch],
                    )
                    products_added += len(batch)
        set_meta(conn, "cves_nvd_mirror_at", utc_now())
    return {
        "cves_before": before,
        "cves_after": after,
        "cves_added": max(0, after - before),
        "products_touched": products_added,
    }


def expand_nvd_cpes_into_lookup_tables(
    *,
    force: bool = False,
    min_cpes: int = 50_000,
    min_matches: int = 10_000,
) -> dict[str, Any]:
    """
    Expand nvd_cves into cve_cpes + cve_products + cve_cpe_matches.

    cve_cpe_matches carries NVD versionStart/End bounds for Vulners-like matching.
    """
    wild = {"", "*", "-", "n/a", "na", "any", "unspecified", "unknown"}
    set_progress(
        phase="nvd_cpe_expand",
        label="Expanding NVD CPEs",
        detail="cve_cpes + products + ranges",
    )
    with db_session() as conn:
        # Ensure schema exists on older DBs.
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cve_cpe_matches (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id          TEXT NOT NULL,
                cpe             TEXT NOT NULL,
                soft            TEXT,
                version         TEXT,
                update_token    TEXT,
                ver_start_incl  TEXT,
                ver_start_excl  TEXT,
                ver_end_incl    TEXT,
                ver_end_excl    TEXT,
                vulnerable      INTEGER DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_cve_cpe_matches_soft ON cve_cpe_matches(soft);
            CREATE INDEX IF NOT EXISTS idx_cve_cpe_matches_cve ON cve_cpe_matches(cve_id);
            """
        )
        before_cpes = int(conn.execute("SELECT COUNT(*) AS n FROM cve_cpes").fetchone()["n"])
        before_prods = int(conn.execute("SELECT COUNT(*) AS n FROM cve_products").fetchone()["n"])
        before_matches = int(
            conn.execute("SELECT COUNT(*) AS n FROM cve_cpe_matches").fetchone()["n"]
        )
        need_cpes = force or before_cpes < min_cpes
        need_matches = force or before_matches < min_matches
        if not need_cpes and not need_matches:
            return {
                "skipped": True,
                "reason": "already_populated",
                "cve_cpes": before_cpes,
                "cve_products": before_prods,
                "cve_cpe_matches": before_matches,
            }

        # Older DBs may lack cpe_matches_json until init_db/_ensure runs.
        try:
            conn.execute("SELECT cpe_matches_json FROM nvd_cves LIMIT 1")
            has_matches_col = True
        except Exception:
            has_matches_col = False
            try:
                conn.execute("ALTER TABLE nvd_cves ADD COLUMN cpe_matches_json TEXT")
                has_matches_col = True
            except Exception:
                has_matches_col = False

        if has_matches_col:
            rows = conn.execute(
                """
                SELECT cve_id, cpes_json, cpe_matches_json FROM nvd_cves
                WHERE (cpes_json IS NOT NULL AND length(cpes_json) > 4)
                   OR (cpe_matches_json IS NOT NULL AND length(cpe_matches_json) > 4)
                """
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT cve_id, cpes_json FROM nvd_cves
                WHERE cpes_json IS NOT NULL AND length(cpes_json) > 4
                """
            ).fetchall()

        cpe_batch: list[tuple[str, str]] = []
        prod_batch: list[tuple[str, str, str, str, str]] = []
        match_batch: list[tuple[Any, ...]] = []
        seen_cpe: set[tuple[str, str]] = set()
        seen_prod: set[tuple[str, str, str, str]] = set()
        seen_match: set[tuple[Any, ...]] = set()
        cpe_added = 0
        prod_added = 0
        match_added = 0
        total = len(rows)

        if need_matches and (force or before_matches == 0):
            conn.execute("DELETE FROM cve_cpe_matches")

        def flush() -> None:
            nonlocal cpe_added, prod_added, match_added, cpe_batch, prod_batch, match_batch
            if need_cpes and cpe_batch:
                conn.executemany(
                    """
                    INSERT INTO cve_cpes(cve_id, cpe)
                    SELECT ?, ?
                    WHERE NOT EXISTS (
                      SELECT 1 FROM cve_cpes x
                      WHERE x.cve_id = ? AND lower(x.cpe) = lower(?)
                    )
                    """,
                    [(cid, cpe, cid, cpe) for cid, cpe in cpe_batch],
                )
                cpe_added += len(cpe_batch)
                cpe_batch = []
            if need_cpes and prod_batch:
                conn.executemany(
                    """
                    INSERT INTO cve_products(cve_id, vendor, product, version, status)
                    SELECT ?, ?, ?, ?, ?
                    WHERE NOT EXISTS (
                      SELECT 1 FROM cve_products p
                      WHERE p.cve_id = ? AND lower(p.product) = lower(?)
                        AND lower(COALESCE(p.vendor,'')) = lower(?)
                        AND COALESCE(p.version,'') = ?
                    )
                    """,
                    [
                        (cid, v, p, ver, st, cid, p, v, ver)
                        for cid, v, p, ver, st in prod_batch
                    ],
                )
                prod_added += len(prod_batch)
                prod_batch = []
            if need_matches and match_batch:
                conn.executemany(
                    """
                    INSERT INTO cve_cpe_matches(
                        cve_id, cpe, soft, version, update_token,
                        ver_start_incl, ver_start_excl, ver_end_incl, ver_end_excl, vulnerable
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    match_batch,
                )
                match_added += len(match_batch)
                match_batch = []

        for idx, r in enumerate(rows, start=1):
            check_cancelled()
            cid = str(r["cve_id"] or "").strip().upper()
            if not cid:
                continue

            matches: list[dict[str, Any]] = []
            raw_matches = r["cpe_matches_json"] if "cpe_matches_json" in r.keys() else None
            if raw_matches:
                try:
                    parsed = json.loads(raw_matches or "[]")
                    if isinstance(parsed, list):
                        matches = [m for m in parsed if isinstance(m, dict)]
                except json.JSONDecodeError:
                    matches = []

            cpe_uris: list[str] = []
            try:
                arr = json.loads(r["cpes_json"] or "[]")
                if isinstance(arr, list):
                    cpe_uris = [str(x).strip() for x in arr if str(x).strip()]
            except json.JSONDecodeError:
                cpe_uris = []

            if not matches and cpe_uris:
                for cpe_s in cpe_uris[:40]:
                    parts = cpe_s.lower().replace("cpe:/", "cpe:2.3:").split(":")
                    version = parts[5] if len(parts) > 5 else ""
                    update = parts[6] if len(parts) > 6 else ""
                    matches.append(
                        {
                            "cpe": cpe_s,
                            "soft": _soft_from_cpe(cpe_s),
                            "version": version,
                            "update": update,
                            "ver_start_incl": "",
                            "ver_start_excl": "",
                            "ver_end_incl": "",
                            "ver_end_excl": "",
                            "vulnerable": 1,
                        }
                    )

            for m in matches[:80]:
                cpe_s = str(m.get("cpe") or "").strip()
                if not cpe_s:
                    continue
                if need_cpes:
                    key_c = (cid, cpe_s.lower())
                    if key_c not in seen_cpe:
                        seen_cpe.add(key_c)
                        cpe_batch.append((cid, cpe_s))
                    parts = cpe_s.lower().replace("cpe:/", "cpe:2.3:").split(":")
                    if len(parts) >= 6 and parts[0] == "cpe" and parts[1] == "2.3":
                        vendor = parts[3] if parts[3] not in wild else ""
                        product = parts[4] if parts[4] not in wild else ""
                        version = parts[5] if parts[5] not in wild else ""
                        update = parts[6] if len(parts) > 6 and parts[6] not in wild else ""
                        # Skip pre-release-only CPEs so cve_products does not
                        # store GA-looking versions like 3.14.0 for 3.14.0:alpha1.
                        _pre = ("alpha", "beta", "rc", "preview", "pre", "dev", "snapshot")
                        upd_l = (update or "").lower()
                        if upd_l.startswith(_pre) or any(
                            upd_l.startswith(f"{t}.") or upd_l.startswith(f"{t}-")
                            for t in _pre
                        ):
                            version = ""
                        if product and version:
                            key_p = (cid, vendor.lower(), product.lower(), version)
                            if key_p not in seen_prod:
                                seen_prod.add(key_p)
                                prod_batch.append(
                                    (cid, vendor, product, version, "nvd_cpe")
                                )
                if need_matches:
                    soft = str(m.get("soft") or _soft_from_cpe(cpe_s))
                    version = str(m.get("version") or "")
                    update = str(m.get("update") or m.get("update_token") or "")
                    si = str(m.get("ver_start_incl") or "")
                    sx = str(m.get("ver_start_excl") or "")
                    ei = str(m.get("ver_end_incl") or "")
                    ex = str(m.get("ver_end_excl") or "")
                    vuln = 1 if int(m.get("vulnerable", 1) or 0) else 0
                    key_m = (cid, cpe_s.lower(), si, sx, ei, ex, vuln)
                    if key_m in seen_match:
                        continue
                    seen_match.add(key_m)
                    match_batch.append(
                        (cid, cpe_s, soft, version, update, si, sx, ei, ex, vuln)
                    )

            if (
                len(cpe_batch) >= 2000
                or len(prod_batch) >= 2000
                or len(match_batch) >= 2000
            ):
                flush()
            if idx % 25_000 == 0:
                set_progress(
                    phase="nvd_cpe_expand",
                    label="Expanding NVD CPEs",
                    detail=f"{idx:,}/{total:,}",
                    current=idx,
                    total=total,
                )
        flush()
        after_cpes = int(conn.execute("SELECT COUNT(*) AS n FROM cve_cpes").fetchone()["n"])
        after_prods = int(conn.execute("SELECT COUNT(*) AS n FROM cve_products").fetchone()["n"])
        after_matches = int(
            conn.execute("SELECT COUNT(*) AS n FROM cve_cpe_matches").fetchone()["n"]
        )
        set_meta(conn, "nvd_cpe_expand_at", utc_now())
        set_meta(conn, "nvd_cpe_matches_at", utc_now())
    return {
        "skipped": False,
        "cve_cpes_before": before_cpes,
        "cve_cpes_after": after_cpes,
        "cve_products_before": before_prods,
        "cve_products_after": after_prods,
        "cve_cpe_matches_before": before_matches,
        "cve_cpe_matches_after": after_matches,
        "cpe_rows_touched": cpe_added,
        "product_rows_touched": prod_added,
        "match_rows_touched": match_added,
        "ranges_available": after_matches > 0,
    }


def refresh_recent_nvd_for_ranges(
    *,
    years: list[int] | None = None,
    force_download: bool = False,
) -> dict[str, Any]:
    """
    Download/parse NVD year feeds so cpe_matches_json includes version ranges,
    then expand lookup tables (force matches rebuild).

    Default years: every feed from NVD_FEED_FIRST_YEAR through the current year
    (plus modified + recent). Existing zip files are re-parsed without re-download
    unless force_download=True.
    """
    config.ensure_dirs()
    now_year = datetime.now(timezone.utc).year
    first = int(getattr(config, "NVD_FEED_FIRST_YEAR", 2002) or 2002)
    use_years = years or list(range(first, now_year + 1))
    feeds = [str(y) for y in use_years] + ["modified", "recent"]
    stats: dict[str, Any] = {
        "feeds": feeds,
        "ingested": {},
        "downloaded": [],
        "reused_zip": [],
    }
    for idx, feed_id in enumerate(feeds, start=1):
        check_cancelled()
        set_progress(
            phase="nvd_range_refresh",
            label=f"NVD feed {feed_id}",
            detail=f"{idx}/{len(feeds)} — ranges backfill",
            current=idx,
            total=len(feeds),
        )
        try:
            with db_session() as conn:
                conn.execute(
                    "DELETE FROM sync_meta WHERE key=?",
                    (f"nvd_meta_sha_{feed_id}",),
                )
            meta = _fetch_meta(feed_id) or {}
            zip_path = config.NVD_FEED_DIR / f"nvdcve-2.0-{feed_id}.json.zip"
            need_dl = force_download or not zip_path.is_file()
            if need_dl:
                set_progress(
                    phase="nvd_download",
                    label=f"Downloading NVD {feed_id}",
                    detail=_zip_url(feed_id),
                    current=idx,
                    total=len(feeds),
                )
                download_file(_zip_url(feed_id), zip_path)
                stats["downloaded"].append(feed_id)
            else:
                stats["reused_zip"].append(feed_id)
            n = _ingest_zip(zip_path, feed_id=feed_id)
            stats["ingested"][feed_id] = n
            with db_session() as conn:
                if meta.get("sha256"):
                    set_meta(conn, f"nvd_meta_sha_{feed_id}", meta["sha256"])
                if feed_id.isdigit():
                    set_meta(conn, f"nvd_feed_ok_{feed_id}", utc_now())
        except Exception as exc:
            log.warning("NVD range refresh failed for %s: %s", feed_id, exc)
            stats["ingested"][feed_id] = {"error": str(exc)}
    mirror = mirror_to_cves()
    expand = expand_nvd_cpes_into_lookup_tables(force=True)
    stats["mirror"] = mirror
    stats["expand"] = expand
    return stats


def download_all_nvd_years(*, force_download: bool = False) -> dict[str, Any]:
    """Download + ingest every NVD year zip (2002…current) into the local DB."""
    return refresh_recent_nvd_for_ranges(years=None, force_download=force_download)


def download_and_ingest_for_cves(*, full: bool | None = None) -> dict[str, Any]:
    """
    NVD JSON 2.0 feeds as a CVE List source: download year/modified/recent zips,
    upsert into nvd_cves, then mirror into Manage `cves` (no duplicate CVE ids).
    """
    # Prefer a complete local year archive when Sync asks for full, or when
    # many year zips are still missing on disk.
    missing_years = []
    first = int(getattr(config, "NVD_FEED_FIRST_YEAR", 2002) or 2002)
    now_year = datetime.now(timezone.utc).year
    for y in range(first, now_year + 1):
        zp = config.NVD_FEED_DIR / f"nvdcve-2.0-{y}.json.zip"
        if not zp.is_file():
            missing_years.append(y)
    if full is True or (full is None and len(missing_years) > 3):
        # Ensure every year zip is present + range JSON populated.
        stats = download_all_nvd_years(force_download=False)
        return stats

    stats = download_and_ingest(full=full)
    mirror = mirror_to_cves()
    stats["cves_mirror"] = mirror
    try:
        stats["cpe_expand"] = expand_nvd_cpes_into_lookup_tables(force=False)
        with db_session() as conn:
            n_matches = int(
                conn.execute("SELECT COUNT(*) AS n FROM cve_cpe_matches").fetchone()["n"]
            )
        if n_matches < 10_000:
            stats["cpe_expand"] = expand_nvd_cpes_into_lookup_tables(force=True)
    except Exception as exc:
        log.warning("NVD CPE expand failed: %s", exc)
        stats["cpe_expand"] = {"error": str(exc)}
    return stats


def _ingest_zip(zip_path: Path, *, feed_id: str) -> int:
    set_progress(phase="nvd_parse", label=f"Parsing NVD feed {feed_id}", detail=zip_path.name)
    count = 0
    batch: list[dict[str, Any]] = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = [n for n in zf.namelist() if n.endswith(".json")]
        if not names:
            return 0
        with zf.open(names[0]) as fh:
            # Stream-load JSON (feeds fit in memory for year files ~ tens of MB uncompressed)
            payload = json.loads(fh.read().decode("utf-8", errors="replace"))
    vulns = payload.get("vulnerabilities") or []
    total = len(vulns)
    for i, item in enumerate(vulns, start=1):
        check_cancelled()
        row = _row_from_vuln(item if isinstance(item, dict) else {})
        if not row:
            continue
        batch.append(row)
        if len(batch) >= 500:
            count += _upsert_rows(batch)
            batch = []
            if i % 2000 == 0:
                set_progress(
                    phase="nvd_parse",
                    label=f"Parsing NVD feed {feed_id}",
                    detail=f"{i:,}/{total:,}",
                    current=i,
                    total=total,
                )
    if batch:
        count += _upsert_rows(batch)
    return count


def _should_download(feed_id: str, meta: dict[str, str]) -> bool:
    sha = (meta.get("sha256") or "").lower()
    with db_session() as conn:
        prev = conn.execute(
            "SELECT value FROM sync_meta WHERE key=?",
            (f"nvd_meta_sha_{feed_id}",),
        ).fetchone()
    if prev and (prev["value"] or "").lower() == sha and sha:
        zip_path = config.NVD_FEED_DIR / f"nvdcve-2.0-{feed_id}.json.zip"
        if zip_path.is_file():
            return False
    return True


def download_and_ingest(*, full: bool | None = None) -> dict[str, Any]:
    """
    Sync NVD JSON 2.0 ZIP feeds (year + modified + recent).

    Upserts by cve_id (ON CONFLICT) — re-running a year never creates duplicates.
    full=None → auto: all years when corpus is sparse; else missing years + modified/recent.
    """
    config.ensure_dirs()
    job_id = None
    with db_session() as conn:
        job_id = log_job_start(conn, "nvd_ingest")
        existing = conn.execute("SELECT COUNT(*) AS n FROM nvd_cves").fetchone()["n"]
        _bootstrap_year_metas_if_healthy(conn, int(existing or 0))

    if full is None:
        # Incomplete corpus (partial year ingest) must not stay on incremental forever.
        full = existing == 0 or int(existing) < 100_000

    feeds = _feed_ids(full=bool(full))
    # De-dupe while preserving order (missing years + modified/recent).
    seen_ids: set[str] = set()
    ordered: list[str] = []
    for fid in feeds:
        if fid not in seen_ids:
            seen_ids.add(fid)
            ordered.append(fid)
    feeds = ordered

    set_progress(
        phase="nvd_sync",
        label="Syncing NVD JSON 2.0 feeds",
        detail=f"{'full' if full else 'incremental'} ({len(feeds)} feeds)",
    )

    stats = {
        "mode": "full" if full else "incremental",
        "feeds": [],
        "upserted": 0,
        "skipped": 0,
        "downloaded": 0,
        "feed_ids": feeds,
    }

    try:
        for idx, feed_id in enumerate(feeds, start=1):
            check_cancelled()
            set_progress(
                phase="nvd_meta",
                label=f"NVD feed {feed_id}",
                detail=f"{idx}/{len(feeds)} — checking META",
                current=idx,
                total=len(feeds),
            )
            meta = _fetch_meta(feed_id)
            if not meta:
                stats["feeds"].append({"id": feed_id, "status": "meta_failed"})
                continue

            zip_path = config.NVD_FEED_DIR / f"nvdcve-2.0-{feed_id}.json.zip"
            need = _should_download(feed_id, meta) or not zip_path.is_file()
            if not need:
                stats["skipped"] += 1
                stats["feeds"].append({"id": feed_id, "status": "unchanged"})
                # Year still counts as present when META matches prior successful ingest.
                if feed_id.isdigit():
                    with db_session() as conn:
                        set_meta(conn, f"nvd_feed_ok_{feed_id}", utc_now())
                continue

            set_progress(
                phase="nvd_download",
                label=f"Downloading NVD {feed_id}",
                detail=_zip_url(feed_id),
                current=idx,
                total=len(feeds),
            )
            result = download_file(
                _zip_url(feed_id),
                zip_path,
                etag_path=config.NVD_FEED_DIR / f"nvdcve-2.0-{feed_id}.etag",
                label=f"NVD {feed_id}",
            )
            if result.get("skipped") and zip_path.is_file():
                # ETag skip but META said changed — still parse local zip
                pass
            elif not zip_path.is_file():
                stats["feeds"].append({"id": feed_id, "status": "download_failed"})
                continue

            stats["downloaded"] += 1
            n = _ingest_zip(zip_path, feed_id=feed_id)
            stats["upserted"] += n
            with db_session() as conn:
                set_meta(conn, f"nvd_meta_sha_{feed_id}", meta.get("sha256") or "")
                set_meta(conn, f"nvd_meta_modified_{feed_id}", meta.get("lastModifiedDate") or "")
                if feed_id.isdigit():
                    set_meta(conn, f"nvd_feed_ok_{feed_id}", utc_now())
            stats["feeds"].append({"id": feed_id, "status": "ok", "upserted": n})

        with db_session() as conn:
            set_meta(conn, "nvd_last_ingest", utc_now())
            set_meta(conn, "nvd_last_mode", stats["mode"])
            invalidate_nvd_product_counts(conn)
            nvd_count = conn.execute("SELECT COUNT(*) AS n FROM nvd_cves").fetchone()["n"]
            stats["nvd_cves"] = int(nvd_count)
            stats["overview"] = refresh_overview(conn)
            if job_id:
                log_job_finish(conn, job_id, "ok", f"NVD upserted {stats['upserted']}")
        set_progress(phase="idle", label="Idle", detail="NVD sync complete")
        return stats
    except JobCancelled:
        with db_session() as conn:
            if job_id:
                log_job_finish(conn, job_id, "cancelled", "NVD sync cancelled")
        raise
    except Exception as exc:
        with db_session() as conn:
            if job_id:
                log_job_finish(conn, job_id, "error", str(exc)[:400])
        raise


def sync_delta() -> dict[str, Any]:
    """Incremental NVD sync (modified + recent feeds)."""
    return download_and_ingest(full=False)


def get_nvd_detail(cve_id: str) -> dict[str, Any] | None:
    cve_id = (cve_id or "").strip().upper()
    if not cve_id:
        return None
    with db_session() as conn:
        row = conn.execute("SELECT * FROM nvd_cves WHERE cve_id = ?", (cve_id,)).fetchone()
        if not row:
            return None
        data = dict(row)
        cwe_ids = []
        try:
            cwe_ids = json.loads(data.get("cwe_ids") or "[]")
        except json.JSONDecodeError:
            cwe_ids = []
        cwes: list[dict[str, str]] = []
        for cid in cwe_ids:
            crow = conn.execute("SELECT cwe_id, name, description, url FROM cwe WHERE cwe_id = ?", (cid,)).fetchone()
            if crow:
                cwes.append(dict(crow))
            else:
                num = cid.replace("CWE-", "")
                cwes.append(
                    {
                        "cwe_id": cid,
                        "name": "",
                        "description": "",
                        "url": f"https://cwe.mitre.org/data/definitions/{num}.html",
                    }
                )
        try:
            cpes = json.loads(data.get("cpes_json") or "[]")
        except json.JSONDecodeError:
            cpes = []
        try:
            refs = json.loads(data.get("references_json") or "[]")
        except json.JSONDecodeError:
            refs = []
        return {
            "cve_id": data["cve_id"],
            "vuln_status": data.get("vuln_status") or "",
            "source_id": data.get("source_id") or "",
            "published": data.get("published") or "",
            "last_modified": data.get("last_modified") or "",
            "description": data.get("description") or "",
            "cvss_version": data.get("cvss_version") or "",
            "cvss_score": data.get("cvss_score"),
            "cvss_vector": data.get("cvss_vector") or "",
            "severity": data.get("severity") or "",
            "cwes": cwes,
            "cpes": cpes,
            "references": refs,
            "detail_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "feed_info": "NVD JSON 2.0 feed",
        }
