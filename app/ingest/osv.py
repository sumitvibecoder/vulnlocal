"""Ingest OSV.dev ecosystem vulnerability zips (official GCS mirrors).

Source: https://osv.dev/list
Docs:   https://google.github.io/osv.dev/
Zips:   https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip
"""

from __future__ import annotations

import json
import logging
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .. import config
from ..db import db_session, log_job_finish, log_job_start, set_meta, utc_now
from ..httputil import download_file
from ..progress import JobCancelled, check_cancelled, set_progress
from ..settings_store import get_url

log = logging.getLogger("vulnlocal.osv")

_UPSERT_VULN = """
INSERT INTO osv_vulns(osv_id, summary, details, severity, published, modified,
                      aliases_json, packages_json, detail_url, updated_at)
VALUES (:osv_id, :summary, :details, :severity, :published, :modified,
        :aliases_json, :packages_json, :detail_url, :updated_at)
ON CONFLICT(osv_id) DO UPDATE SET
    summary=excluded.summary,
    details=excluded.details,
    severity=excluded.severity,
    published=excluded.published,
    modified=excluded.modified,
    aliases_json=excluded.aliases_json,
    packages_json=excluded.packages_json,
    detail_url=excluded.detail_url,
    updated_at=excluded.updated_at
"""


def _ecosystems() -> list[str]:
    raw = get_url("osv_ecosystems", ",".join(config.OSV_ECOSYSTEMS))
    return [x.strip() for x in raw.split(",") if x.strip()]


def _parse_vuln(doc: dict[str, Any], now: str) -> tuple[dict[str, Any], list[str]] | None:
    osv_id = str(doc.get("id") or "").strip()
    if not osv_id:
        return None
    aliases = [str(a).strip().upper() for a in (doc.get("aliases") or []) if str(a).strip()]
    cves = [a for a in aliases if a.startswith("CVE-")]
    if osv_id.upper().startswith("CVE-"):
        cves.append(osv_id.upper())
    packages = []
    for affected in doc.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package") or {}
        packages.append(
            {
                "ecosystem": pkg.get("ecosystem") or "",
                "name": pkg.get("name") or "",
                "purl": pkg.get("purl") or "",
            }
        )
    sev = ""
    for s in doc.get("severity") or []:
        if isinstance(s, dict) and s.get("score"):
            sev = str(s.get("score"))
            break
        if isinstance(s, str) and s.strip():
            sev = s.strip()
            break
    row = {
        "osv_id": osv_id,
        "summary": str(doc.get("summary") or "")[:1000],
        "details": str(doc.get("details") or "")[:4000],
        "severity": sev,
        "published": str(doc.get("published") or ""),
        "modified": str(doc.get("modified") or ""),
        "aliases_json": json.dumps(aliases, separators=(",", ":")),
        "packages_json": json.dumps(packages[:40], separators=(",", ":")),
        "detail_url": f"https://osv.dev/vulnerability/{osv_id}",
        "updated_at": now,
    }
    return row, sorted(set(cves))


def _flush_batch(
    vuln_rows: dict[str, dict[str, Any]],
    cve_links: set[tuple[str, str]],
) -> int:
    if not vuln_rows:
        return 0
    rows = list(vuln_rows.values())
    ids = [r["osv_id"] for r in rows]
    with db_session() as conn:
        conn.executemany(_UPSERT_VULN, rows)
        # Replace CVE links for these OSV ids
        conn.executemany("DELETE FROM osv_cves WHERE osv_id = ?", [(i,) for i in ids])
        if cve_links:
            conn.executemany(
                "INSERT OR IGNORE INTO osv_cves(osv_id, cve_id) VALUES (?, ?)",
                list(cve_links),
            )
    return len(rows)


def download_and_ingest() -> dict[str, Any]:
    """Download/parse each ecosystem zip and upsert immediately (Manage counts rise live)."""
    config.ensure_dirs()
    job_id = None
    with db_session() as conn:
        job_id = log_job_start(conn, "osv_ingest")
    now = utc_now()
    ecosystems = _ecosystems()
    total_upserted = 0
    ecos_ok: list[str] = []
    try:
        for i, eco in enumerate(ecosystems, 1):
            check_cancelled()
            tmpl = get_url("osv_ecosystem_zip", config.OSV_ECOSYSTEM_ZIP_TMPL)
            url = tmpl.format(ecosystem=quote(eco, safe="."))
            safe_name = eco.replace("/", "_").replace(" ", "_")
            dest = config.OSV_DIR / f"{safe_name}.zip"
            set_progress(
                phase="osv",
                label=f"Downloading OSV {eco}",
                current=i,
                total=len(ecosystems),
                unit="ecosystems",
                detail=url,
            )
            try:
                download_file(
                    url,
                    dest,
                    etag_path=config.OSV_DIR / f"{safe_name}.etag",
                    label=f"OSV {eco}",
                )
            except Exception as exc:
                log.warning("OSV download failed for %s: %s", eco, exc)
                continue
            if not dest.is_file():
                log.warning("OSV zip missing for %s", eco)
                continue

            set_progress(phase="osv", label=f"Parsing OSV {eco}", detail=dest.name)
            vuln_rows: dict[str, dict[str, Any]] = {}
            cve_links: set[tuple[str, str]] = set()
            try:
                with zipfile.ZipFile(dest, "r") as zf:
                    names = [n for n in zf.namelist() if n.lower().endswith(".json")]
                    for j, name in enumerate(names, 1):
                        if j % 500 == 0:
                            check_cancelled()
                            set_progress(
                                phase="osv",
                                label=f"Parsing OSV {eco}",
                                current=j,
                                total=len(names),
                                unit="vulns",
                                detail=f"{Path(name).name} stored={total_upserted + len(vuln_rows)}",
                            )
                            # Flush periodically to keep memory bounded + UI counts live
                            if len(vuln_rows) >= 2000:
                                total_upserted += _flush_batch(vuln_rows, cve_links)
                                vuln_rows.clear()
                                cve_links.clear()
                        try:
                            doc = json.loads(zf.read(name))
                        except (json.JSONDecodeError, KeyError, OSError):
                            continue
                        if not isinstance(doc, dict):
                            continue
                        parsed = _parse_vuln(doc, now)
                        if not parsed:
                            continue
                        row, cves = parsed
                        vuln_rows[row["osv_id"]] = row
                        for cve in cves:
                            cve_links.add((row["osv_id"], cve))
            except zipfile.BadZipFile as exc:
                log.warning("OSV bad zip for %s: %s", eco, exc)
                continue

            total_upserted += _flush_batch(vuln_rows, cve_links)
            ecos_ok.append(eco)
            with db_session() as conn:
                n = int(conn.execute("SELECT COUNT(*) AS n FROM osv_vulns").fetchone()["n"])
            set_progress(
                phase="osv",
                label=f"OSV {eco} done",
                current=i,
                total=len(ecosystems),
                unit="ecosystems",
                detail=f"osv_vulns={n:,}",
            )

        with db_session() as conn:
            final_n = int(conn.execute("SELECT COUNT(*) AS n FROM osv_vulns").fetchone()["n"])
            if total_upserted:
                set_meta(conn, "osv_last_ingest", utc_now())
            if job_id:
                if total_upserted:
                    log_job_finish(
                        conn,
                        job_id,
                        "ok",
                        f"osv={final_n} upserted={total_upserted} ecos={','.join(ecos_ok) or '-'}",
                    )
                else:
                    log_job_finish(
                        conn,
                        job_id,
                        "ok" if final_n else "error",
                        f"osv empty kept={final_n}",
                    )

        if not total_upserted:
            return {
                "osv_vulns": final_n,
                "upserted": 0,
                "skipped": True,
                "reason": "no_vulns_parsed",
                "kept_existing": True,
                "ecosystems": ecosystems,
            }

        set_progress(phase="idle", label="Idle", detail=f"OSV {final_n:,}")
        return {
            "osv_vulns": final_n,
            "cve_links": 0,
            "ecosystems": ecos_ok,
            "upserted": total_upserted,
        }
    except JobCancelled:
        with db_session() as conn:
            final_n = int(conn.execute("SELECT COUNT(*) AS n FROM osv_vulns").fetchone()["n"])
            if job_id:
                log_job_finish(conn, job_id, "cancelled", f"osv partial={final_n}")
        raise
    except Exception as exc:
        log.exception("OSV ingest failed")
        with db_session() as conn:
            if job_id:
                log_job_finish(conn, job_id, "error", str(exc))
        raise
