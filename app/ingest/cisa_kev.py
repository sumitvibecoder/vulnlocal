"""Ingest CISA Known Exploited Vulnerabilities Catalog (official JSON feed).

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
Feed:   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

from __future__ import annotations

import json
import logging
from typing import Any

from .. import config
from ..db import db_session, log_job_finish, log_job_start, set_meta, utc_now
from ..httputil import download_file
from ..progress import JobCancelled, check_cancelled, set_progress
from ..settings_store import get_url

log = logging.getLogger("vulnlocal.cisa_kev")


def download_and_ingest() -> dict[str, Any]:
    config.ensure_dirs()
    job_id = None
    with db_session() as conn:
        job_id = log_job_start(conn, "cisa_kev_ingest")

    set_progress(phase="cisa_kev", label="Downloading CISA KEV catalog", detail="JSON feed")
    try:
        dest = config.CISA_KEV_DIR / "known_exploited_vulnerabilities.json"
        result = download_file(
            get_url("cisa_kev_json", config.CISA_KEV_JSON_URL),
            dest,
            etag_path=config.CISA_KEV_DIR / "kev.etag",
            label="CISA KEV JSON",
        )
        check_cancelled()
        if not dest.is_file():
            raise RuntimeError("CISA KEV JSON download failed")

        if result.get("skipped"):
            with db_session() as conn:
                count = conn.execute("SELECT COUNT(*) AS n FROM cisa_kev").fetchone()["n"]
                from ..sync.feed_health import FEED_MIN_COUNTS

                if int(count or 0) >= FEED_MIN_COUNTS.get("cisa_kev", 1):
                    if job_id:
                        log_job_finish(conn, job_id, "ok", f"cisa_kev unchanged (etag) {count}")
                    set_progress(phase="idle", label="Idle", detail="CISA KEV unchanged — skipped")
                    return {
                        "cisa_kev": int(count),
                        "upserted": 0,
                        "skipped": True,
                        "skipped_download": True,
                    }

        set_progress(phase="cisa_kev", label="Parsing CISA KEV catalog", detail=dest.name)
        data = json.loads(dest.read_text(encoding="utf-8"))
        vulns = data.get("vulnerabilities") or []
        rows: list[dict[str, Any]] = []
        for item in vulns:
            check_cancelled()
            if not isinstance(item, dict):
                continue
            cve_id = str(item.get("cveID") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue
            cwes = item.get("cwes") or []
            if not isinstance(cwes, list):
                cwes = [str(cwes)]
            rows.append(
                {
                    "cve_id": cve_id,
                    "vendor_project": str(item.get("vendorProject") or ""),
                    "product": str(item.get("product") or ""),
                    "vulnerability_name": str(item.get("vulnerabilityName") or ""),
                    "date_added": str(item.get("dateAdded") or ""),
                    "short_description": str(item.get("shortDescription") or ""),
                    "required_action": str(item.get("requiredAction") or ""),
                    "due_date": str(item.get("dueDate") or ""),
                    "known_ransomware": str(item.get("knownRansomwareCampaignUse") or ""),
                    "notes": str(item.get("notes") or ""),
                    "cwes_json": json.dumps([str(c) for c in cwes]),
                    "detail_url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search={cve_id}",
                    "raw_json": json.dumps(item)[:100_000],
                    "updated_at": utc_now(),
                }
            )

        with db_session() as conn:
            if rows:
                conn.executemany(
                    """
                    INSERT INTO cisa_kev(
                        cve_id, vendor_project, product, vulnerability_name, date_added,
                        short_description, required_action, due_date, known_ransomware,
                        notes, cwes_json, detail_url, raw_json, updated_at
                    ) VALUES (
                        :cve_id, :vendor_project, :product, :vulnerability_name, :date_added,
                        :short_description, :required_action, :due_date, :known_ransomware,
                        :notes, :cwes_json, :detail_url, :raw_json, :updated_at
                    )
                    ON CONFLICT(cve_id) DO UPDATE SET
                        vendor_project=excluded.vendor_project,
                        product=excluded.product,
                        vulnerability_name=excluded.vulnerability_name,
                        date_added=excluded.date_added,
                        short_description=excluded.short_description,
                        required_action=excluded.required_action,
                        due_date=excluded.due_date,
                        known_ransomware=excluded.known_ransomware,
                        notes=excluded.notes,
                        cwes_json=excluded.cwes_json,
                        detail_url=excluded.detail_url,
                        raw_json=excluded.raw_json,
                        updated_at=excluded.updated_at
                    """,
                    rows,
                )
            set_meta(conn, "cisa_kev_last_ingest", utc_now())
            set_meta(conn, "cisa_kev_catalog_version", str(data.get("catalogVersion") or ""))
            count = conn.execute("SELECT COUNT(*) AS n FROM cisa_kev").fetchone()["n"]
            if job_id:
                log_job_finish(conn, job_id, "ok", f"cisa_kev={count}")
        set_progress(phase="idle", label="Idle", detail="CISA KEV sync complete")
        return {
            "cisa_kev": int(count),
            "upserted": len(rows),
            "catalog_version": data.get("catalogVersion"),
            "skipped_download": bool(result.get("skipped")),
        }
    except JobCancelled:
        with db_session() as conn:
            if job_id:
                log_job_finish(conn, job_id, "cancelled", "cancelled")
        raise
    except Exception as exc:
        with db_session() as conn:
            if job_id:
                log_job_finish(conn, job_id, "error", str(exc)[:400])
        raise


def get_cisa_kev(cve_id: str) -> dict[str, Any] | None:
    cve_id = (cve_id or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return None
    with db_session() as conn:
        row = conn.execute("SELECT * FROM cisa_kev WHERE cve_id=?", (cve_id,)).fetchone()
    if not row:
        return None
    data = dict(row)
    try:
        data["cwes"] = json.loads(data.pop("cwes_json") or "[]")
    except json.JSONDecodeError:
        data["cwes"] = []
    data.pop("raw_json", None)
    data["in_catalog"] = True
    data["catalog_url"] = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    return data
