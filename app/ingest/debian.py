"""Ingest Debian Security Tracker official JSON dump.

Source: https://security-tracker.debian.org/tracker/
Feed:   https://security-tracker.debian.org/tracker/data/json
"""

from __future__ import annotations

import json
import logging
from typing import Any

from .. import config
from ..db import db_session, log_job_finish, log_job_start, set_meta, utc_now
from ..httputil import download_file
from ..progress import check_cancelled, set_progress
from ..settings_store import get_url

log = logging.getLogger("vulnlocal.debian")


def download_and_ingest() -> dict[str, Any]:
    config.ensure_dirs()
    job_id = None
    with db_session() as conn:
        job_id = log_job_start(conn, "debian_ingest")
    set_progress(phase="debian", label="Downloading Debian tracker JSON", detail="data/json")
    try:
        dest = config.DEBIAN_DIR / "tracker.json"
        result = download_file(
            get_url("debian_tracker_json", config.DEBIAN_TRACKER_JSON_URL),
            dest,
            etag_path=config.DEBIAN_DIR / "tracker.etag",
            label="Debian tracker JSON",
        )
        check_cancelled()
        if result.get("skipped"):
            with db_session() as conn:
                n = conn.execute("SELECT COUNT(*) AS n FROM debian_cves").fetchone()["n"]
                from ..sync.feed_health import FEED_MIN_COUNTS

                if int(n or 0) >= FEED_MIN_COUNTS.get("debian_cves", 1):
                    if job_id:
                        log_job_finish(conn, job_id, "ok", f"debian unchanged {n}")
                    set_progress(phase="idle", label="Idle", detail="Debian tracker unchanged — skipped")
                    return {"debian_cves": int(n), "upserted": 0, "skipped": True, "skipped_download": True}

        set_progress(phase="debian", label="Parsing Debian tracker", detail=dest.name)
        data = json.loads(dest.read_text(encoding="utf-8"))
        now = utc_now()
        rows: list[dict[str, Any]] = []
        # Shape: { "package": { "CVE-…": {…}, … }, … }
        for pkg, vulns in data.items():
            check_cancelled()
            if not isinstance(vulns, dict):
                continue
            for cve_id, meta in vulns.items():
                if not isinstance(cve_id, str) or not cve_id.upper().startswith("CVE-"):
                    continue
                if not isinstance(meta, dict):
                    continue
                cid = cve_id.upper()
                rows.append(
                    {
                        "cve_id": cid,
                        "scope": str(meta.get("scope") or ""),
                        "description": str(meta.get("description") or "")[:4000],
                        "debianbug": str(meta.get("debianbug") or ""),
                        "packages_json": json.dumps(
                            {"package": pkg, "releases": meta.get("releases") or {}},
                            separators=(",", ":"),
                        ),
                        "detail_url": f"https://security-tracker.debian.org/tracker/{cid}",
                        "updated_at": now,
                    }
                )
        # Collapse multiple packages per CVE into one row (merge package blobs)
        merged: dict[str, dict[str, Any]] = {}
        for row in rows:
            cid = row["cve_id"]
            if cid not in merged:
                merged[cid] = dict(row)
                merged[cid]["_pkgs"] = [json.loads(row["packages_json"])]
            else:
                merged[cid]["_pkgs"].append(json.loads(row["packages_json"]))
                if not merged[cid]["description"] and row["description"]:
                    merged[cid]["description"] = row["description"]
        out_rows = []
        for cid, row in merged.items():
            pkgs = row.pop("_pkgs", [])
            row["packages_json"] = json.dumps(pkgs, separators=(",", ":"))
            out_rows.append(row)

        with db_session() as conn:
            conn.execute("DELETE FROM debian_cves")
            conn.executemany(
                """
                INSERT INTO debian_cves(cve_id, scope, description, debianbug,
                                        packages_json, detail_url, updated_at)
                VALUES (:cve_id, :scope, :description, :debianbug,
                        :packages_json, :detail_url, :updated_at)
                """,
                out_rows,
            )
            set_meta(conn, "debian_last_ingest", utc_now())
            if job_id:
                log_job_finish(conn, job_id, "ok", f"debian_cves={len(out_rows)}")
        set_progress(phase="idle", label="Idle", detail=f"Debian {len(out_rows):,}")
        return {"debian_cves": len(out_rows), "upserted": len(out_rows)}
    except Exception as exc:
        log.exception("Debian ingest failed")
        with db_session() as conn:
            if job_id:
                log_job_finish(conn, job_id, "error", str(exc))
        raise
