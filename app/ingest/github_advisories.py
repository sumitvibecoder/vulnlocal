"""Ingest GitHub Advisory Database from the official OSV JSON mirror.

Source: https://github.com/advisories
Repo:   https://github.com/github/advisory-database
Zip:    https://codeload.github.com/github/advisory-database/zip/refs/heads/main

Stores GitHub-reviewed advisories (advisories/github-reviewed/**/*.json),
including withdrawn entries so local counts match github.com/advisories.
No HTML scraping; no paginated REST crawl (avoids the ~100-row rate-limit cap).
"""

from __future__ import annotations

import json
import logging
import zipfile
from pathlib import Path
from typing import Any

from .. import config
from ..db import db_session, log_job_finish, log_job_start, set_meta, utc_now
from ..httputil import download_file
from ..progress import check_cancelled, set_progress
from ..settings_store import get_url

log = logging.getLogger("vulnlocal.ghsa")

_UPSERT_SQL = """
INSERT INTO ghsa_advisories(ghsa_id, cve_id, summary, severity, published_at,
                            updated_at_src, html_url, packages_json, updated_at)
VALUES (:ghsa_id, :cve_id, :summary, :severity, :published_at,
        :updated_at_src, :html_url, :packages_json, :updated_at)
ON CONFLICT(ghsa_id) DO UPDATE SET
    cve_id=excluded.cve_id,
    summary=excluded.summary,
    severity=excluded.severity,
    published_at=excluded.published_at,
    updated_at_src=excluded.updated_at_src,
    html_url=excluded.html_url,
    packages_json=excluded.packages_json,
    updated_at=excluded.updated_at
"""


def _is_reviewed_advisory(name: str) -> bool:
    low = name.replace("\\", "/").lower()
    return "/advisories/github-reviewed/" in low and low.endswith(".json")


def _first_cve(aliases: list[Any], osv_id: str) -> str | None:
    for a in aliases:
        s = str(a or "").strip().upper()
        if s.startswith("CVE-"):
            return s
    oid = osv_id.strip().upper()
    if oid.startswith("CVE-"):
        return oid
    return None


def _packages(doc: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for affected in doc.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package") or {}
        if not isinstance(pkg, dict):
            pkg = {}
        vulnerable = ""
        patched = ""
        for rng in affected.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            for ev in rng.get("events") or []:
                if not isinstance(ev, dict):
                    continue
                if ev.get("introduced") is not None and not vulnerable:
                    vulnerable = f">={ev.get('introduced')}"
                if ev.get("fixed") is not None and not patched:
                    patched = str(ev.get("fixed") or "")
        out.append(
            {
                "ecosystem": str(pkg.get("ecosystem") or ""),
                "name": str(pkg.get("name") or ""),
                "vulnerable": vulnerable,
                "patched": patched,
            }
        )
        if len(out) >= 40:
            break
    return out


def _parse_doc(doc: dict[str, Any], now: str) -> dict[str, Any] | None:
    # Keep withdrawn advisories — github.com/advisories reviewed count includes them.
    ghsa_id = str(doc.get("id") or "").strip().upper()
    if not ghsa_id.startswith("GHSA-"):
        return None
    db_specific = doc.get("database_specific") or {}
    if not isinstance(db_specific, dict):
        db_specific = {}
    severity = str(db_specific.get("severity") or "").strip().upper()
    if not severity:
        for s in doc.get("severity") or []:
            if isinstance(s, dict) and s.get("score"):
                severity = str(s.get("score"))
                break
    if doc.get("withdrawn") and severity and "WITHDRAWN" not in severity:
        severity = f"{severity}/WITHDRAWN"
    elif doc.get("withdrawn") and not severity:
        severity = "WITHDRAWN"
    aliases = doc.get("aliases") or []
    if not isinstance(aliases, list):
        aliases = []
    cve_id = _first_cve(aliases, ghsa_id)
    summary = str(doc.get("summary") or "")[:1000]
    if doc.get("withdrawn") and summary and not summary.lower().startswith("[withdrawn]"):
        summary = f"[withdrawn] {summary}"[:1000]
    return {
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "summary": summary,
        "severity": severity,
        "published_at": str(doc.get("published") or ""),
        "updated_at_src": str(doc.get("modified") or doc.get("withdrawn") or ""),
        "html_url": f"https://github.com/advisories/{ghsa_id}",
        "packages_json": json.dumps(_packages(doc), separators=(",", ":")),
        "updated_at": now,
    }


def _flush(rows: dict[str, dict[str, Any]]) -> int:
    if not rows:
        return 0
    batch = list(rows.values())
    with db_session() as conn:
        conn.executemany(_UPSERT_SQL, batch)
    return len(batch)


def _count_reviewed_in_zip(dest: Path) -> int:
    try:
        with zipfile.ZipFile(dest, "r") as zf:
            return sum(1 for n in zf.namelist() if _is_reviewed_advisory(n))
    except zipfile.BadZipFile:
        return 0


def needs_full_ingest(*, force: bool = False) -> bool:
    """True when Manage still shows the old REST ~100-row GHSA subset."""
    if force:
        return True
    with db_session() as conn:
        n = int(conn.execute("SELECT COUNT(*) AS n FROM ghsa_advisories").fetchone()["n"])
    return n < 20_000


def download_and_ingest(*, force: bool = False) -> dict[str, Any]:
    config.ensure_dirs()
    config.GHSA_DIR.mkdir(parents=True, exist_ok=True)
    job_id = None
    with db_session() as conn:
        job_id = log_job_start(conn, "ghsa_ingest")
        existing_n = int(conn.execute("SELECT COUNT(*) AS n FROM ghsa_advisories").fetchone()["n"])

    url = get_url("github_advisory_database_zip", config.GITHUB_ADVISORY_DATABASE_ZIP_URL)
    # Migrate old Settings value that still points at the REST API.
    if "api.github.com/advisories" in (url or ""):
        url = config.GITHUB_ADVISORY_DATABASE_ZIP_URL
    dest = config.GHSA_DIR / "advisory-database.zip"
    etag_path = config.GHSA_DIR / "advisory-database.etag"
    now = utc_now()
    upserted = 0
    seen: set[str] = set()
    withdrawn_n = 0

    try:
        # If DB was wiped back to the old REST ~100-row subset, force a full zip parse.
        force_parse = force or needs_full_ingest() or existing_n < 20_000
        if force_parse:
            for p in (etag_path, dest):
                try:
                    if p.is_file():
                        p.unlink()
                except OSError:
                    pass

        set_progress(
            phase="ghsa",
            label="Downloading GitHub advisory-database zip",
            current=0,
            total=0,
            unit="bytes",
            detail=url,
        )
        result = download_file(
            url,
            dest,
            etag_path=etag_path,
            label="GitHub advisory-database",
        )
        if not dest.is_file():
            raise FileNotFoundError(f"GHSA zip missing: {dest}")

        zip_reviewed = _count_reviewed_in_zip(dest)
        if zip_reviewed and existing_n < int(zip_reviewed * 0.9):
            force_parse = True

        if result and result.get("skipped") and not force_parse and existing_n >= 20_000:
            with db_session() as conn:
                final_n = int(conn.execute("SELECT COUNT(*) AS n FROM ghsa_advisories").fetchone()["n"])
                if job_id:
                    log_job_finish(
                        conn,
                        job_id,
                        "ok",
                        f"ghsa unchanged (etag) kept={final_n} zip_reviewed={zip_reviewed}",
                    )
            set_progress(phase="idle", label="Idle", detail=f"GHSA unchanged {final_n:,}")
            return {
                "ghsa_advisories": final_n,
                "upserted": 0,
                "reviewed_files": 0,
                "zip_reviewed": zip_reviewed,
                "skipped": True,
                "source": "advisory-database.zip",
            }

        set_progress(
            phase="ghsa",
            label="Parsing GitHub-reviewed advisories",
            detail=f"{dest.name} (~{zip_reviewed:,} files)",
        )
        pending: dict[str, dict[str, Any]] = {}
        with zipfile.ZipFile(dest, "r") as zf:
            names = [n for n in zf.namelist() if _is_reviewed_advisory(n)]
            total = len(names)
            for i, name in enumerate(names, 1):
                if i % 400 == 0:
                    check_cancelled()
                    set_progress(
                        phase="ghsa",
                        label="Parsing GitHub-reviewed advisories",
                        current=i,
                        total=total,
                        unit="advisories",
                        detail=f"{Path(name).name} stored={upserted + len(pending):,}",
                    )
                    if len(pending) >= 1500:
                        upserted += _flush(pending)
                        pending.clear()
                try:
                    doc = json.loads(zf.read(name))
                except (json.JSONDecodeError, KeyError, OSError):
                    continue
                if not isinstance(doc, dict):
                    continue
                if doc.get("withdrawn"):
                    withdrawn_n += 1
                row = _parse_doc(doc, now)
                if not row:
                    continue
                pending[row["ghsa_id"]] = row
                seen.add(row["ghsa_id"])

        upserted += _flush(pending)

        with db_session() as conn:
            # Drop advisories absent from this successful full zip parse.
            if seen:
                conn.execute("DELETE FROM ghsa_advisories WHERE updated_at != ?", (now,))
            final_n = int(conn.execute("SELECT COUNT(*) AS n FROM ghsa_advisories").fetchone()["n"])
            if upserted:
                set_meta(conn, "ghsa_last_ingest", utc_now())
                set_meta(conn, "ghsa_last_count", str(final_n))
            if job_id:
                log_job_finish(
                    conn,
                    job_id,
                    "ok" if final_n else "error",
                    f"ghsa={final_n} upserted={upserted} reviewed_files={len(seen)} "
                    f"withdrawn={withdrawn_n} zip_reviewed={total}",
                )

        set_progress(phase="idle", label="Idle", detail=f"GHSA {final_n:,}")
        return {
            "ghsa_advisories": final_n,
            "upserted": upserted,
            "reviewed_files": len(seen),
            "withdrawn": withdrawn_n,
            "zip_reviewed": total,
            "source": "advisory-database.zip",
        }
    except Exception as exc:
        log.exception("GHSA ingest failed")
        with db_session() as conn:
            existing = int(conn.execute("SELECT COUNT(*) AS n FROM ghsa_advisories").fetchone()["n"])
            if job_id:
                log_job_finish(conn, job_id, "error", f"{exc} kept={existing}")
        raise
