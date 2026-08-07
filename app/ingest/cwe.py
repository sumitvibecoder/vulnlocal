"""Ingest MITRE CWE catalog (official XML zip)."""

from __future__ import annotations

import logging
import zipfile
from pathlib import Path
from typing import Any

try:
    from defusedxml.ElementTree import fromstring as _xml_fromstring
except ImportError:  # pragma: no cover - runtime dependency preferred
    import xml.etree.ElementTree as ET

    def _xml_fromstring(data: bytes | str):
        return ET.fromstring(data)

from .. import config
from ..db import db_session, log_job_finish, log_job_start, set_meta, utc_now
from ..httputil import download_file
from ..progress import JobCancelled, check_cancelled, set_progress
from ..settings_store import get_url

log = logging.getLogger("vulnlocal.cwe")

# CWE XML uses a versioned namespace; ElementTree needs local-name matching.
_NS = {"cwe": "http://cwe.mitre.org/cwe-7"}


def _local(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _text(el) -> str:
    if el is None:
        return ""
    return "".join(el.itertext()).strip()


def _parse_cwe_xml(xml_bytes: bytes) -> list[dict[str, str]]:
    root = _xml_fromstring(xml_bytes)
    rows: list[dict[str, str]] = []
    now = utc_now()
    for el in root.iter():
        if _local(el.tag) != "Weakness":
            continue
        wid = (el.attrib.get("ID") or "").strip()
        name = (el.attrib.get("Name") or "").strip()
        abstraction = (el.attrib.get("Abstraction") or "").strip()
        if not wid:
            continue
        cwe_id = f"CWE-{wid}"
        desc = ""
        for child in el:
            if _local(child.tag) == "Description":
                desc = _text(child)
                break
        rows.append(
            {
                "cwe_id": cwe_id,
                "name": name,
                "abstraction": abstraction,
                "description": desc[:2000],
                "url": f"https://cwe.mitre.org/data/definitions/{wid}.html",
                "updated_at": now,
            }
        )
    return rows


def download_and_ingest() -> dict[str, Any]:
    config.ensure_dirs()
    job_id = None
    with db_session() as conn:
        job_id = log_job_start(conn, "cwe_ingest")

    dest = config.CWE_DIR / "cwec_latest.xml.zip"
    cwe_url = get_url("cwe_xml_zip", config.CWE_XML_ZIP_URL)
    set_progress(phase="cwe_download", label="Downloading MITRE CWE catalog", detail=cwe_url)
    try:
        check_cancelled()
        result = download_file(
            cwe_url,
            dest,
            etag_path=config.CWE_DIR / "cwec_latest.etag",
            label="CWE XML",
        )
        if not dest.is_file():
            raise FileNotFoundError("CWE zip download failed")

        if result.get("skipped"):
            with db_session() as conn:
                count = conn.execute("SELECT COUNT(*) AS n FROM cwe").fetchone()["n"]
                from ..sync.feed_health import FEED_MIN_COUNTS

                if int(count or 0) >= FEED_MIN_COUNTS.get("cwe", 1):
                    if job_id:
                        log_job_finish(conn, job_id, "ok", f"CWE unchanged (etag) {count}")
                    set_progress(phase="idle", label="Idle", detail="CWE unchanged — skipped")
                    return {"cwe_count": int(count), "parsed": 0, "skipped": True}

        set_progress(phase="cwe_parse", label="Parsing CWE XML", detail=dest.name)
        xml_bytes = b""
        with zipfile.ZipFile(dest, "r") as zf:
            names = [n for n in zf.namelist() if n.lower().endswith(".xml")]
            if not names:
                raise FileNotFoundError("No XML inside CWE zip")
            xml_bytes = zf.read(names[0])

        rows = _parse_cwe_xml(xml_bytes)
        check_cancelled()
        set_progress(phase="cwe_store", label="Storing CWE entries", detail=f"{len(rows):,} weaknesses")
        with db_session() as conn:
            conn.executemany(
                """
                INSERT INTO cwe(cwe_id, name, abstraction, description, url, updated_at)
                VALUES (:cwe_id, :name, :abstraction, :description, :url, :updated_at)
                ON CONFLICT(cwe_id) DO UPDATE SET
                    name=excluded.name,
                    abstraction=excluded.abstraction,
                    description=excluded.description,
                    url=excluded.url,
                    updated_at=excluded.updated_at
                """,
                rows,
            )
            set_meta(conn, "cwe_last_ingest", utc_now())
            count = conn.execute("SELECT COUNT(*) AS n FROM cwe").fetchone()["n"]
            if job_id:
                log_job_finish(conn, job_id, "ok", f"CWE entries {count}")
        set_progress(phase="idle", label="Idle", detail="CWE sync complete")
        return {"cwe_count": int(count), "parsed": len(rows), "skipped": False}
    except JobCancelled:
        with db_session() as conn:
            if job_id:
                log_job_finish(conn, job_id, "cancelled", "CWE sync cancelled")
        raise
    except Exception as exc:
        with db_session() as conn:
            if job_id:
                log_job_finish(conn, job_id, "error", str(exc)[:400])
        raise
