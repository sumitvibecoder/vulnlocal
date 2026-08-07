"""Ingest MITRE CAPEC attack patterns from the official XML download.

Source: https://capec.mitre.org/data/downloads.html
Feed:   https://capec.mitre.org/data/xml/capec_latest.xml
"""

from __future__ import annotations

import logging
import re
from typing import Any

try:
    from defusedxml.ElementTree import fromstring as _xml_fromstring
except ImportError:  # pragma: no cover
    import xml.etree.ElementTree as ET

    def _xml_fromstring(data: bytes | str):
        return ET.fromstring(data)

from .. import config
from ..db import db_session, log_job_finish, log_job_start, set_meta, utc_now
from ..httputil import download_file
from ..progress import check_cancelled, set_progress
from ..settings_store import get_url

log = logging.getLogger("vulnlocal.capec")
_CWE_RE = re.compile(r"CWE-(\d+)", re.I)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _text(el) -> str:
    if el is None:
        return ""
    return "".join(el.itertext()).strip()


def _parse(xml_bytes: bytes) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    root = _xml_fromstring(xml_bytes)
    rows: list[dict[str, Any]] = []
    links: list[tuple[str, str]] = []
    now = utc_now()
    for el in root.iter():
        if _local(el.tag) != "Attack_Pattern":
            continue
        check_cancelled()
        cid = (el.attrib.get("ID") or "").strip()
        if not cid:
            continue
        capec_id = f"CAPEC-{cid}" if not cid.upper().startswith("CAPEC-") else cid.upper()
        name = (el.attrib.get("Name") or "").strip()
        abstraction = (el.attrib.get("Abstraction") or "").strip()
        status = (el.attrib.get("Status") or "").strip()
        desc = ""
        likelihood = ""
        severity = ""
        for child in el:
            tag = _local(child.tag)
            if tag == "Description" and not desc:
                desc = _text(child)[:4000]
            elif tag == "Likelihood_Of_Attack":
                likelihood = _text(child)
            elif tag == "Typical_Severity":
                severity = _text(child)
            elif tag == "Related_Weaknesses":
                for rw in child:
                    if _local(rw.tag) != "Related_Weakness":
                        continue
                    cwe_raw = (rw.attrib.get("CWE_ID") or "").strip()
                    if not cwe_raw:
                        continue
                    m = _CWE_RE.search(cwe_raw) or _CWE_RE.search(f"CWE-{cwe_raw}")
                    if m:
                        links.append((capec_id, f"CWE-{m.group(1)}"))
        rows.append(
            {
                "capec_id": capec_id,
                "name": name,
                "abstraction": abstraction,
                "status": status,
                "description": desc,
                "likelihood": likelihood,
                "severity": severity,
                "detail_url": f"https://capec.mitre.org/data/definitions/{cid}.html",
                "updated_at": now,
            }
        )
    return rows, links


def download_and_ingest() -> dict[str, Any]:
    config.ensure_dirs()
    job_id = None
    with db_session() as conn:
        job_id = log_job_start(conn, "capec_ingest")
    set_progress(phase="capec", label="Downloading CAPEC XML", detail="capec_latest.xml")
    try:
        dest = config.CAPEC_DIR / "capec_latest.xml"
        result = download_file(
            get_url("capec_xml", config.CAPEC_XML_URL),
            dest,
            etag_path=config.CAPEC_DIR / "capec.etag",
            label="CAPEC XML",
        )
        check_cancelled()
        if result.get("skipped"):
            with db_session() as conn:
                n = conn.execute("SELECT COUNT(*) AS n FROM capec").fetchone()["n"]
                from ..sync.feed_health import FEED_MIN_COUNTS

                if int(n or 0) >= FEED_MIN_COUNTS.get("capec", 1):
                    if job_id:
                        log_job_finish(conn, job_id, "ok", f"capec unchanged {n}")
                    set_progress(phase="idle", label="Idle", detail="CAPEC unchanged — skipped")
                    return {"capec": int(n), "upserted": 0, "skipped": True, "skipped_download": True}

        set_progress(phase="capec", label="Parsing CAPEC", detail=dest.name)
        rows, links = _parse(dest.read_bytes())
        with db_session() as conn:
            conn.execute("DELETE FROM capec_cwes")
            conn.execute("DELETE FROM capec")
            conn.executemany(
                """
                INSERT INTO capec(capec_id, name, abstraction, status, description,
                                  likelihood, severity, detail_url, updated_at)
                VALUES (:capec_id, :name, :abstraction, :status, :description,
                        :likelihood, :severity, :detail_url, :updated_at)
                """,
                rows,
            )
            if links:
                conn.executemany(
                    "INSERT OR IGNORE INTO capec_cwes(capec_id, cwe_id) VALUES (?, ?)",
                    links,
                )
            set_meta(conn, "capec_last_ingest", utc_now())
            if job_id:
                log_job_finish(conn, job_id, "ok", f"capec={len(rows)} cwe_links={len(links)}")
        set_progress(phase="idle", label="Idle", detail=f"CAPEC {len(rows):,}")
        return {"capec": len(rows), "cwe_links": len(links), "upserted": len(rows)}
    except Exception as exc:
        log.exception("CAPEC ingest failed")
        with db_session() as conn:
            if job_id:
                log_job_finish(conn, job_id, "error", str(exc))
        raise
