"""Ingest Nessus plugins from all-2.0.tar.gz and map to CVE / EDB IDs.

Accepts a local archive path (default: project all-2.0.tar.gz) or an optional
licensed download URL configured in Settings.
"""

from __future__ import annotations

import json
import logging
import re
import tarfile
from pathlib import Path
from typing import Any

from .. import config
from ..db import db_session, get_meta, log_job_finish, log_job_start, set_meta, utc_now
from ..httputil import download_file
from ..progress import JobCancelled, check_cancelled, set_progress
from ..settings_store import get_url
from ..sync.skip import archive_signature

log = logging.getLogger("vulnlocal.nessus")

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
_SCRIPT_ID_RE = re.compile(r"script_id\s*\(\s*(\d+)\s*\)")
_SCRIPT_CVE_RE = re.compile(r"script_cve_id\s*\((.*?)\)\s*;", re.S)
_SCRIPT_NAME_RE = re.compile(
    r"script_name\s*\(\s*english\s*:\s*\"((?:\\.|[^\"\\])*)\"\s*\)",
    re.I,
)
_SCRIPT_SUMMARY_RE = re.compile(
    r"script_summary\s*\(\s*english\s*:\s*\"((?:\\.|[^\"\\])*)\"\s*\)",
    re.I,
)
_ATTR_RE = re.compile(
    r"script_set_attribute\s*\(\s*attribute\s*:\s*\"([^\"]+)\"\s*,\s*value\s*:\s*"
    r"(?:\"((?:\\.|[^\"\\])*)\"|string\s*\(\s*\"((?:\\.|[^\"\\])*)\"\s*\))",
    re.I | re.S,
)
_XREF_RE = re.compile(
    r"script_xref\s*\(\s*name\s*:\s*\"([^\"]+)\"\s*,\s*value\s*:\s*\"([^\"]+)\"\s*\)",
    re.I,
)
_VERSION_RE = re.compile(r"script_version\s*\(\s*\"([^\"]+)\"\s*\)")
_FAMILY_RE = re.compile(
    r"script_family\s*\(\s*english\s*:\s*\"((?:\\.|[^\"\\])*)\"\s*\)",
    re.I,
)
_RISK_RE = re.compile(r"script_set_attribute\s*\(\s*attribute\s*:\s*\"risk_factor\"[^;]*value\s*:\s*\"([^\"]+)\"", re.I)


def _unescape(s: str) -> str:
    return (
        (s or "")
        .replace('\\"', '"')
        .replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\\\", "\\")
    )


def _parse_nasl(filename: str, text: str) -> dict[str, Any] | None:
    mid = _SCRIPT_ID_RE.search(text)
    if not mid:
        return None
    plugin_id = mid.group(1)

    cves: list[str] = []
    seen: set[str] = set()
    cm = _SCRIPT_CVE_RE.search(text)
    if cm:
        for c in _CVE_RE.findall(cm.group(1)):
            cid = c.upper()
            if cid not in seen:
                seen.add(cid)
                cves.append(cid)
    # Also catch loose CVE strings in xrefs / body for plugins missing script_cve_id
    if not cves:
        for c in _CVE_RE.findall(text[:12000]):
            cid = c.upper()
            if cid not in seen:
                seen.add(cid)
                cves.append(cid)

    attrs: dict[str, list[str]] = {}
    for m in _ATTR_RE.finditer(text):
        key = (m.group(1) or "").strip().lower()
        val = _unescape(m.group(2) or m.group(3) or "").strip()
        if not key or not val:
            continue
        attrs.setdefault(key, []).append(val)

    xrefs: list[dict[str, str]] = []
    edbs: list[str] = []
    for m in _XREF_RE.finditer(text):
        name = (m.group(1) or "").strip()
        value = (m.group(2) or "").strip()
        if not name or not value:
            continue
        xrefs.append({"name": name, "value": value})
        low = name.lower()
        if low in {"edb-id", "edb", "exploit-db"}:
            edbs.append(value)
        if low == "cve" and value.upper().startswith("CVE-"):
            cid = value.upper()
            if cid not in seen:
                seen.add(cid)
                cves.append(cid)

    nm = _SCRIPT_NAME_RE.search(text)
    sm = _SCRIPT_SUMMARY_RE.search(text)
    fm = _FAMILY_RE.search(text)
    vm = _VERSION_RE.search(text)
    rm = _RISK_RE.search(text)

    name = _unescape(nm.group(1)) if nm else filename
    synopsis = (attrs.get("synopsis") or [""])[0][:2000]
    description = (attrs.get("description") or [""])[0][:8000]
    solution = (attrs.get("solution") or [""])[0][:4000]
    see_also = attrs.get("see_also") or []

    return {
        "plugin_id": plugin_id,
        "name": name[:500],
        "summary": _unescape(sm.group(1))[:1000] if sm else "",
        "synopsis": synopsis,
        "description": description,
        "solution": solution,
        "family": _unescape(fm.group(1))[:200] if fm else "",
        "risk_factor": (rm.group(1) if rm else "")[:80],
        "filename": filename,
        "version": vm.group(1) if vm else "",
        "see_also_json": json.dumps(see_also[:40]),
        "xrefs_json": json.dumps(xrefs[:80]),
        "edb_ids_json": json.dumps(edbs[:40]),
        "detail_url": f"{config.NESSUS_PLUGIN_DETAIL_BASE}/{plugin_id}",
        "cves": cves,
        "raw_json": json.dumps(
            {"filename": filename, "cves": cves[:20], "edbs": edbs[:20]}
        )[:20_000],
        "updated_at": utc_now(),
    }


def _resolve_archive() -> Path:
    path_setting = get_url("nessus_plugins_path", str(config.NESSUS_PLUGINS_DEFAULT_PATH))
    path = Path(path_setting).expanduser()
    if path.is_file():
        return path
    # Fallback to project root default
    if config.NESSUS_PLUGINS_DEFAULT_PATH.is_file():
        return config.NESSUS_PLUGINS_DEFAULT_PATH
    return path


def download_and_ingest() -> dict[str, Any]:
    config.ensure_dirs()
    job_id = None
    with db_session() as conn:
        job_id = log_job_start(conn, "nessus_ingest")

    try:
        archive = _resolve_archive()
        url = get_url("nessus_plugins_url", "").strip()
        downloaded = False
        if (not archive.is_file()) and url:
            set_progress(phase="nessus", label="Downloading Nessus plugins", detail="all-2.0.tar.gz")
            dest = config.NESSUS_PLUGINS_DIR / "all-2.0.tar.gz"
            download_file(url, dest, etag_path=config.NESSUS_PLUGINS_DIR / "nessus.etag", label="Nessus all-2.0")
            archive = dest
            downloaded = True
        if not archive.is_file():
            raise RuntimeError(
                "Nessus all-2.0.tar.gz not found. Place it at the project root "
                "or set nessus_plugins_path / nessus_plugins_url in Settings."
            )

        sig = archive_signature(archive)
        with db_session() as conn:
            prev_sig = get_meta(conn, "nessus_archive_sig") or ""
            pcount = conn.execute("SELECT COUNT(*) AS n FROM nessus_plugins").fetchone()["n"]
        if (not downloaded) and prev_sig == sig and int(pcount or 0) > 0:
            set_progress(phase="idle", label="Idle", detail="Nessus archive unchanged — skipped")
            with db_session() as conn:
                if job_id:
                    log_job_finish(conn, job_id, "ok", f"nessus unchanged {pcount}")
            return {
                "nessus_plugins": int(pcount),
                "skipped": True,
                "archive": str(archive),
            }

        set_progress(phase="nessus", label="Parsing Nessus plugins", detail=archive.name)
        rows: list[dict[str, Any]] = []
        link_rows: list[tuple[str, str]] = []
        parsed = 0
        with_cve = 0

        with tarfile.open(archive, "r:gz") as tf:
            members = [m for m in tf.getmembers() if m.isfile() and m.name.lower().endswith(".nasl")]
            total = len(members)
            for i, member in enumerate(members, 1):
                if i % 500 == 0 or i == total:
                    check_cancelled()
                    set_progress(
                        phase="nessus",
                        label="Parsing Nessus plugins",
                        current=i,
                        total=total,
                        unit="plugins",
                        detail=Path(member.name).name,
                    )
                fh = tf.extractfile(member)
                if fh is None:
                    continue
                try:
                    # NASL headers with CVE refs are near the top; cap read size
                    text = fh.read(65536).decode("utf-8", "replace")
                except Exception:
                    continue
                plugin = _parse_nasl(Path(member.name).name, text)
                if not plugin:
                    continue
                parsed += 1
                cves = plugin.pop("cves", [])
                if cves:
                    with_cve += 1
                rows.append(plugin)
                for cid in cves:
                    link_rows.append((plugin["plugin_id"], cid))

                # Flush batches to keep memory bounded
                if len(rows) >= 2000:
                    _flush(rows, link_rows)
                    rows = []
                    link_rows = []

        if rows:
            _flush(rows, link_rows)

        with db_session() as conn:
            set_meta(conn, "nessus_last_ingest", utc_now())
            set_meta(conn, "nessus_archive_path", str(archive))
            set_meta(conn, "nessus_archive_sig", sig)
            pcount = conn.execute("SELECT COUNT(*) AS n FROM nessus_plugins").fetchone()["n"]
            lcount = conn.execute("SELECT COUNT(*) AS n FROM nessus_plugin_cves").fetchone()["n"]
            if job_id:
                log_job_finish(conn, job_id, "ok", f"nessus={pcount} links={lcount}")

        set_progress(phase="idle", label="Idle", detail="Nessus plugins sync complete")
        return {
            "nessus_plugins": int(pcount),
            "cve_links": int(lcount),
            "parsed_plugins": parsed,
            "with_cve": with_cve,
            "archive": str(archive),
            "downloaded": downloaded,
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


def _flush(rows: list[dict[str, Any]], link_rows: list[tuple[str, str]]) -> None:
    if not rows:
        return
    with db_session() as conn:
        conn.executemany(
            """
            INSERT INTO nessus_plugins(
                plugin_id, name, summary, synopsis, description, solution, family,
                risk_factor, filename, version, see_also_json, xrefs_json, edb_ids_json,
                detail_url, raw_json, updated_at
            ) VALUES (
                :plugin_id, :name, :summary, :synopsis, :description, :solution, :family,
                :risk_factor, :filename, :version, :see_also_json, :xrefs_json, :edb_ids_json,
                :detail_url, :raw_json, :updated_at
            )
            ON CONFLICT(plugin_id) DO UPDATE SET
                name=excluded.name,
                summary=excluded.summary,
                synopsis=excluded.synopsis,
                description=excluded.description,
                solution=excluded.solution,
                family=excluded.family,
                risk_factor=excluded.risk_factor,
                filename=excluded.filename,
                version=excluded.version,
                see_also_json=excluded.see_also_json,
                xrefs_json=excluded.xrefs_json,
                edb_ids_json=excluded.edb_ids_json,
                detail_url=excluded.detail_url,
                raw_json=excluded.raw_json,
                updated_at=excluded.updated_at
            """,
            rows,
        )
        if link_rows:
            ids = list({r[0] for r in link_rows})
            for i in range(0, len(ids), 400):
                chunk = ids[i : i + 400]
                placeholders = ",".join("?" * len(chunk))
                conn.execute(
                    f"DELETE FROM nessus_plugin_cves WHERE plugin_id IN ({placeholders})",
                    chunk,
                )
            conn.executemany(
                "INSERT OR IGNORE INTO nessus_plugin_cves(plugin_id, cve_id) VALUES (?, ?)",
                link_rows,
            )


def get_nessus_for_cve(cve_id: str, *, limit: int = 40) -> list[dict[str, Any]]:
    cve_id = (cve_id or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return []
    limit = max(1, min(int(limit), 100))
    with db_session() as conn:
        rows = conn.execute(
            """
            SELECT p.plugin_id, p.name, p.summary, p.synopsis, p.solution, p.family,
                   p.risk_factor, p.filename, p.detail_url, p.see_also_json, p.edb_ids_json
            FROM nessus_plugins p
            JOIN nessus_plugin_cves pc ON pc.plugin_id = p.plugin_id
            WHERE pc.cve_id = ?
            ORDER BY CAST(p.plugin_id AS INTEGER) DESC
            LIMIT ?
            """,
            (cve_id, limit),
        ).fetchall()
    out = []
    for r in rows:
        item = dict(r)
        try:
            item["see_also"] = json.loads(item.pop("see_also_json") or "[]")
        except json.JSONDecodeError:
            item["see_also"] = []
        try:
            item["edb_ids"] = json.loads(item.pop("edb_ids_json") or "[]")
        except json.JSONDecodeError:
            item["edb_ids"] = []
        out.append(item)
    return out
