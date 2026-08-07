"""Ingest Rapid7 Metasploit Framework modules and map to CVE / EDB IDs.

Source: https://github.com/rapid7/metasploit-framework
Bulk zip only (modules: auxiliary, encoders, evasion, exploits, nops, payloads, post).
"""

from __future__ import annotations

import json
import logging
import re
import zipfile
from pathlib import Path
from typing import Any

from .. import config
from ..db import db_session, log_job_finish, log_job_start, set_meta, utc_now
from ..httputil import download_file
from ..progress import JobCancelled, check_cancelled, set_progress
from ..settings_store import get_url

log = logging.getLogger("vulnlocal.metasploit")

_MODULE_TYPES = (
    "auxiliary",
    "encoders",
    "evasion",
    "exploits",
    "nops",
    "payloads",
    "post",
)
_CVE_REF_RE = re.compile(r"\['CVE'\s*,\s*'([^']+)'\]", re.I)
_EDB_REF_RE = re.compile(r"\['EDB'\s*,\s*'([^']+)'\]", re.I)
_NAME_RE = re.compile(r"'Name'\s*=>\s*(?:%q\{([^}]*)\}|'((?:\\'|[^'])*)'|\"((?:\\\"|[^\"])*)\")", re.S)
_DESC_RE = re.compile(
    r"'Description'\s*=>\s*%q\{(.*?)\}",
    re.S,
)
_RANK_RE = re.compile(r"Rank\s*=\s*(\w+)")


def _normalize_cve(raw: str) -> str | None:
    raw = (raw or "").strip().upper()
    if not raw:
        return None
    if raw.startswith("CVE-"):
        return raw
    if re.fullmatch(r"\d{4}-\d{4,}", raw):
        return f"CVE-{raw}"
    return None


def _parse_module(path_in_zip: str, text: str) -> dict[str, Any] | None:
    # modules/<type>/.../<name>.rb
    parts = Path(path_in_zip.replace("\\", "/")).parts
    try:
        idx = parts.index("modules")
    except ValueError:
        return None
    if idx + 2 >= len(parts):
        return None
    module_type = parts[idx + 1]
    if module_type not in _MODULE_TYPES:
        return None
    rel = "/".join(parts[idx + 1 :])
    if not rel.endswith(".rb"):
        return None
    fullname = rel[:-3].replace("\\", "/")

    cves: list[str] = []
    seen: set[str] = set()
    for m in _CVE_REF_RE.finditer(text):
        cid = _normalize_cve(m.group(1))
        if cid and cid not in seen:
            seen.add(cid)
            cves.append(cid)

    edbs = []
    for m in _EDB_REF_RE.finditer(text):
        edb = (m.group(1) or "").strip()
        if edb and edb not in edbs:
            edbs.append(edb)

    name = fullname.rsplit("/", 1)[-1]
    nm = _NAME_RE.search(text)
    if nm:
        name = next((g for g in nm.groups() if g), name) or name
    desc = ""
    dm = _DESC_RE.search(text)
    if dm:
        desc = (dm.group(1) or "").strip()[:4000]
    rank = ""
    rm = _RANK_RE.search(text)
    if rm:
        rank = rm.group(1)

    detail_url = f"{config.METASPLOIT_DETAIL_BASE}/modules/{rel}"
    return {
        "fullname": fullname,
        "name": name.strip()[:500],
        "module_type": module_type,
        "rank": rank,
        "description": desc,
        "platform": "",
        "arch": "",
        "path": f"modules/{rel}",
        "detail_url": detail_url,
        "edb_ids_json": json.dumps(edbs),
        "cves": cves,
        "raw_json": json.dumps({"path": rel, "cves": cves, "edbs": edbs})[:20_000],
        "updated_at": utc_now(),
    }


def download_and_ingest() -> dict[str, Any]:
    config.ensure_dirs()
    job_id = None
    with db_session() as conn:
        job_id = log_job_start(conn, "metasploit_ingest")

    set_progress(phase="metasploit", label="Downloading Metasploit modules", detail="GitHub zip")
    try:
        dest = config.METASPLOIT_DIR / "metasploit-framework-master.zip"
        urls = [
            get_url("metasploit_zip", config.METASPLOIT_ZIP_URLS[0]),
            *config.METASPLOIT_ZIP_URLS,
        ]
        # dedupe
        seen_urls: list[str] = []
        for u in urls:
            u = (u or "").strip()
            if u and u not in seen_urls:
                seen_urls.append(u)

        last_err: Exception | None = None
        result = None
        for url in seen_urls:
            try:
                result = download_file(
                    url,
                    dest,
                    etag_path=config.METASPLOIT_DIR / "metasploit.etag",
                    label="metasploit-framework zip",
                )
                break
            except Exception as exc:
                last_err = exc
                log.warning("metasploit zip failed from %s: %s", url, exc)
        if result is None:
            raise RuntimeError(f"metasploit-framework download failed: {last_err}")

        if result.get("skipped"):
            with db_session() as conn:
                mcount = conn.execute("SELECT COUNT(*) AS n FROM metasploit_modules").fetchone()["n"]
                lcount = conn.execute("SELECT COUNT(*) AS n FROM metasploit_module_cves").fetchone()["n"]
                from ..sync.feed_health import FEED_MIN_COUNTS

                if int(mcount or 0) >= FEED_MIN_COUNTS.get("metasploit_modules", 1):
                    if job_id:
                        log_job_finish(conn, job_id, "ok", f"metasploit unchanged (etag) {mcount}")
                    set_progress(phase="idle", label="Idle", detail="Metasploit unchanged — skipped")
                    return {
                        "metasploit_modules": int(mcount),
                        "cve_links": int(lcount),
                        "parsed_modules": 0,
                        "skipped": True,
                        "skipped_download": True,
                    }

        check_cancelled()
        set_progress(phase="metasploit", label="Parsing Metasploit modules", detail=dest.name)

        rows: list[dict[str, Any]] = []
        link_rows: list[tuple[str, str]] = []
        parsed = 0
        with zipfile.ZipFile(dest, "r") as zf:
            members = [n for n in zf.namelist() if "/modules/" in n.replace("\\", "/") and n.endswith(".rb")]
            total = len(members)
            for i, name in enumerate(members, 1):
                if i % 250 == 0 or i == total:
                    check_cancelled()
                    set_progress(
                        phase="metasploit",
                        label="Parsing Metasploit modules",
                        current=i,
                        total=total,
                        unit="files",
                        detail=name.rsplit("/", 1)[-1],
                    )
                # Only under modules/<type>/
                norm = name.replace("\\", "/")
                if not any(f"/modules/{t}/" in norm for t in _MODULE_TYPES):
                    continue
                try:
                    text = zf.read(name).decode("utf-8", "replace")
                except Exception:
                    continue
                # Strip zip root prefix: metasploit-framework-master/modules/...
                rel = norm
                if "/modules/" in norm:
                    rel = "modules/" + norm.split("/modules/", 1)[1]
                mod = _parse_module(rel, text)
                if not mod:
                    continue
                parsed += 1
                cves = mod.pop("cves", [])
                rows.append(mod)
                for cid in cves:
                    link_rows.append((mod["fullname"], cid))

        with db_session() as conn:
            if rows:
                conn.executemany(
                    """
                    INSERT INTO metasploit_modules(
                        fullname, name, module_type, rank, description, platform, arch,
                        path, detail_url, edb_ids_json, raw_json, updated_at
                    ) VALUES (
                        :fullname, :name, :module_type, :rank, :description, :platform, :arch,
                        :path, :detail_url, :edb_ids_json, :raw_json, :updated_at
                    )
                    ON CONFLICT(fullname) DO UPDATE SET
                        name=excluded.name,
                        module_type=excluded.module_type,
                        rank=excluded.rank,
                        description=excluded.description,
                        platform=excluded.platform,
                        arch=excluded.arch,
                        path=excluded.path,
                        detail_url=excluded.detail_url,
                        edb_ids_json=excluded.edb_ids_json,
                        raw_json=excluded.raw_json,
                        updated_at=excluded.updated_at
                    """,
                    rows,
                )
            if link_rows:
                # Replace links for upserted modules
                fullnames = list({r[0] for r in link_rows})
                for i in range(0, len(fullnames), 400):
                    chunk = fullnames[i : i + 400]
                    placeholders = ",".join("?" * len(chunk))
                    conn.execute(
                        f"DELETE FROM metasploit_module_cves WHERE fullname IN ({placeholders})",
                        chunk,
                    )
                conn.executemany(
                    "INSERT OR IGNORE INTO metasploit_module_cves(fullname, cve_id) VALUES (?, ?)",
                    link_rows,
                )
            set_meta(conn, "metasploit_last_ingest", utc_now())
            mcount = conn.execute("SELECT COUNT(*) AS n FROM metasploit_modules").fetchone()["n"]
            lcount = conn.execute("SELECT COUNT(*) AS n FROM metasploit_module_cves").fetchone()["n"]
            if job_id:
                log_job_finish(conn, job_id, "ok", f"metasploit={mcount} links={lcount}")

        set_progress(phase="idle", label="Idle", detail="Metasploit sync complete")
        return {
            "metasploit_modules": int(mcount),
            "cve_links": int(lcount),
            "parsed_modules": parsed,
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


def get_metasploit_for_cve(cve_id: str, *, limit: int = 40) -> list[dict[str, Any]]:
    cve_id = (cve_id or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return []
    limit = max(1, min(int(limit), 100))
    with db_session() as conn:
        rows = conn.execute(
            """
            SELECT m.fullname, m.name, m.module_type, m.rank, m.description,
                   m.path, m.detail_url, m.edb_ids_json
            FROM metasploit_modules m
            JOIN metasploit_module_cves mc ON mc.fullname = m.fullname
            WHERE mc.cve_id = ?
            ORDER BY
                CASE m.module_type
                    WHEN 'exploits' THEN 0
                    WHEN 'auxiliary' THEN 1
                    WHEN 'post' THEN 2
                    WHEN 'payloads' THEN 3
                    ELSE 4
                END,
                m.fullname
            LIMIT ?
            """,
            (cve_id, limit),
        ).fetchall()
    out = []
    for r in rows:
        item = dict(r)
        try:
            item["edb_ids"] = json.loads(item.pop("edb_ids_json") or "[]")
        except json.JSONDecodeError:
            item["edb_ids"] = []
        out.append(item)
    return out
