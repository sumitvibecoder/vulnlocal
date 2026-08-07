"""Ingest GitHub PoC indexes from nomi-sec/PoC-in-GitHub and 0xMarcio/cve.

Sources:
  https://github.com/nomi-sec/PoC-in-GitHub
  https://github.com/0xMarcio/cve

Bulk downloads only (GitHub zip / raw text indexes — no HTML scraping).
"""

from __future__ import annotations

import json
import logging
import re
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .. import config
from ..db import db_session, log_job_finish, log_job_start, set_meta, utc_now
from ..httputil import download_file
from ..progress import check_cancelled, set_progress
from ..settings_store import get_url

log = logging.getLogger("vulnlocal.poc_github")
_CVE_FILE_RE = re.compile(r"(CVE-\d{4}-\d+)\.json$", re.I)
_CVE_LINE_RE = re.compile(
    r"^(CVE-\d{4}-\d+)\s*[-–—:]\s*(https?://\S+)",
    re.I,
)
_GITHUB_REPO_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/([^/\s]+)/([^/\s?#]+)(?:\.git)?/?$",
    re.I,
)


def _full_name_from_url(url: str) -> str:
    m = _GITHUB_REPO_RE.match(url.strip().rstrip("/"))
    if not m:
        return ""
    owner, repo = m.group(1), m.group(2)
    if repo.lower().endswith(".git"):
        repo = repo[:-4]
    return f"{owner}/{repo}"


def _parse_nomi_zip(dest: Path, now: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not dest.is_file():
        return rows
    with zipfile.ZipFile(dest, "r") as zf:
        names = [n for n in zf.namelist() if _CVE_FILE_RE.search(n)]
        for i, name in enumerate(names, 1):
            if i % 200 == 0:
                check_cancelled()
                set_progress(
                    phase="poc_github",
                    label="Parsing PoC-in-GitHub",
                    current=i,
                    total=len(names),
                    unit="files",
                    detail=Path(name).name,
                )
            m = _CVE_FILE_RE.search(name)
            if not m:
                continue
            cve_id = m.group(1).upper()
            try:
                data = json.loads(zf.read(name))
            except (json.JSONDecodeError, KeyError, OSError):
                continue
            items = data if isinstance(data, list) else [data]
            for item in items:
                if not isinstance(item, dict):
                    continue
                html_url = str(item.get("html_url") or item.get("url") or "").strip()
                if not html_url:
                    continue
                rows.append(
                    {
                        "cve_id": cve_id,
                        "html_url": html_url,
                        "full_name": str(item.get("full_name") or _full_name_from_url(html_url))[:300],
                        "description": str(item.get("description") or "")[:1000],
                        "stargazers": int(item.get("stargazers_count") or item.get("stargazers") or 0),
                        "language": str(item.get("language") or "")[:80],
                        "updated_at_src": str(item.get("updated_at") or item.get("pushed_at") or ""),
                        "updated_at": now,
                    }
                )
    return rows


def _parse_marcio_index(text: str, now: str) -> list[dict[str, Any]]:
    """Parse 0xMarcio github[-all].txt lines: 'CVE-… - https://github.com/…'."""
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _CVE_LINE_RE.match(line)
        if not m:
            continue
        cve_id = m.group(1).upper()
        if cve_id == "CVE-0000-0000":
            continue
        html_url = m.group(2).strip().rstrip(".,;")
        # Prefer GitHub PoC repos; still accept other http(s) refs as links
        if not html_url.lower().startswith("http"):
            continue
        host = (urlparse(html_url).hostname or "").lower()
        if "github.com" not in host:
            continue
        full_name = _full_name_from_url(html_url)
        rows.append(
            {
                "cve_id": cve_id,
                "html_url": html_url.split("?")[0].rstrip("/"),
                "full_name": full_name[:300],
                "description": "",
                "stargazers": 0,
                "language": "",
                "updated_at_src": "",
                "updated_at": now,
            }
        )
    return rows


def _ingest_marcio(now: str) -> list[dict[str, Any]]:
    """Download 0xMarcio github-all.txt (raw) or fall back to repo zip."""
    config.MARCIO_CVE_DIR.mkdir(parents=True, exist_ok=True)
    txt_url = get_url("marcio_cve_github_index", config.MARCIO_CVE_GITHUB_INDEX_URL)
    txt_dest = config.MARCIO_CVE_DIR / "github-all.txt"
    set_progress(phase="poc_github", label="Downloading 0xMarcio/cve index", detail=txt_url)
    try:
        download_file(
            txt_url,
            txt_dest,
            etag_path=config.MARCIO_CVE_DIR / "github-all.etag",
            label="0xMarcio github-all.txt",
        )
        if txt_dest.is_file() and txt_dest.stat().st_size > 0:
            set_progress(phase="poc_github", label="Parsing 0xMarcio/cve index", detail=txt_dest.name)
            return _parse_marcio_index(txt_dest.read_text(encoding="utf-8", errors="replace"), now)
    except Exception as exc:
        log.warning("0xMarcio raw index failed (%s) — trying zip", exc)

    zip_url = get_url("marcio_cve_zip", config.MARCIO_CVE_ZIP_URL)
    zip_dest = config.MARCIO_CVE_DIR / "0xMarcio-cve.zip"
    set_progress(phase="poc_github", label="Downloading 0xMarcio/cve zip", detail=zip_url)
    download_file(
        zip_url,
        zip_dest,
        etag_path=config.MARCIO_CVE_DIR / "marcio.etag",
        label="0xMarcio/cve zip",
    )
    if not zip_dest.is_file():
        return []
    with zipfile.ZipFile(zip_dest, "r") as zf:
        # Prefer github-all.txt inside the archive
        candidates = [
            n
            for n in zf.namelist()
            if n.replace("\\", "/").endswith("github-all.txt")
            or n.replace("\\", "/").endswith("github.txt")
        ]
        candidates.sort(key=lambda n: (0 if n.endswith("github-all.txt") else 1, n))
        for name in candidates:
            try:
                text = zf.read(name).decode("utf-8", errors="replace")
            except OSError:
                continue
            set_progress(phase="poc_github", label="Parsing 0xMarcio/cve index", detail=Path(name).name)
            rows = _parse_marcio_index(text, now)
            if rows:
                return rows
    return []


def download_and_ingest() -> dict[str, Any]:
    config.ensure_dirs()
    job_id = None
    with db_session() as conn:
        job_id = log_job_start(conn, "poc_github_ingest")
    now = utc_now()
    rows: list[dict[str, Any]] = []
    sources: dict[str, int] = {"nomi": 0, "marcio": 0}
    try:
        # --- nomi-sec/PoC-in-GitHub ---
        set_progress(phase="poc_github", label="Downloading PoC-in-GitHub", detail="archive zip")
        nomi_dest = config.POC_GITHUB_DIR / "PoC-in-GitHub.zip"
        nomi_result = download_file(
            get_url("poc_github_zip", config.POC_GITHUB_ZIP_URL),
            nomi_dest,
            etag_path=config.POC_GITHUB_DIR / "poc.etag",
            label="PoC-in-GitHub zip",
        )
        check_cancelled()
        nomi_rows = _parse_nomi_zip(nomi_dest, now)
        sources["nomi"] = len(nomi_rows)
        rows.extend(nomi_rows)

        # --- 0xMarcio/cve ---
        check_cancelled()
        try:
            marcio_rows = _ingest_marcio(now)
            sources["marcio"] = len(marcio_rows)
            rows.extend(marcio_rows)
        except Exception as exc:
            log.warning("0xMarcio/cve ingest failed — continuing with nomi-sec only: %s", exc)

        # If both sources unchanged and DB already populated, skip rewrite when
        # nomi reported skipped AND we got no new marcio parse… still rewrite if
        # we have rows (keeps merge correct after adding marcio).
        if (
            nomi_result.get("skipped")
            and sources["marcio"] == 0
            and sources["nomi"] == 0
        ):
            with db_session() as conn:
                n = conn.execute("SELECT COUNT(*) AS n FROM poc_github").fetchone()["n"]
                if int(n or 0) > 0:
                    if job_id:
                        log_job_finish(conn, job_id, "ok", f"poc_github unchanged {n}")
                    set_progress(phase="idle", label="Idle", detail="PoC indexes unchanged — skipped")
                    return {
                        "poc_github": int(n),
                        "upserted": 0,
                        "skipped": True,
                        "skipped_download": True,
                        "sources": sources,
                    }

        # Prefer richer nomi-sec rows when duplicate (cve_id, html_url)
        uniq: dict[tuple[str, str], dict[str, Any]] = {}
        for r in rows:
            key = (r["cve_id"], r["html_url"])
            prev = uniq.get(key)
            if prev is None:
                uniq[key] = r
                continue
            # Keep the row with more metadata
            score = (len(r.get("description") or ""), int(r.get("stargazers") or 0), len(r.get("full_name") or ""))
            prev_score = (
                len(prev.get("description") or ""),
                int(prev.get("stargazers") or 0),
                len(prev.get("full_name") or ""),
            )
            if score > prev_score:
                uniq[key] = r
        out = list(uniq.values())

        if not out:
            with db_session() as conn:
                existing = int(conn.execute("SELECT COUNT(*) AS n FROM poc_github").fetchone()["n"])
                if job_id:
                    log_job_finish(conn, job_id, "ok" if existing else "error", f"poc empty kept={existing}")
            return {
                "poc_github": existing,
                "upserted": 0,
                "skipped": True,
                "reason": "empty_parse",
                "kept_existing": True,
                "sources": sources,
            }

        with db_session() as conn:
            conn.execute("DELETE FROM poc_github")
            conn.executemany(
                """
                INSERT INTO poc_github(cve_id, html_url, full_name, description, stargazers,
                                       language, updated_at_src, updated_at)
                VALUES (:cve_id, :html_url, :full_name, :description, :stargazers,
                        :language, :updated_at_src, :updated_at)
                """,
                out,
            )
            set_meta(conn, "poc_github_last_ingest", utc_now())
            if job_id:
                log_job_finish(
                    conn,
                    job_id,
                    "ok",
                    f"poc_github={len(out)} nomi={sources['nomi']} marcio={sources['marcio']}",
                )
        set_progress(phase="idle", label="Idle", detail=f"PoC GitHub {len(out):,}")
        return {"poc_github": len(out), "upserted": len(out), "sources": sources}
    except Exception as exc:
        log.exception("PoC GitHub ingest failed")
        with db_session() as conn:
            if job_id:
                log_job_finish(conn, job_id, "error", str(exc))
        raise
