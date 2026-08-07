"""Ingest ProjectDiscovery nuclei-templates and map templates → CVE IDs.

Source: https://github.com/projectdiscovery/nuclei-templates
Bulk zip only (no HTML scraping).

Only stores templates that carry CVE and/or exploit signal
(so Manage “Nuclei templates” reflects correlatable data, not every
misc/tech/fingerprint YAML in the zip).
"""

from __future__ import annotations

import json
import logging
import re
import zipfile
from pathlib import Path
from typing import Any

import yaml

from .. import config
from ..db import db_session, log_job_finish, log_job_start, set_meta, utc_now
from ..httputil import download_file
from ..progress import JobCancelled, check_cancelled, set_progress
from ..settings_store import get_url

log = logging.getLogger("vulnlocal.nuclei")

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)

# Non-template / support YAML that should not inflate the Manage count.
_SKIP_PATH_PARTS = (
    "/.github/",
    "/helpers/",
    "/profiles/",
)


def _as_list(val: Any) -> list[Any]:
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]


def _should_skip_path(path_in_zip: str) -> bool:
    low = path_in_zip.replace("\\", "/").lower()
    if low.endswith("/"):
        return True
    # Root tooling / stats YAML (not scan templates)
    base = Path(low).name
    if base in {
        ".pre-commit-config.yml",
        ".yamllint",
        ".nuclei-ignore",
        ".review-bot",
        ".new-additions",
    }:
        return True
    return any(part in low for part in _SKIP_PATH_PARTS)


def _is_cve_or_exploit(info: dict[str, Any], rel_path: str, cves: list[str]) -> bool:
    """Keep only templates useful for CVE/exploit correlation."""
    if cves:
        return True
    low = (rel_path or "").replace("\\", "/").lower()
    if "/cves/" in low or "/exploits/" in low or "/exploit/" in low:
        return True
    tags = _as_list(info.get("tags"))
    for tag in tags:
        t = str(tag or "").strip().lower()
        if not t:
            continue
        if t in {"cve", "exploit", "kev"}:
            return True
        if t.startswith("cve-") or t.startswith("cve20") or "exploit" in t:
            return True
    name = str(info.get("name") or "")
    if _CVE_RE.search(name):
        return True
    return False


def _extract_cves(info: dict[str, Any], text_blob: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()

    def add(cid: str) -> None:
        cid = cid.strip().upper()
        if cid.startswith("CVE-") and cid not in seen:
            seen.add(cid)
            found.append(cid)

    classification = info.get("classification") or {}
    if isinstance(classification, dict):
        for key in ("cve-id", "cve_id", "cve"):
            for item in _as_list(classification.get(key)):
                if isinstance(item, str):
                    for m in _CVE_RE.finditer(item):
                        add(m.group(0))
                elif isinstance(item, (list, tuple)):
                    for sub in item:
                        if isinstance(sub, str):
                            for m in _CVE_RE.finditer(sub):
                                add(m.group(0))
    metadata = info.get("metadata") or {}
    if isinstance(metadata, dict):
        for key in ("cve", "cve-id", "cve_id"):
            for item in _as_list(metadata.get(key)):
                if isinstance(item, str):
                    for m in _CVE_RE.finditer(item):
                        add(m.group(0))
    for tag in _as_list(info.get("tags")):
        if isinstance(tag, str):
            for m in _CVE_RE.finditer(tag):
                add(m.group(0))
            # tags often use "cve2021-44228" style without hyphen after CVE year glue
            compact = tag.replace("_", "-")
            for m in _CVE_RE.finditer(compact):
                add(m.group(0))
    for m in _CVE_RE.finditer(text_blob or ""):
        add(m.group(0))
    for ref in _as_list(info.get("reference")):
        if isinstance(ref, str):
            for m in _CVE_RE.finditer(ref):
                add(m.group(0))
    return found


def _parse_template(path_in_zip: str, raw: bytes) -> dict[str, Any] | None:
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return None
    # Skip huge non-template blobs
    if len(text) > 2_000_000:
        return None
    try:
        data = yaml.safe_load(text)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    info = data.get("info") if isinstance(data.get("info"), dict) else {}
    template_id = str(data.get("id") or "").strip()
    if not template_id:
        return None
    # Require info block — distinguishes real nuclei templates from misc YAML
    if not info:
        return None
    # Normalize path relative to repo root (strip archive prefix)
    parts = Path(path_in_zip.replace("\\", "/")).parts
    rel = "/".join(parts[1:]) if parts else path_in_zip
    cves = _extract_cves(info, text)
    if not _is_cve_or_exploit(info, rel, cves):
        return None
    tags = info.get("tags")
    if isinstance(tags, list):
        tags_s = ",".join(str(t) for t in tags)
    else:
        tags_s = str(tags or "")
    authors = info.get("author")
    if isinstance(authors, list):
        author_s = ", ".join(str(a) for a in authors)
    else:
        author_s = str(authors or "")
    return {
        "template_id": template_id,
        "name": str(info.get("name") or template_id),
        "severity": str(info.get("severity") or ""),
        "author": author_s,
        "description": str(info.get("description") or "")[:4000],
        "tags": tags_s[:2000],
        "path": rel,
        "detail_url": f"{config.NUCLEI_DETAIL_BASE}/{rel}",
        "raw_json": json.dumps(
            {
                "id": template_id,
                "info": {
                    "name": info.get("name"),
                    "severity": info.get("severity"),
                    "tags": info.get("tags"),
                    "classification": info.get("classification"),
                },
                "path": rel,
            }
        )[:100_000],
        "updated_at": utc_now(),
        "_cves": cves,
    }


def _flush_batch(
    templates: list[dict[str, Any]],
    links: list[tuple[str, str]],
    *,
    seen_ids: set[str],
) -> tuple[int, int]:
    if not templates and not links:
        return 0, 0
    with db_session() as conn:
        if templates:
            conn.executemany(
                """
                INSERT INTO nuclei_templates(
                    template_id, name, severity, author, description, tags,
                    path, detail_url, raw_json, updated_at
                ) VALUES (
                    :template_id, :name, :severity, :author, :description, :tags,
                    :path, :detail_url, :raw_json, :updated_at
                )
                ON CONFLICT(template_id) DO UPDATE SET
                    name=excluded.name,
                    severity=excluded.severity,
                    author=excluded.author,
                    description=excluded.description,
                    tags=excluded.tags,
                    path=excluded.path,
                    detail_url=excluded.detail_url,
                    raw_json=excluded.raw_json,
                    updated_at=excluded.updated_at
                """,
                templates,
            )
            for row in templates:
                seen_ids.add(row["template_id"])
        if links:
            tids = list({t for t, _ in links})
            for i in range(0, len(tids), 400):
                chunk = tids[i : i + 400]
                placeholders = ",".join("?" * len(chunk))
                conn.execute(
                    f"DELETE FROM nuclei_template_cves WHERE template_id IN ({placeholders})",
                    chunk,
                )
            conn.executemany(
                "INSERT OR IGNORE INTO nuclei_template_cves(template_id, cve_id) VALUES (?, ?)",
                links,
            )
    return len(templates), len(links)


def download_and_ingest() -> dict[str, Any]:
    config.ensure_dirs()
    job_id = None
    with db_session() as conn:
        job_id = log_job_start(conn, "nuclei_ingest")

    set_progress(phase="nuclei", label="Downloading nuclei-templates", detail="GitHub zip")
    try:
        dest = config.NUCLEI_DIR / "nuclei-templates-main.zip"
        etag_path = config.NUCLEI_DIR / "nuclei.etag"
        with db_session() as conn:
            existing_n = int(conn.execute("SELECT COUNT(*) AS n FROM nuclei_templates").fetchone()["n"])
            linked_n = int(
                conn.execute(
                    "SELECT COUNT(DISTINCT template_id) AS n FROM nuclei_template_cves"
                ).fetchone()["n"]
            )
        from ..sync.feed_health import NUCLEI_ALL_TEMPLATES_CEILING

        force_parse = bool(
            (existing_n > 0 and linked_n < int(existing_n * 0.85))
            or existing_n > NUCLEI_ALL_TEMPLATES_CEILING
        )
        if force_parse and etag_path.is_file():
            try:
                etag_path.unlink()
            except OSError:
                pass

        last_err = None
        urls = []
        preferred = get_url("nuclei_templates_zip", config.NUCLEI_TEMPLATES_ZIP_URLS[0])
        for url in [preferred, *config.NUCLEI_TEMPLATES_ZIP_URLS]:
            u = (url or "").strip()
            if u and u not in urls:
                urls.append(u)
        result = None
        for url in urls:
            try:
                result = download_file(
                    url,
                    dest,
                    etag_path=etag_path,
                    label="nuclei-templates zip",
                )
                if dest.is_file() and dest.stat().st_size > 1000:
                    break
            except Exception as exc:
                last_err = exc
                log.warning("nuclei zip failed from %s: %s", url, exc)
        if not dest.is_file() or dest.stat().st_size < 1000:
            raise RuntimeError(f"nuclei-templates download failed: {last_err}")

        if result and result.get("skipped") and not force_parse:
            with db_session() as conn:
                tcount = conn.execute("SELECT COUNT(*) AS n FROM nuclei_templates").fetchone()["n"]
                lcount = conn.execute("SELECT COUNT(*) AS n FROM nuclei_template_cves").fetchone()["n"]
                if int(tcount or 0) > 0:
                    if job_id:
                        log_job_finish(conn, job_id, "ok", f"nuclei unchanged (etag) templates={tcount}")
                    set_progress(phase="idle", label="Idle", detail="Nuclei unchanged — skipped")
                    return {
                        "nuclei_templates": int(tcount),
                        "cve_links": int(lcount),
                        "parsed_templates": 0,
                        "skipped": True,
                    }

        check_cancelled()
        set_progress(phase="nuclei", label="Parsing nuclei CVE/exploit templates", detail=dest.name)
        templates: list[dict[str, Any]] = []
        links: list[tuple[str, str]] = []
        seen_ids: set[str] = set()
        parsed = 0
        yaml_files = 0
        skipped_paths = 0
        skipped_unrelated = 0
        now = utc_now()

        with zipfile.ZipFile(dest, "r") as zf:
            names = [n for n in zf.namelist() if n.lower().endswith((".yaml", ".yml"))]
            total = len(names)
            for i, name in enumerate(names, start=1):
                if i % 200 == 0:
                    check_cancelled()
                    set_progress(
                        phase="nuclei",
                        label="Parsing nuclei CVE/exploit templates",
                        detail=f"{i}/{total} stored={parsed:,}",
                        current=i,
                        total=total,
                    )
                    if len(templates) >= 800:
                        n_t, _ = _flush_batch(templates, links, seen_ids=seen_ids)
                        parsed += n_t
                        templates.clear()
                        links.clear()
                if _should_skip_path(name):
                    skipped_paths += 1
                    continue
                yaml_files += 1
                try:
                    raw = zf.read(name)
                except Exception:
                    continue
                row = _parse_template(name, raw)
                if not row:
                    # Invalid YAML, missing info, or not CVE/exploit-related
                    skipped_unrelated += 1
                    continue
                cves = row.pop("_cves", [])
                row["updated_at"] = now
                templates.append(row)
                for cve_id in cves:
                    links.append((row["template_id"], cve_id))

        n_t, _ = _flush_batch(templates, links, seen_ids=seen_ids)
        parsed += n_t

        with db_session() as conn:
            # Remove templates absent from this successful full parse (drops non-CVE noise).
            if seen_ids:
                conn.execute("DELETE FROM nuclei_templates WHERE updated_at != ?", (now,))
                conn.execute(
                    """
                    DELETE FROM nuclei_template_cves
                    WHERE template_id NOT IN (SELECT template_id FROM nuclei_templates)
                    """
                )
            set_meta(conn, "nuclei_last_ingest", utc_now())
            tcount = int(conn.execute("SELECT COUNT(*) AS n FROM nuclei_templates").fetchone()["n"])
            lcount = int(conn.execute("SELECT COUNT(*) AS n FROM nuclei_template_cves").fetchone()["n"])
            if job_id:
                log_job_finish(
                    conn,
                    job_id,
                    "ok",
                    f"templates={tcount} links={lcount} yaml={yaml_files} "
                    f"skipped_paths={skipped_paths} skipped_unrelated={skipped_unrelated}",
                )
        set_progress(phase="idle", label="Idle", detail=f"Nuclei CVE/exploit templates {tcount:,}")
        return {
            "nuclei_templates": tcount,
            "cve_links": lcount,
            "parsed_templates": parsed,
            "yaml_considered": yaml_files,
            "skipped_paths": skipped_paths,
            "skipped_unrelated": skipped_unrelated,
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


def get_nuclei_for_cve(cve_id: str, *, limit: int = 40) -> list[dict[str, Any]]:
    cve_id = (cve_id or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return []
    limit = max(1, min(int(limit), 100))
    with db_session() as conn:
        rows = conn.execute(
            """
            SELECT t.template_id, t.name, t.severity, t.author, t.description,
                   t.tags, t.path, t.detail_url
            FROM nuclei_templates t
            JOIN nuclei_template_cves tc ON tc.template_id = t.template_id
            WHERE tc.cve_id = ?
            ORDER BY
                CASE lower(COALESCE(t.severity,''))
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3
                    ELSE 4
                END,
                t.template_id
            LIMIT ?
            """,
            (cve_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]
