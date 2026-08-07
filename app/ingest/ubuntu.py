"""Ingest Ubuntu CVE data from official Canonical / UCT GitHub bulk archives.

Primary (Ubuntu CVE Tracker text files — Launchpad UCT mirrors):
  https://github.com/kees/ubuntu-cve-tracker
  https://github.com/nottrobin/ubuntu-cve-tracker

Enrichment (OpenVEX + VCF image CSV reports):
  https://github.com/canonical/soss-vulnerability-data
  https://github.com/canonical/vcf-ubuntu-vulnerabilities

Downloads use GitHub codeload zip mirrors only (no HTML scraping, no
ubuntu.com/security/cves.json pagination).
"""

from __future__ import annotations

import csv
import io
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

log = logging.getLogger("vulnlocal.ubuntu")

_CVE_NAME_RE = re.compile(r"(CVE-\d{4}-\d{4,})", re.I)
_UCT_MULTILINE = frozenset(
    {
        "Description",
        "Ubuntu-Description",
        "References",
        "Notes",
        "Bugs",
        "Mitigation",
        "CVSS",
    }
)
_UCT_SCALAR = frozenset(
    {
        "Candidate",
        "PublicDate",
        "PublicDateAtUSN",
        "Priority",
        "Assigned-to",
        "Discovered-by",
    }
)

_UPSERT_SQL = """
INSERT INTO ubuntu_cves(cve_id, title, description, priority, published,
                        packages_json, notices_json, detail_url, updated_at)
VALUES (:cve_id, :title, :description, :priority, :published,
        :packages_json, :notices_json, :detail_url, :updated_at)
ON CONFLICT(cve_id) DO UPDATE SET
    title=COALESCE(NULLIF(excluded.title, ''), ubuntu_cves.title),
    description=CASE
        WHEN length(COALESCE(excluded.description, '')) >= length(COALESCE(ubuntu_cves.description, ''))
        THEN excluded.description ELSE ubuntu_cves.description END,
    priority=COALESCE(NULLIF(excluded.priority, ''), ubuntu_cves.priority),
    published=COALESCE(NULLIF(excluded.published, ''), ubuntu_cves.published),
    packages_json=excluded.packages_json,
    notices_json=excluded.notices_json,
    detail_url=COALESCE(NULLIF(excluded.detail_url, ''), ubuntu_cves.detail_url),
    updated_at=excluded.updated_at
"""


def _uct_urls() -> list[str]:
    raw = get_url("ubuntu_uct_zips", ",".join(config.UBUNTU_UCT_ZIP_URLS))
    return [u.strip() for u in raw.split(",") if u.strip()]


def _parse_uct_text(text: str) -> dict[str, Any] | None:
    """Parse one Ubuntu CVE Tracker text file into fields + package statuses."""
    fields: dict[str, str] = {}
    packages: list[dict[str, str]] = []
    current: str | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("#"):
            continue
        # Field header: "Key:" or "Key: value" at column 0 (not indented package notes)
        if current and (line.startswith(" ") or line.startswith("\t")):
            fields[current] = (fields.get(current, "") + " " + line.strip()).strip()
            continue
        if ":" in line:
            key, _, rest = line.partition(":")
            key = key.strip()
            rest = rest.strip()
            if key in _UCT_SCALAR:
                fields[key] = rest
                current = None
                continue
            if key in _UCT_MULTILINE:
                fields[key] = rest
                current = key
                continue
            # release_package: status  (e.g. jammy_openssl: released (3.0.2-0ubuntu1.12))
            if "_" in key and not key.startswith("http"):
                packages.append({"entry": key, "status": rest})
                current = None
                continue
        if current in _UCT_MULTILINE:
            fields[current] = (fields.get(current, "") + " " + line.strip()).strip()
    cve_id = (fields.get("Candidate") or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        m = _CVE_NAME_RE.search(text)
        if not m:
            return None
        cve_id = m.group(1).upper()
    desc = (fields.get("Ubuntu-Description") or fields.get("Description") or "").strip()
    return {
        "cve_id": cve_id,
        "title": (desc[:120] + ("…" if len(desc) > 120 else "")) if desc else cve_id,
        "description": desc[:4000],
        "priority": (fields.get("Priority") or "").strip(),
        "published": (fields.get("PublicDate") or fields.get("PublicDateAtUSN") or "").strip(),
        "packages": packages[:200],
        "notices": {
            "references": (fields.get("References") or "")[:4000],
            "notes": (fields.get("Notes") or "")[:2000],
            "bugs": (fields.get("Bugs") or "")[:1000],
            "source": "ubuntu-cve-tracker",
        },
        "detail_url": f"https://ubuntu.com/security/{cve_id}",
    }


def _merge_row(store: dict[str, dict[str, Any]], row: dict[str, Any], now: str) -> None:
    cid = row["cve_id"]
    pkgs = row.pop("packages", None) or []
    notices = row.pop("notices", None) or {}
    if cid not in store:
        store[cid] = {
            "cve_id": cid,
            "title": row.get("title") or cid,
            "description": row.get("description") or "",
            "priority": row.get("priority") or "",
            "published": row.get("published") or "",
            "packages_json": json.dumps(pkgs, separators=(",", ":"))[:200_000],
            "notices_json": json.dumps(notices, separators=(",", ":"))[:100_000],
            "detail_url": row.get("detail_url") or f"https://ubuntu.com/security/{cid}",
            "updated_at": now,
            "_pkgs": list(pkgs),
            "_notices": dict(notices),
        }
        return
    cur = store[cid]
    if len(row.get("description") or "") > len(cur.get("description") or ""):
        cur["description"] = row["description"]
        cur["title"] = row.get("title") or cur["title"]
    if row.get("priority") and not cur.get("priority"):
        cur["priority"] = row["priority"]
    if row.get("published") and not cur.get("published"):
        cur["published"] = row["published"]
    if pkgs:
        cur["_pkgs"].extend(pkgs)
        # de-dupe by entry key
        seen: set[str] = set()
        uniq = []
        for p in cur["_pkgs"]:
            key = json.dumps(p, sort_keys=True) if isinstance(p, dict) else str(p)
            if key in seen:
                continue
            seen.add(key)
            uniq.append(p)
        cur["_pkgs"] = uniq[:400]
        cur["packages_json"] = json.dumps(cur["_pkgs"], separators=(",", ":"))[:200_000]
    if notices:
        cur["_notices"].update({k: v for k, v in notices.items() if v})
        cur["notices_json"] = json.dumps(cur["_notices"], separators=(",", ":"))[:100_000]
    cur["updated_at"] = now


def _finalize_rows(store: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for row in store.values():
        row.pop("_pkgs", None)
        row.pop("_notices", None)
        out.append(row)
    return out


def _ingest_uct_zip(zf: zipfile.ZipFile, store: dict[str, dict[str, Any]], now: str) -> int:
    names = [
        n
        for n in zf.namelist()
        if not n.endswith("/")
        and _CVE_NAME_RE.search(Path(n).name)
        and ("/active/" in n.replace("\\", "/") or "/retired/" in n.replace("\\", "/") or "/ignored/" in n.replace("\\", "/"))
    ]
    added = 0
    for i, name in enumerate(names, 1):
        if i % 400 == 0:
            check_cancelled()
            set_progress(
                phase="ubuntu",
                label="Parsing Ubuntu CVE Tracker",
                current=i,
                total=len(names),
                unit="files",
                detail=Path(name).name,
            )
        try:
            text = zf.read(name).decode("utf-8", errors="replace")
        except OSError:
            continue
        parsed = _parse_uct_text(text)
        if not parsed:
            continue
        _merge_row(store, parsed, now)
        added += 1
    return added


def _ingest_soss_zip(zf: zipfile.ZipFile, store: dict[str, dict[str, Any]], now: str) -> int:
    names = [n for n in zf.namelist() if n.lower().endswith(".json") and "CVE-" in Path(n).name.upper()]
    added = 0
    for i, name in enumerate(names, 1):
        if i % 200 == 0:
            check_cancelled()
            set_progress(
                phase="ubuntu",
                label="Parsing SOSS OpenVEX",
                current=i,
                total=len(names),
                unit="files",
                detail=Path(name).name,
            )
        try:
            doc = json.loads(zf.read(name))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(doc, dict):
            continue
        for stmt in doc.get("statements") or []:
            if not isinstance(stmt, dict):
                continue
            vuln = stmt.get("vulnerability") or {}
            if not isinstance(vuln, dict):
                continue
            cve_id = str(vuln.get("name") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                m = _CVE_NAME_RE.search(Path(name).name)
                cve_id = m.group(1).upper() if m else ""
            if not cve_id.startswith("CVE-"):
                continue
            products = []
            for p in stmt.get("products") or []:
                if isinstance(p, dict):
                    products.append(
                        {
                            "id": p.get("@id") or p.get("id") or "",
                            "status": stmt.get("status") or "",
                        }
                    )
            desc = str(vuln.get("description") or "").strip()
            if desc.upper() == "NO DESCRIPTION":
                desc = ""
            _merge_row(
                store,
                {
                    "cve_id": cve_id,
                    "title": desc[:120] if desc else cve_id,
                    "description": desc[:4000],
                    "priority": "",
                    "published": str(stmt.get("timestamp") or doc.get("timestamp") or ""),
                    "packages": products[:80],
                    "notices": {"source": "soss-vulnerability-data", "status": stmt.get("status") or ""},
                    "detail_url": f"https://ubuntu.com/security/{cve_id}",
                },
                now,
            )
            added += 1
    return added


def _ingest_vcf_zip(zf: zipfile.ZipFile, store: dict[str, dict[str, Any]], now: str) -> int:
    names = [n for n in zf.namelist() if n.lower().endswith(".csv")]
    added = 0
    for i, name in enumerate(names, 1):
        check_cancelled()
        set_progress(
            phase="ubuntu",
            label="Parsing VCF Ubuntu CSVs",
            current=i,
            total=len(names),
            unit="files",
            detail=Path(name).name,
        )
        try:
            raw = zf.read(name).decode("utf-8", errors="replace")
        except OSError:
            continue
        reader = csv.DictReader(io.StringIO(raw))
        for row in reader:
            if not isinstance(row, dict):
                continue
            # Normalize header variants
            lower = { (k or "").strip().lower(): (v or "").strip() for k, v in row.items() }
            cve_id = (lower.get("cve id") or lower.get("cve") or lower.get("cve_id") or "").upper()
            if not cve_id.startswith("CVE-"):
                m = _CVE_NAME_RE.search(cve_id)
                if not m:
                    continue
                cve_id = m.group(1).upper()
            title = lower.get("title") or ""
            desc = lower.get("description") or title
            pkg = lower.get("package name") or lower.get("package") or ""
            packages = []
            if pkg:
                packages.append(
                    {
                        "package": pkg,
                        "installed": lower.get("installed version") or "",
                        "fixed": lower.get("fixed version") or "",
                        "distro": lower.get("distro") or "",
                        "severity": lower.get("severity") or "",
                        "score": lower.get("score") or "",
                        "image": lower.get("image+version") or lower.get("image") or "",
                    }
                )
            _merge_row(
                store,
                {
                    "cve_id": cve_id,
                    "title": (title or desc[:120] or cve_id)[:500],
                    "description": desc[:4000],
                    "priority": lower.get("severity") or "",
                    "published": lower.get("published date") or "",
                    "packages": packages,
                    "notices": {
                        "source": "vcf-ubuntu-vulnerabilities",
                        "url": lower.get("url") or "",
                    },
                    "detail_url": lower.get("url") or f"https://ubuntu.com/security/{cve_id}",
                },
                now,
            )
            added += 1
    return added


def _download_one(url: str, dest: Path, label: str) -> dict[str, Any]:
    dest.parent.mkdir(parents=True, exist_ok=True)
    return download_file(url, dest, etag_path=dest.with_suffix(dest.suffix + ".etag"), label=label)


def download_and_ingest() -> dict[str, Any]:
    """Download UCT / SOSS / VCF GitHub zips and upsert into ubuntu_cves."""
    config.ensure_dirs()
    job_id = None
    with db_session() as conn:
        job_id = log_job_start(conn, "ubuntu_ingest")

    now = utc_now()
    store: dict[str, dict[str, Any]] = {}
    sources_ok: list[str] = []
    stats: dict[str, int] = {"uct": 0, "soss": 0, "vcf": 0}

    try:
        # --- Ubuntu CVE Tracker (try mirrors in order) ---
        uct_dest = config.UBUNTU_DIR / "ubuntu-cve-tracker.zip"
        uct_downloaded = False
        last_uct_err: Exception | None = None
        for url in _uct_urls():
            check_cancelled()
            set_progress(phase="ubuntu", label="Downloading Ubuntu CVE Tracker", detail=url)
            try:
                _download_one(url, uct_dest, "Ubuntu CVE Tracker zip")
                uct_downloaded = True
                sources_ok.append(url)
                break
            except Exception as exc:
                last_uct_err = exc
                log.warning("UCT zip failed (%s): %s", url, exc)
        if uct_downloaded and uct_dest.is_file():
            set_progress(phase="ubuntu", label="Parsing Ubuntu CVE Tracker", detail=uct_dest.name)
            try:
                with zipfile.ZipFile(uct_dest, "r") as zf:
                    stats["uct"] = _ingest_uct_zip(zf, store, now)
            except zipfile.BadZipFile as exc:
                log.warning("UCT bad zip: %s", exc)
        elif last_uct_err and not store:
            log.warning("All UCT mirrors failed: %s", last_uct_err)

        # --- SOSS OpenVEX ---
        check_cancelled()
        soss_url = get_url("ubuntu_soss_zip", config.UBUNTU_SOSS_ZIP_URL)
        soss_dest = config.UBUNTU_DIR / "soss-vulnerability-data.zip"
        set_progress(phase="ubuntu", label="Downloading SOSS VEX", detail=soss_url)
        try:
            _download_one(soss_url, soss_dest, "SOSS vulnerability data zip")
            if soss_dest.is_file():
                with zipfile.ZipFile(soss_dest, "r") as zf:
                    stats["soss"] = _ingest_soss_zip(zf, store, now)
                sources_ok.append(soss_url)
        except Exception as exc:
            log.warning("SOSS ingest skipped: %s", exc)

        # --- VCF Ubuntu CSV reports ---
        check_cancelled()
        vcf_url = get_url("ubuntu_vcf_zip", config.UBUNTU_VCF_ZIP_URL)
        vcf_dest = config.UBUNTU_DIR / "vcf-ubuntu-vulnerabilities.zip"
        set_progress(phase="ubuntu", label="Downloading VCF Ubuntu reports", detail=vcf_url)
        try:
            _download_one(vcf_url, vcf_dest, "VCF Ubuntu vulnerabilities zip")
            if vcf_dest.is_file():
                with zipfile.ZipFile(vcf_dest, "r") as zf:
                    stats["vcf"] = _ingest_vcf_zip(zf, store, now)
                sources_ok.append(vcf_url)
        except Exception as exc:
            log.warning("VCF ingest skipped: %s", exc)

        rows = _finalize_rows(store)
        if not rows:
            with db_session() as conn:
                existing = int(conn.execute("SELECT COUNT(*) AS n FROM ubuntu_cves").fetchone()["n"])
                if job_id:
                    log_job_finish(
                        conn,
                        job_id,
                        "ok" if existing else "error",
                        f"ubuntu empty — kept existing={existing}",
                    )
            return {
                "ubuntu_cves": existing,
                "upserted": 0,
                "skipped": True,
                "reason": "no_rows_parsed",
                "kept_existing": True,
                "sources": sources_ok,
                "stats": stats,
            }

        # Batch upsert
        batch: list[dict[str, Any]] = []
        upserted = 0
        for i, row in enumerate(rows, 1):
            batch.append(row)
            if len(batch) >= 500:
                check_cancelled()
                with db_session() as conn:
                    conn.executemany(_UPSERT_SQL, batch)
                upserted += len(batch)
                batch.clear()
                set_progress(
                    phase="ubuntu",
                    label="Writing Ubuntu CVEs",
                    current=i,
                    total=len(rows),
                    unit="cves",
                    detail=f"stored={upserted}",
                )
        if batch:
            with db_session() as conn:
                conn.executemany(_UPSERT_SQL, batch)
            upserted += len(batch)

        with db_session() as conn:
            final_n = int(conn.execute("SELECT COUNT(*) AS n FROM ubuntu_cves").fetchone()["n"])
            set_meta(conn, "ubuntu_last_ingest", utc_now())
            if job_id:
                log_job_finish(
                    conn,
                    job_id,
                    "ok",
                    f"ubuntu_cves={final_n} upserted={upserted} uct={stats['uct']} soss={stats['soss']} vcf={stats['vcf']}",
                )

        set_progress(phase="idle", label="Idle", detail=f"Ubuntu {final_n:,}")
        return {
            "ubuntu_cves": final_n,
            "upserted": upserted,
            "sources": sources_ok,
            "stats": stats,
        }
    except JobCancelled:
        with db_session() as conn:
            final_n = int(conn.execute("SELECT COUNT(*) AS n FROM ubuntu_cves").fetchone()["n"])
            if job_id:
                log_job_finish(conn, job_id, "cancelled", f"ubuntu partial={final_n}")
        raise
    except Exception as exc:
        log.exception("Ubuntu ingest failed")
        with db_session() as conn:
            if job_id:
                log_job_finish(conn, job_id, "error", str(exc))
        raise
