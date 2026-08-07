"""Ingest and delta-sync CVE List V5 from official bulk archives (no site crawling)."""

from __future__ import annotations

import json
import logging
import shutil
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable

from .. import config
from ..db import (
    connect,
    db_session,
    get_meta,
    log_job_finish,
    log_job_start,
    refresh_overview,
    set_meta,
    utc_now,
)
from ..httputil import download_first_ok, http_get
from ..progress import JobCancelled, check_cancelled, set_progress
from ..settings_store import get_url

log = logging.getLogger("vulnlocal.cve")

# Official CVE List is hundreds of thousands of records. Below this we treat
# the local `cves` table as incomplete (e.g. test limit / delta-only seed).
MIN_FULL_CVE_COUNT = 100_000


def needs_full_ingest() -> bool:
    """True when Manage “CVEs” is missing most of CVE List V5."""
    with db_session() as conn:
        cve_n = int(conn.execute("SELECT COUNT(*) AS n FROM cves").fetchone()["n"])
        try:
            nvd_n = int(conn.execute("SELECT COUNT(*) AS n FROM nvd_cves").fetchone()["n"])
        except Exception:
            nvd_n = 0
    if cve_n == 0:
        return True
    if cve_n < MIN_FULL_CVE_COUNT:
        return True
    # Still far behind a rich NVD corpus (common after delta-only syncs).
    if nvd_n >= 50_000 and cve_n < int(nvd_n * 0.6):
        return True
    return False


def resolve_cve_root() -> Path | None:
    candidates = [
        config.LOCAL_CVE_TREE,
        config.CVE_EXTRACT_DIR / "cvelistV5-main",
        config.CVE_EXTRACT_DIR,
    ]
    for root in candidates:
        if (root / "cves").is_dir():
            return root
    return None


def _english_description(cna: dict) -> str:
    for item in cna.get("descriptions") or []:
        if (item.get("lang") or "").lower().startswith("en"):
            return (item.get("value") or "").strip()
    for item in cna.get("descriptions") or []:
        if item.get("value"):
            return str(item["value"]).strip()
    return ""


def _pick_cvss(containers: dict) -> tuple[float | None, str | None, str | None]:
    best: tuple[float, str | None, str | None] | None = None

    def consider(metrics: list | None) -> None:
        nonlocal best
        if not metrics:
            return
        for metric in metrics:
            for key in ("cvssV3_1", "cvssV3_0", "cvssV2"):
                block = metric.get(key)
                if not block:
                    continue
                score = block.get("baseScore")
                if score is None:
                    continue
                try:
                    score_f = float(score)
                except (TypeError, ValueError):
                    continue
                vector = block.get("vectorString")
                severity = block.get("baseSeverity") or metric.get("baseSeverity")
                if best is None or score_f > best[0]:
                    best = (score_f, vector, severity)

    cna = containers.get("cna") or {}
    consider(cna.get("metrics"))
    for adp in containers.get("adp") or []:
        consider(adp.get("metrics"))
    if best:
        return best[0], best[1], best[2]
    return None, None, None


def _iter_cpes(containers: dict) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()

    def add(cpe: str) -> None:
        cpe = cpe.strip()
        if cpe and cpe not in seen:
            seen.add(cpe)
            found.append(cpe)

    cna = containers.get("cna") or {}
    for affected in cna.get("affected") or []:
        for cpe in affected.get("cpes") or []:
            add(str(cpe))
    for adp in containers.get("adp") or []:
        for affected in adp.get("affected") or []:
            for cpe in affected.get("cpes") or []:
                add(str(cpe))
        for match in adp.get("cpeApplicability") or []:
            for node in match.get("nodes") or []:
                for cm in node.get("cpeMatch") or []:
                    if cm.get("criteria"):
                        add(str(cm["criteria"]))
    return found


def _iter_products(containers: dict) -> list[dict[str, str]]:
    products: list[dict[str, str]] = []
    cna = containers.get("cna") or {}
    for affected in cna.get("affected") or []:
        vendor = (affected.get("vendor") or "").strip()
        product = (affected.get("product") or "").strip()
        if not vendor and not product:
            continue
        versions = affected.get("versions") or [{}]
        for ver in versions:
            products.append(
                {
                    "vendor": vendor,
                    "product": product,
                    "version": str(ver.get("version") or ""),
                    "status": str(ver.get("status") or affected.get("defaultStatus") or ""),
                }
            )
    return products


def parse_cve_record(data: dict[str, Any], source_path: str = "") -> dict[str, Any] | None:
    meta = data.get("cveMetadata") or {}
    cve_id = meta.get("cveId")
    if not cve_id:
        return None
    containers = data.get("containers") or {}
    cna = containers.get("cna") or {}
    score, vector, severity = _pick_cvss(containers)
    return {
        "cve_id": cve_id,
        "state": meta.get("state") or "",
        "description": _english_description(cna)[:8000],
        "date_published": meta.get("datePublished") or "",
        "date_updated": meta.get("dateUpdated") or "",
        "cvss_score": score,
        "cvss_vector": vector or "",
        "severity": severity or "",
        "assigner": meta.get("assignerShortName") or "",
        "source_path": source_path,
        "updated_at": utc_now(),
        "products": _iter_products(containers),
        "cpes": _iter_cpes(containers),
    }


def _parse_path(path_str: str) -> dict[str, Any] | None:
    path = Path(path_str)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return parse_cve_record(data, source_path=path_str)


def _parse_bytes(payload: bytes, source_path: str = "") -> dict[str, Any] | None:
    try:
        data = json.loads(payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return parse_cve_record(data, source_path=source_path)


def upsert_cve(conn, record: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO cves(
            cve_id, state, description, date_published, date_updated,
            cvss_score, cvss_vector, severity, assigner, source_path, updated_at
        ) VALUES (
            :cve_id, :state, :description, :date_published, :date_updated,
            :cvss_score, :cvss_vector, :severity, :assigner, :source_path, :updated_at
        )
        ON CONFLICT(cve_id) DO UPDATE SET
            state=excluded.state,
            description=excluded.description,
            date_published=excluded.date_published,
            date_updated=excluded.date_updated,
            cvss_score=excluded.cvss_score,
            cvss_vector=excluded.cvss_vector,
            severity=excluded.severity,
            assigner=excluded.assigner,
            source_path=excluded.source_path,
            updated_at=excluded.updated_at
        """,
        {
            "cve_id": record["cve_id"],
            "state": record["state"],
            "description": record["description"],
            "date_published": record["date_published"],
            "date_updated": record["date_updated"],
            "cvss_score": record["cvss_score"],
            "cvss_vector": record["cvss_vector"],
            "severity": record["severity"],
            "assigner": record["assigner"],
            "source_path": record["source_path"],
            "updated_at": record["updated_at"],
        },
    )
    conn.execute("DELETE FROM cve_products WHERE cve_id=?", (record["cve_id"],))
    conn.execute("DELETE FROM cve_cpes WHERE cve_id=?", (record["cve_id"],))
    if record["products"]:
        conn.executemany(
            """
            INSERT INTO cve_products(cve_id, vendor, product, version, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (record["cve_id"], p["vendor"], p["product"], p["version"], p["status"])
                for p in record["products"]
            ],
        )
    if record["cpes"]:
        conn.executemany(
            "INSERT INTO cve_cpes(cve_id, cpe) VALUES (?, ?)",
            [(record["cve_id"], cpe) for cpe in record["cpes"]],
        )


def _bulk_write(records: list[dict[str, Any]]) -> int:
    if not records:
        return 0
    conn = connect()
    try:
        conn.execute("PRAGMA synchronous=OFF")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA cache_size=-200000")
        conn.execute("BEGIN")
        for rec in records:
            upsert_cve(conn, rec)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.close()
    return len(records)


def iter_cve_json_files(root: Path) -> Iterable[Path]:
    cves_dir = root / "cves"
    if not cves_dir.is_dir():
        return
    yield from cves_dir.rglob("CVE-*.json")


def _commit_meta(root: Path, count: int, job_id: int) -> None:
    with db_session() as conn:
        set_meta(conn, "cve_last_ingest", utc_now())
        set_meta(conn, "cve_tree_path", str(root))
        delta_path = root / "cves" / "delta.json"
        if delta_path.is_file():
            try:
                delta = json.loads(delta_path.read_text(encoding="utf-8"))
                if delta.get("fetchTime"):
                    set_meta(conn, "cve_delta_fetch_time", delta["fetchTime"])
            except json.JSONDecodeError:
                pass
        log_job_finish(conn, job_id, "ok", f"ingested={count} root={root}")
        refresh_overview(conn)


def ingest_from_tree(root: Path | None = None, limit: int | None = None) -> dict:
    """Parallel-parse every CVE-*.json under the local tree into SQLite."""
    root = root or resolve_cve_root()
    if root is None:
        raise FileNotFoundError(
            "No CVE tree found. Place cvelistV5-main next to the project "
            "or download the official zip first."
        )

    with db_session() as conn:
        job_id = log_job_start(conn, "cve_bulk_ingest")

    started = time.monotonic()
    count = 0
    batch: list[dict[str, Any]] = []
    paths: list[str] = []
    try:
        set_progress(
            phase="cve_scan",
            label="Scanning local CVE JSON tree",
            current=0,
            total=0,
            unit="files",
            detail=str(root),
        )
        for path in iter_cve_json_files(root):
            paths.append(str(path))
            if len(paths) % 5000 == 0:
                set_progress(
                    phase="cve_scan",
                    label="Scanning local CVE JSON tree",
                    current=len(paths),
                    total=0,
                    unit="files",
                    detail=str(root),
                )
            if limit is not None and len(paths) >= limit:
                break

        total = len(paths)
        workers = max(1, config.CVE_PARSE_WORKERS)
        log.info("Parsing %d CVE JSON files with %d workers", total, workers)
        set_progress(
            phase="cve_ingest",
            label="Ingesting CVE records",
            current=0,
            total=total,
            unit="CVEs",
            detail=f"{workers} workers",
        )

        chunk = max(workers * 64, 512)
        last_logged = 0
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for i in range(0, len(paths), chunk):
                slice_paths = paths[i : i + chunk]
                futures = [pool.submit(_parse_path, p) for p in slice_paths]
                for fut in as_completed(futures):
                    check_cancelled()
                    rec = fut.result()
                    if not rec:
                        continue
                    batch.append(rec)
                    if len(batch) >= config.CVE_BATCH_SIZE:
                        count += _bulk_write(batch)
                        batch.clear()
                        set_progress(
                            phase="cve_ingest",
                            label="Ingesting CVE records",
                            current=count,
                            total=total,
                            unit="CVEs",
                            detail=f"{count:,} / {total:,}",
                        )
                        if count - last_logged >= config.CVE_BATCH_SIZE * 5:
                            log.info("CVE ingest progress: %d / %d", count, total)
                            last_logged = count
        if batch:
            check_cancelled()
            count += _bulk_write(batch)

        set_progress(
            phase="cve_done",
            label="CVE ingest complete",
            current=count,
            total=total,
            unit="CVEs",
            detail=f"{count:,} records",
        )
        _commit_meta(root, count, job_id)
        elapsed = time.monotonic() - started
        log.info("CVE ingest done: %d records in %.1fs (%.0f/s)", count, elapsed, count / max(elapsed, 0.1))
        return {"status": "ok", "ingested": count, "root": str(root), "seconds": round(elapsed, 1)}
    except JobCancelled as exc:
        with db_session() as conn:
            log_job_finish(conn, job_id, "cancelled", str(exc))
        raise
    except Exception as exc:
        with db_session() as conn:
            log_job_finish(conn, job_id, "error", str(exc))
        raise


def ingest_from_zip(zip_path: Path, limit: int | None = None) -> dict:
    """
    Stream-parse CVE JSON members directly from a zip without full extract.
    Much faster cold-start when only the archive is available.
    """
    with db_session() as conn:
        job_id = log_job_start(conn, "cve_zip_ingest")

    started = time.monotonic()
    count = 0
    batch: list[dict[str, Any]] = []
    try:
        set_progress(
            phase="cve_zip_scan",
            label="Indexing CVE zip members",
            current=0,
            total=0,
            unit="files",
            detail=str(zip_path.name),
        )
        with zipfile.ZipFile(zip_path, "r") as zf:
            members = [
                info
                for info in zf.infolist()
                if (not info.is_dir())
                and info.filename.replace("\\", "/").endswith(".json")
                and "/CVE-" in info.filename.replace("\\", "/").upper()
            ]
            if limit is not None:
                members = members[:limit]
            total = len(members)
            log.info("Zip contains %d CVE JSON members", total)
            set_progress(
                phase="cve_ingest",
                label="Ingesting CVE zip records",
                current=0,
                total=total,
                unit="CVEs",
                detail=str(zip_path.name),
            )

            workers = max(1, config.CVE_PARSE_WORKERS)
            chunk_size = max(workers * 8, 64)
            for i in range(0, len(members), chunk_size):
                slice_members = members[i : i + chunk_size]
                payloads: list[tuple[str, bytes]] = []
                for info in slice_members:
                    with zf.open(info, "r") as fh:
                        payloads.append((info.filename, fh.read()))
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = [
                        pool.submit(_parse_bytes, blob, name) for name, blob in payloads
                    ]
                    for fut in as_completed(futures):
                        check_cancelled()
                        rec = fut.result()
                        if not rec:
                            continue
                        batch.append(rec)
                        if len(batch) >= config.CVE_BATCH_SIZE:
                            count += _bulk_write(batch)
                            batch.clear()
                            set_progress(
                                phase="cve_ingest",
                                label="Ingesting CVE zip records",
                                current=count,
                                total=total,
                                unit="CVEs",
                                detail=f"{count:,} / {total:,}",
                            )
                if count and count % (config.CVE_BATCH_SIZE * 5) == 0:
                    log.info("CVE zip ingest progress: %d", count)

        if batch:
            check_cancelled()
            count += _bulk_write(batch)

        set_progress(
            phase="cve_done",
            label="CVE zip ingest complete",
            current=count,
            total=total if "total" in locals() else count,
            unit="CVEs",
            detail=f"{count:,} records",
        )
        with db_session() as conn:
            set_meta(conn, "cve_last_ingest", utc_now())
            set_meta(conn, "cve_zip_path", str(zip_path))
            log_job_finish(conn, job_id, "ok", f"ingested={count} zip={zip_path}")
            refresh_overview(conn)

        elapsed = time.monotonic() - started
        return {
            "status": "ok",
            "ingested": count,
            "zip": str(zip_path),
            "seconds": round(elapsed, 1),
        }
    except JobCancelled as exc:
        with db_session() as conn:
            log_job_finish(conn, job_id, "cancelled", str(exc))
        raise
    except Exception as exc:
        with db_session() as conn:
            log_job_finish(conn, job_id, "error", str(exc))
        raise


def _latest_release_midnight_zip_url() -> str | None:
    """Prefer the official midnight baseline asset when GitHub Releases API works."""
    try:
        resp = http_get(
            get_url("cve_releases_api", config.CVE_RELEASES_API),
            extra_headers={"Accept": "application/vnd.github+json"},
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        for asset in data.get("assets") or []:
            name = asset.get("name") or ""
            if name.endswith("_all_CVEs_at_midnight.zip"):
                return asset.get("browser_download_url")
    except Exception as exc:  # noqa: BLE001
        log.warning("Could not resolve release midnight zip: %s", exc)
    return None


def download_cve_archive(force: bool = False, *, extract: bool = True) -> Path:
    """
    Download one bulk CVE archive from official mirrors.

    Preference order (see https://github.com/CVEProject/cvelistV5):
      1) existing local tree (unless force)
      2) GitHub Releases midnight baseline zip
      3) codeload / archive main.zip
    """
    config.ensure_dirs()
    existing = resolve_cve_root()
    if existing and not force:
        return existing

    urls: list[str] = []
    midnight = _latest_release_midnight_zip_url()
    if midnight:
        urls.append(midnight)
    urls.extend(
        [
            get_url("cve_codeload_zip", config.CVE_CODELOAD_ZIP_URL),
            get_url("cve_main_zip", config.CVE_MAIN_ZIP_URL),
        ]
    )

    set_progress(
        phase="cve_download",
        label="Downloading CVE List V5 archive",
        current=0,
        total=0,
        unit="",
        detail="official GitHub mirror",
    )
    zip_path = config.DOWNLOAD_DIR / "cvelistV5-bulk.zip"
    download_first_ok(urls, zip_path, label="CVE List V5 archive")

    if not extract:
        return zip_path

    set_progress(
        phase="cve_extract",
        label="Extracting CVE archive",
        current=0,
        total=0,
        unit="",
        detail=str(zip_path.name),
    )
    # Extract once so delta sync / future local ingest can reuse the tree
    extract_to = config.CVE_EXTRACT_DIR
    if extract_to.exists():
        shutil.rmtree(extract_to, ignore_errors=True)
    extract_to.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(extract_to)

    root = resolve_cve_root()
    if root is None:
        # Still return zip path usefulness — caller may ingest_from_zip
        return zip_path
    return root


def download_main_zip(force: bool = False) -> Path:
    return download_cve_archive(force=force)


def download_and_ingest(force_zip: bool = False, prefer_zip_stream: bool = True) -> dict:
    """
    Full CVE ingest for local use.

    Prefers streaming the official zip (midnight release or main.zip) so we do
    not depend on a fragile full filesystem extract. Falls back to an existing
    cvelistV5 tree when present and force_zip is False.
    """
    root = resolve_cve_root()
    zip_path = config.DOWNLOAD_DIR / "cvelistV5-bulk.zip"

    if force_zip or root is None:
        downloaded = download_cve_archive(force=bool(force_zip or root is None), extract=not prefer_zip_stream)
        root = resolve_cve_root()
        if prefer_zip_stream:
            if zip_path.is_file() and zip_path.stat().st_size > 1_000_000:
                return ingest_from_zip(zip_path)
            if isinstance(downloaded, Path) and downloaded.suffix.lower() == ".zip" and downloaded.is_file():
                return ingest_from_zip(downloaded)
        if root is None:
            if zip_path.is_file():
                return ingest_from_zip(zip_path)
            raise RuntimeError("CVE archive downloaded but no usable tree/zip found")
    return ingest_from_tree(root)


def _fetch_delta_json(entry: dict) -> tuple[str, dict | None]:
    """Fetch a single delta CVE JSON politely (used by small worker pool)."""
    link = entry.get("githubLink") or ""
    cve_id = entry.get("cveId") or ""
    if not link or not cve_id:
        return cve_id, None
    time.sleep(config.DELTA_FETCH_PAUSE_MS / 1000.0)
    resp = http_get(link)
    resp.raise_for_status()
    return cve_id, resp.json()


def sync_delta() -> dict:
    """
    Apply latest delta.json new/updated CVE records.

    Uses a small worker pool + short pause so we do not look like a crawler
    hammering raw.githubusercontent.com.
    """
    with db_session() as conn:
        job_id = log_job_start(conn, "cve_delta_sync")
        last_fetch = get_meta(conn, "cve_delta_fetch_time")

    try:
        delta = http_get(get_url("cve_delta", config.CVE_DELTA_URL)).json()
        fetch_time = delta.get("fetchTime") or ""
        if last_fetch and fetch_time and fetch_time == last_fetch:
            with db_session() as conn:
                log_job_finish(conn, job_id, "ok", "no changes (same fetchTime)")
            return {
                "status": "ok",
                "changed": False,
                "fetchTime": fetch_time,
                "new": 0,
                "updated": 0,
            }

        new_entries = list(delta.get("new") or [])
        updated_entries = list(delta.get("updated") or [])
        all_entries = [("new", e) for e in new_entries] + [("updated", e) for e in updated_entries]
        n_new = n_upd = 0
        total = len(all_entries)
        set_progress(
            phase="cve_delta",
            label="Syncing CVE delta",
            current=0,
            total=total,
            unit="CVEs",
            detail=f"new={len(new_entries)} updated={len(updated_entries)}",
        )

        workers = max(1, min(config.DELTA_FETCH_WORKERS, 6))
        records: list[dict[str, Any]] = []
        done = 0

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(_fetch_delta_json, entry): kind
                for kind, entry in all_entries
            }
            for fut in as_completed(futures):
                check_cancelled()
                kind = futures[fut]
                cve_id, data = fut.result()
                done += 1
                if not data:
                    set_progress(
                        phase="cve_delta",
                        label="Syncing CVE delta",
                        current=done,
                        total=total,
                        unit="CVEs",
                        detail=f"skipped {cve_id or '?'}",
                    )
                    continue
                year = cve_id.split("-")[1] if "-" in cve_id else "unknown"
                cache_dir = config.DOWNLOAD_DIR / "delta_cache" / year
                cache_dir.mkdir(parents=True, exist_ok=True)
                cache_file = cache_dir / f"{cve_id}.json"
                cache_file.write_text(json.dumps(data), encoding="utf-8")
                rec = parse_cve_record(data, source_path=str(cache_file))
                if not rec:
                    continue
                records.append(rec)
                if kind == "new":
                    n_new += 1
                else:
                    n_upd += 1
                set_progress(
                    phase="cve_delta",
                    label="Syncing CVE delta",
                    current=done,
                    total=total,
                    unit="CVEs",
                    detail=f"new={n_new} updated={n_upd}",
                )

        _bulk_write(records)
        set_progress(
            phase="cve_delta_done",
            label="CVE delta sync complete",
            current=total,
            total=total,
            unit="CVEs",
            detail=f"new={n_new} updated={n_upd}",
        )

        with db_session() as conn:
            if fetch_time:
                set_meta(conn, "cve_delta_fetch_time", fetch_time)
            set_meta(conn, "cve_last_delta_sync", utc_now())
            log_job_finish(
                conn,
                job_id,
                "ok",
                f"new={n_new} updated={n_upd} fetchTime={fetch_time}",
            )
            refresh_overview(conn)

        return {
            "status": "ok",
            "changed": True,
            "fetchTime": fetch_time,
            "new": n_new,
            "updated": n_upd,
        }
    except JobCancelled as exc:
        with db_session() as conn:
            log_job_finish(conn, job_id, "cancelled", str(exc))
        raise
    except Exception as exc:
        with db_session() as conn:
            log_job_finish(conn, job_id, "error", str(exc))
        raise
