"""Helpers for Sync DB orchestration."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from ..db import db_session, dedupe_cve_related, refresh_overview, set_meta, utc_now
from ..download_cleanup import clean_all_downloads, clean_feed_downloads, clean_nse_temp_exports
from ..export.nse_db import export_nse_databases
from ..ingest import capec as capec_ingest
from ..ingest import cisa_kev as cisa_kev_ingest
from ..ingest import cve as cve_ingest
from ..ingest import cwe as cwe_ingest
from ..ingest import debian as debian_ingest
from ..ingest import exploitdb as edb_ingest
from ..ingest import github_advisories as ghsa_ingest
from ..ingest import metasploit as metasploit_ingest
from ..ingest import msrc as msrc_ingest
from ..ingest import nessus_plugins as nessus_ingest
from ..ingest import nuclei as nuclei_ingest
from ..ingest import nvd as nvd_ingest
from ..ingest import osv as osv_ingest
from ..ingest import poc_github as poc_github_ingest
from ..ingest import ubuntu as ubuntu_ingest
from ..progress import JobCancelled, check_cancelled, set_progress
from ..settings_store import is_feed_enabled
from . import feed_health

log = logging.getLogger("vulnlocal.sync.pipeline")


def feed_changed(name: str, result: Any) -> bool:
    """Return False when an ingest result indicates no data change (skip NSE rebuild)."""
    if not isinstance(result, dict):
        return True
    if result.get("skipped") is True:
        return False
    if result.get("error"):
        return False
    if name == "nvd":
        return int(result.get("downloaded") or 0) > 0 or int(result.get("upserted") or 0) > 0
    if name == "cve":
        return bool(
            result.get("changed")
            or result.get("ingested")
            or result.get("applied")
            or int(result.get("updated") or 0) > 0
        )
    if name == "msrc":
        return int(result.get("fetched") or 0) > 0 or int(result.get("cves_upserted") or 0) > 0
    if result.get("skipped_download") and int(
        result.get("upserted") or result.get("parsed") or result.get("parsed_templates") or 0
    ) == 0:
        return False
    return True


def _safe_feed(name: str, fn: Callable[[], Any]) -> tuple[Any, bool]:
    """Run one feed; log failures and continue (do not abort the whole Sync DB)."""
    if not is_feed_enabled(name):
        set_progress(phase=name, label=f"{name} skipped", detail="disabled in Live status")
        log.info("Feed %s skipped — disabled in sync_feeds", name)
        return {"skipped": True, "disabled": True, "feed": name}, False
    try:
        result = fn()
        changed = feed_changed(name, result)
        if isinstance(result, dict) and not result.get("error"):
            try:
                clean_info = clean_feed_downloads(name)
                result["downloads_cleaned"] = int(clean_info.get("bytes") or 0)
            except Exception as clean_exc:
                log.warning("Download cleanup for %s failed: %s", name, clean_exc)
        return result, changed
    except JobCancelled:
        raise
    except Exception as exc:
        log.exception("Feed %s failed — continuing Sync DB", name)
        set_progress(
            phase=name,
            label=f"{name} failed",
            detail=str(exc)[:200],
        )
        return {"skipped": True, "error": str(exc), "feed": name}, False


def run_incremental_sync() -> dict[str, Any]:
    """Incremental Sync: conditional downloads; NSE export only if something changed."""
    any_changed = False
    results: dict[str, Any] = {}
    nvd_ran = False
    health = feed_health.log_sparse_summary()
    results["feed_health"] = health
    results["sync_feeds"] = {
        k: is_feed_enabled(k) for k in (
            "edb", "cve", "cwe", "cisa", "capec", "debian", "ghsa", "poc_github",
            "ubuntu", "osv", "nvd", "nuclei", "metasploit", "nessus", "msrc",
        )
    }

    def step(name: str, fn: Callable[[], Any]) -> None:
        nonlocal any_changed
        check_cancelled()
        result, changed = _safe_feed(name, fn)
        results[name] = result
        any_changed = changed or any_changed

    step("edb", edb_ingest.download_and_ingest)

    def _cve():
        nonlocal nvd_ran
        out: dict[str, Any] = {}
        # CVE List V5 (GitHub) when sparse / due for delta
        if cve_ingest.needs_full_ingest() or feed_health.is_sparse("cves"):
            set_progress(
                phase="cve",
                label="Full CVE List V5 ingest",
                detail="Downloading official archive (delta-only is not enough)",
            )
            out["cvelist"] = cve_ingest.download_and_ingest(force_zip=True, prefer_zip_stream=True)
        else:
            out["cvelist"] = cve_ingest.sync_delta()

        # Official NVD JSON 2.0 year + modified/recent zips as CVE sources
        # (https://nvd.nist.gov/vuln/data-feeds#divJson20Feeds) — upsert by cve_id.
        # Download when NVD Sync is On, or when NVD corpus is still sparse.
        # If NVD Sync is Off and corpus is healthy, only mirror existing nvd_cves → cves.
        nvd_on = is_feed_enabled("nvd")
        nvd_sparse = feed_health.is_sparse("nvd_cves")
        if nvd_on or nvd_sparse:
            set_progress(
                phase="cve",
                label="NVD feeds → CVEs",
                detail="year + modified + recent (upsert into cves)",
            )
            out["nvd"] = nvd_ingest.download_and_ingest_for_cves(full=None)
            nvd_ran = True
        else:
            set_progress(
                phase="cve",
                label="Mirror NVD → CVEs",
                detail="NVD Sync off — using local nvd_cves only",
            )
            out["nvd"] = {
                "skipped_download": True,
                "reason": "nvd_disabled",
                "cves_mirror": nvd_ingest.mirror_to_cves(),
            }
        with db_session() as conn:
            out["cves"] = int(conn.execute("SELECT COUNT(*) AS n FROM cves").fetchone()["n"])
        out["ingested"] = int(
            (out.get("cvelist") or {}).get("ingested")
            or (out.get("nvd") or {}).get("cves_mirror", {}).get("cves_added")
            or 0
        )
        out["changed"] = bool(
            out.get("ingested")
            or (out.get("cvelist") or {}).get("changed")
            or (out.get("nvd") or {}).get("upserted")
            or (out.get("nvd") or {}).get("downloaded")
        )
        return out

    step("cve", _cve)
    step("cwe", cwe_ingest.download_and_ingest)
    step("cisa", cisa_kev_ingest.download_and_ingest)

    # Advisory feeds early (before NVD/MSRC). Fast API/zip feeds first so Manage
    # counts leave 0 quickly; OSV last among these (multi-GB ecosystem zips).
    step("capec", capec_ingest.download_and_ingest)
    step("debian", debian_ingest.download_and_ingest)
    step("ghsa", lambda: ghsa_ingest.download_and_ingest(force=ghsa_ingest.needs_full_ingest()))
    step("poc_github", poc_github_ingest.download_and_ingest)
    step("ubuntu", ubuntu_ingest.download_and_ingest)
    step("osv", osv_ingest.download_and_ingest)

    def _nvd():
        nonlocal nvd_ran
        if nvd_ran:
            return {
                "skipped": True,
                "reason": "already_ran_with_cve",
            }
        stats = nvd_ingest.download_and_ingest(full=None)
        # Keep Manage “CVEs” aligned when CVE sync is on
        if is_feed_enabled("cve"):
            stats["cves_mirror"] = nvd_ingest.mirror_to_cves()
        return stats

    step("nvd", _nvd)
    step("nuclei", nuclei_ingest.download_and_ingest)
    step("metasploit", metasploit_ingest.download_and_ingest)
    step("nessus", nessus_ingest.download_and_ingest)
    step("msrc", lambda: msrc_ingest.download_and_ingest(full=None))

    check_cancelled()
    with db_session() as conn:
        dedupe = dedupe_cve_related(conn)
    results["dedupe"] = dedupe

    # Always refresh the offline NSE SQLite after Sync DB so downloads stay current.
    set_progress(phase="nse_export", label="Exporting slim NSE SQLite", detail="plaintext")
    try:
        results["nse"] = export_nse_databases()
    except JobCancelled:
        raise
    except Exception as exc:
        log.exception("NSE export failed")
        results["nse"] = {"status": "error", "error": str(exc)}

    with db_session() as conn:
        set_meta(conn, "last_sync_all", utc_now())
        set_progress(phase="overview", label="Refreshing home overview", detail="products + severity")
        results["overview"] = refresh_overview(conn)

    try:
        results["downloads_cleanup"] = clean_all_downloads(also_cve_extract=True)
        results["nse_temp_cleanup"] = clean_nse_temp_exports()
    except Exception as exc:
        log.warning("Final download cleanup failed: %s", exc)
        results["downloads_cleanup"] = {"error": str(exc)}

    results["any_changed"] = any_changed
    return {
        "exploitdb": results.get("edb"),
        "cve": results.get("cve"),
        "cwe": results.get("cwe"),
        "nvd": results.get("nvd"),
        "cisa_kev": results.get("cisa"),
        "nuclei": results.get("nuclei"),
        "metasploit": results.get("metasploit"),
        "nessus": results.get("nessus"),
        "msrc": results.get("msrc"),
        "capec": results.get("capec"),
        "debian": results.get("debian"),
        "ubuntu": results.get("ubuntu"),
        "osv": results.get("osv"),
        "ghsa": results.get("ghsa"),
        "poc_github": results.get("poc_github"),
        "dedupe": dedupe,
        "nse": results.get("nse"),
        "overview": results.get("overview"),
        "downloads_cleanup": results.get("downloads_cleanup"),
        "any_changed": any_changed,
        "feed_errors": {
            k: v.get("error")
            for k, v in results.items()
            if isinstance(v, dict) and v.get("error")
        },
    }


def run_extra_feeds_sync() -> dict[str, Any]:
    """Sync advisory feeds only (CAPEC / Debian / Ubuntu / OSV / GHSA / PoC)."""
    results: dict[str, Any] = {}

    def step(name: str, fn: Callable[[], Any]) -> None:
        check_cancelled()
        result, _changed = _safe_feed(name, fn)
        results[name] = result

    step("capec", capec_ingest.download_and_ingest)
    step("debian", debian_ingest.download_and_ingest)
    step("ghsa", lambda: ghsa_ingest.download_and_ingest(force=ghsa_ingest.needs_full_ingest()))
    step("poc_github", poc_github_ingest.download_and_ingest)
    step("ubuntu", ubuntu_ingest.download_and_ingest)
    step("osv", osv_ingest.download_and_ingest)

    with db_session() as conn:
        set_meta(conn, "last_sync_extra_feeds", utc_now())
        results["overview"] = refresh_overview(conn)

    try:
        results["downloads_cleanup"] = clean_all_downloads(also_cve_extract=False)
    except Exception as exc:
        log.warning("Extra-feed download cleanup failed: %s", exc)
        results["downloads_cleanup"] = {"error": str(exc)}

    return {
        "capec": results.get("capec"),
        "debian": results.get("debian"),
        "ubuntu": results.get("ubuntu"),
        "osv": results.get("osv"),
        "ghsa": results.get("ghsa"),
        "poc_github": results.get("poc_github"),
        "overview": results.get("overview"),
        "downloads_cleanup": results.get("downloads_cleanup"),
        "feed_errors": {
            k: v.get("error")
            for k, v in results.items()
            if isinstance(v, dict) and v.get("error")
        },
    }
