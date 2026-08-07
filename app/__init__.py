"""Flask application factory and routes."""

from __future__ import annotations

import logging
import re
import threading
import time
from typing import Any

from flask import Flask, jsonify, render_template, request, send_file, send_from_directory

from . import config
from .cve_detail import get_cve_detail, invalidate_latest_releases_cache, latest_releases
from .db import (
    db_session,
    dedupe_cve_related,
    init_db,
    peek_overview,
    refresh_overview,
    set_meta,
    set_overview_refresh_hook,
    stats,
    utc_now,
    visual_overview,
)
from .export.nse_db import export_nse_databases
from .purge import CONFIRM_TOKEN as PURGE_CONFIRM_TOKEN
from .purge import purge_ingested_data
from .backup import (
    create_backup,
    delete_backup,
    list_backups,
    resolve_backup_path,
    restore_backup,
    restore_from_file,
)
from .export.packages import (
    build_database_zip,
    build_nmap_scanner_zip,
    copy_nse_script_package,
    copy_nse_sqlite,
    copy_sqlite_snapshot,
)
from .ingest import cve as cve_ingest
from .ingest import cwe as cwe_ingest
from .ingest import exploitdb as edb_ingest
from .ingest import nvd as nvd_ingest
from .ingest import cisa_kev as cisa_kev_ingest
from .ingest import nuclei as nuclei_ingest
from .ingest import metasploit as metasploit_ingest
from .ingest import nessus_plugins as nessus_ingest
from .ingest import msrc as msrc_ingest
from .ingest import capec as capec_ingest
from .ingest import debian as debian_ingest
from .ingest import ubuntu as ubuntu_ingest
from .ingest import osv as osv_ingest
from .ingest import github_advisories as ghsa_ingest
from .ingest import poc_github as poc_github_ingest
from .nse_api import correlate as nse_correlate
from .detection_rules import build_detection_pack
from .search import search_local
from .settings_store import (
    ensure_default_settings_persisted,
    ensure_sync_feeds_persisted,
    get_sync_feeds,
    is_feed_enabled,
    load_settings,
    public_settings,
    save_settings,
    save_sync_feeds,
)
from .progress import JobCancelled, clear_progress, get_progress, request_cancel, reset_cancel, check_cancelled, set_progress

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("vulnlocal")

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)

_job_lock = threading.Lock()
_job_state: dict[str, Any] = {
    "running": None,
    "started_at": None,
    "last": None,
    "progress": None,
    "stop_requested": False,
}

_HOME_CACHE: dict[str, Any] = {"ts": 0.0, "payload": None}
_HOME_CACHE_TTL_SEC = 45.0


def _safe_int(raw: Any, default: int, *, lo: int = 0, hi: int = 10_000) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, value))


def _normalize_cve_id(raw: str) -> str | None:
    cve_id = (raw or "").strip().upper()
    if not _CVE_ID_RE.match(cve_id):
        return None
    return cve_id


def _invalidate_home_caches() -> None:
    _HOME_CACHE["payload"] = None
    _HOME_CACHE["ts"] = 0.0
    invalidate_latest_releases_cache()
    try:
        from .ingest.msrc import invalidate_patch_tuesday_cache

        invalidate_patch_tuesday_cache()
    except Exception:
        pass


def _run_background(name: str, fn) -> tuple[dict, int]:
    if not _job_lock.acquire(blocking=False):
        return {"status": "busy", "running": _job_state.get("running")}, 409

    def worker() -> None:
        started = utc_now()
        reset_cancel()
        clear_progress()
        _job_state["running"] = name
        _job_state["started_at"] = started
        _job_state["stop_requested"] = False
        _job_state["progress"] = get_progress()
        try:
            result = fn()
            _job_state["last"] = {
                "job": name,
                "result": result,
                "started_at": started,
                "finished_at": utc_now(),
                "ok": True,
                "stopped": False,
                "progress": get_progress(),
            }
            _invalidate_home_caches()
        except JobCancelled as exc:
            log.info("Background job %s stopped by user", name)
            _job_state["last"] = {
                "job": name,
                "error": str(exc),
                "started_at": started,
                "finished_at": utc_now(),
                "ok": False,
                "stopped": True,
                "progress": get_progress(),
            }
            _invalidate_home_caches()
        except Exception as exc:
            log.exception("Background job %s failed", name)
            _job_state["last"] = {
                "job": name,
                "error": str(exc),
                "started_at": started,
                "finished_at": utc_now(),
                "ok": False,
                "stopped": False,
                "progress": get_progress(),
            }
        finally:
            _job_state["running"] = None
            _job_state["started_at"] = None
            _job_state["stop_requested"] = False
            _job_state["progress"] = get_progress()
            reset_cancel()
            _job_lock.release()

    threading.Thread(target=worker, daemon=True, name=f"vulnlocal-{name}").start()
    return {"status": "started", "job": name}, 202


def _status_payload() -> dict[str, Any]:
    with db_session() as conn:
        s = stats(conn)
        rows = conn.execute(
            """
            SELECT id, job_name, status, message, started_at, finished_at
            FROM job_log ORDER BY id DESC LIMIT 12
            """
        ).fetchall()
    job = dict(_job_state)
    job["progress"] = get_progress()
    job["stop_requested"] = bool(job.get("stop_requested")) or bool(
        (job.get("progress") or {}).get("cancel_requested")
    )
    from .sync.scheduler import schedule_status

    return {
        "job": job,
        "stats": s,
        "jobs": [dict(r) for r in rows],
        "schedule": schedule_status(),
        "sync_minutes": config.CVE_SYNC_INTERVAL_MINUTES,
        "sync_feeds": get_sync_feeds(force=True),
    }


def create_app(start_bg: bool = True, *, debug: bool = False) -> Flask:
    config.ensure_dirs()
    init_db()
    try:
        ensure_default_settings_persisted()
        ensure_sync_feeds_persisted()
    except Exception:
        pass
    set_overview_refresh_hook(_invalidate_home_caches)

    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = config.SECRET_KEY
    app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024  # backup upload cap
    app.config["DEBUG"] = bool(debug)
    app.config["TEMPLATES_AUTO_RELOAD"] = bool(debug)
    app.config["VULNLOCAL_DEV"] = bool(debug)

    @app.before_request
    def _csrf_origin_guard():
        from .security import reject_cross_origin_mutation

        blocked = reject_cross_origin_mutation(request)
        if blocked is not None:
            return blocked
        return None

    @app.after_request
    def _security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        # Allow Google Fonts used by templates; scripts/styles stay same-origin.
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'",
        )
        if debug:
            resp.headers["X-Vulnlocal-Mode"] = "development"
        return resp

    @app.context_processor
    def inject_globals():
        return {
            "version": config.APP_VERSION,
            "app_name": config.APP_NAME,
            "dev_mode": bool(debug),
        }

    if start_bg:
        from .sync.pipeline import run_incremental_sync
        from .sync.scheduler import register_sync_trigger, start_scheduler

        register_sync_trigger(lambda: _run_background("sync_all", run_incremental_sync))
        start_scheduler()

    @app.get("/favicon.ico")
    @app.get("/favicon.svg")
    def favicon():
        """Browser default icon request — avoid console 404 noise."""
        return send_from_directory(
            app.static_folder,
            "favicon.svg",
            mimetype="image/svg+xml",
            max_age=86_400,
        )

    @app.get("/")
    def index():
        now = time.monotonic()
        cached = _HOME_CACHE.get("payload")
        if cached is not None and (now - float(_HOME_CACHE.get("ts") or 0.0)) < _HOME_CACHE_TTL_SEC:
            return render_template("index.html", active_nav="home", **cached)

        with db_session() as conn:
            # Never heal/recompute overview on the request path — that can stall
            # the whole site for minutes on a full NVD corpus.
            s = stats(conn, heal_overview=False)
            if not (s or {}).get("overview"):

                def _bg() -> None:
                    try:
                        with db_session() as c2:
                            refresh_overview(c2, allow_nvd_product_scan=False)
                        _invalidate_home_caches()
                    except Exception:
                        log.exception("Home overview background refresh failed")

                threading.Thread(target=_bg, daemon=True, name="vulnlocal-home-overview").start()

        visual = visual_overview((s or {}).get("overview"))
        latest = latest_releases(10)
        from .ingest.msrc import latest_patch_tuesday

        patch_tuesday = latest_patch_tuesday(limit=15)
        payload = {
            "stats": s,
            "visual": visual,
            "latest": latest,
            "patch_tuesday": patch_tuesday,
        }
        _HOME_CACHE["payload"] = payload
        _HOME_CACHE["ts"] = now
        return render_template("index.html", active_nav="home", **payload)

    @app.get("/cve/<cve_id>")
    def cve_page(cve_id: str):
        normalized = _normalize_cve_id(cve_id)
        if not normalized:
            return (
                render_template(
                    "cve_missing.html",
                    cve_id=(cve_id or "").upper()[:40],
                    active_nav="home",
                ),
                404,
            )
        detail = get_cve_detail(normalized, include_source=True)
        if not detail:
            return (
                render_template(
                    "cve_missing.html",
                    cve_id=normalized,
                    active_nav="home",
                ),
                404,
            )
        return render_template("cve.html", cve=detail, active_nav="home")

    @app.get("/api/cve/<cve_id>")
    def api_cve_detail(cve_id: str):
        normalized = _normalize_cve_id(cve_id)
        if not normalized:
            return jsonify({"error": "invalid cve id"}), 400
        include_source = request.args.get("source", "1") not in {"0", "false", "no"}
        detail = get_cve_detail(normalized, include_source=include_source)
        if not detail:
            return jsonify({"error": "not found", "cve_id": normalized}), 404
        return jsonify(detail)

    @app.get("/manage")
    def manage():
        from .sync.scheduler import get_schedule

        with db_session() as conn:
            s = stats(conn, heal_overview=False)
        return render_template(
            "manage.html",
            stats=s,
            schedule=get_schedule(),
            sync_minutes=config.CVE_SYNC_INTERVAL_MINUTES,
            sync_feeds=get_sync_feeds(),
            active_nav="manage",
        )

    @app.get("/settings")
    def settings_page():
        return render_template("settings.html", settings=load_settings(), active_nav="settings")

    @app.get("/about")
    def about_page():
        return render_template("about.html", active_nav="about", version=config.APP_VERSION)

    @app.get("/faq")
    def faq_page():
        return render_template("faq.html", active_nav="faq", version=config.APP_VERSION)

    @app.get("/manual")
    def manual_page():
        return render_template("manual.html", active_nav="manual", version=config.APP_VERSION)

    @app.get("/api/cve/<cve_id>/detection")
    def api_cve_detection(cve_id: str):
        normalized = _normalize_cve_id(cve_id)
        if not normalized:
            return jsonify({"error": "invalid cve id"}), 400
        pack = build_detection_pack(normalized)
        return jsonify(pack)

    @app.get("/api/settings")
    def api_settings_get():
        return jsonify(public_settings())

    @app.post("/api/settings")
    def api_settings_save():
        payload = request.get_json(silent=True) or {}
        if isinstance(payload, dict):
            payload.pop("api_keys", None)
        try:
            save_settings(payload)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"status": "ok", "settings": public_settings()})

    @app.get("/api/stats")
    def api_stats():
        force = str(request.args.get("refresh") or "").strip().lower() in {"1", "true", "yes"}
        with db_session() as conn:
            if force:

                def _bg() -> None:
                    try:
                        with db_session() as c2:
                            refresh_overview(c2, allow_nvd_product_scan=False)
                    except Exception:
                        log.exception("api_stats overview refresh failed")

                threading.Thread(target=_bg, daemon=True, name="vulnlocal-stats-refresh").start()
            payload = stats(conn, heal_overview=False)
        payload["visual"] = visual_overview((payload or {}).get("overview"))
        payload["job_running"] = _job_state.get("running")
        return jsonify(payload)

    @app.get("/api/home_overview")
    def api_home_overview():
        """Live home overview + charts (polled while Sync DB runs).

        Always returns quickly from cache. Optional refresh=1 kicks a light
        background recompute so the poll loop never blocks the server.
        """
        force = str(request.args.get("refresh") or "").strip().lower() in {"1", "true", "yes"}
        with db_session() as conn:
            ov = peek_overview(conn)
            if not ov:
                # Empty cache: do not block — rebuild in background.
                def _bg_seed() -> None:
                    try:
                        with db_session() as c2:
                            refresh_overview(c2, allow_nvd_product_scan=False)
                    except Exception:
                        log.exception("Background overview seed failed")

                threading.Thread(
                    target=_bg_seed, daemon=True, name="vulnlocal-overview-seed"
                ).start()
            elif force:

                def _bg_refresh() -> None:
                    try:
                        with db_session() as c2:
                            refresh_overview(c2, allow_nvd_product_scan=False)
                    except Exception:
                        log.exception("Background overview refresh failed")

                threading.Thread(
                    target=_bg_refresh, daemon=True, name="vulnlocal-overview-refresh"
                ).start()
        return jsonify(
            {
                "overview": ov,
                "visual": visual_overview(ov),
                "job_running": _job_state.get("running"),
                "progress": get_progress(),
            }
        )

    @app.get("/api/jobs")
    def api_jobs():
        with db_session() as conn:
            rows = conn.execute(
                """
                SELECT id, job_name, status, message, started_at, finished_at
                FROM job_log ORDER BY id DESC LIMIT 50
                """
            ).fetchall()
        return jsonify([dict(r) for r in rows])

    @app.get("/api/job_state")
    def api_job_state():
        return jsonify(_job_state)

    @app.get("/api/status")
    def api_status():
        """Live ingest/sync status for the home UI."""
        return jsonify(_status_payload())

    @app.get("/api/sync/feeds")
    def api_sync_feeds_get():
        return jsonify({"sync_feeds": get_sync_feeds(force=True)})

    @app.post("/api/sync/feeds")
    def api_sync_feeds_save():
        """Enable/disable individual Sync DB data sources (Manage Live status toggles)."""
        payload = request.get_json(silent=True) or {}
        feeds = payload.get("sync_feeds") if isinstance(payload, dict) else None
        if not isinstance(feeds, dict):
            feeds = payload if isinstance(payload, dict) else {}
        saved = save_sync_feeds(feeds)
        return jsonify({"status": "ok", "sync_feeds": saved})

    @app.post("/api/jobs/stop")
    def api_jobs_stop():
        """Request cooperative stop of the currently running background job."""
        running = _job_state.get("running")
        if not running:
            return jsonify({"status": "idle", "message": "No job is running"}), 200
        _job_state["stop_requested"] = True
        request_cancel()
        # Mark open job_log rows as cancelled so the table reflects the stop request
        with db_session() as conn:
            conn.execute(
                """
                UPDATE job_log
                SET status = 'cancelled',
                    message = COALESCE(NULLIF(message, ''), 'stop requested'),
                    finished_at = ?
                WHERE status = 'running'
                """,
                (utc_now(),),
            )
        return jsonify(
            {
                "status": "stopping",
                "job": running,
                "message": f"Stop requested for {running}",
            }
        ), 202

    @app.delete("/api/jobs/<int:job_id>")
    def api_jobs_delete(job_id: int):
        """Remove a single finished job_log row."""
        with db_session() as conn:
            row = conn.execute(
                "SELECT id, status FROM job_log WHERE id = ?",
                (job_id,),
            ).fetchone()
            if not row:
                return jsonify({"error": "not found", "id": job_id}), 404
            if (row["status"] or "").lower() == "running" and _job_state.get("running"):
                return jsonify(
                    {
                        "error": "job still running",
                        "message": "Stop the job first, then clear it.",
                        "id": job_id,
                    }
                ), 409
            conn.execute("DELETE FROM job_log WHERE id = ?", (job_id,))
        return jsonify({"status": "deleted", "id": job_id})

    @app.delete("/api/jobs")
    def api_jobs_clear_all():
        """Clear finished job history (keeps currently running rows)."""
        with db_session() as conn:
            if _job_state.get("running"):
                cur = conn.execute(
                    "DELETE FROM job_log WHERE status != 'running'"
                )
            else:
                cur = conn.execute("DELETE FROM job_log")
            deleted = cur.rowcount
        return jsonify({"status": "cleared", "deleted": deleted})

    @app.post("/api/sync/all")
    def api_sync_all():
        """Incremental Sync: conditional downloads + skip unchanged parses; NSE export only if data changed."""
        from .sync.pipeline import run_incremental_sync

        body, code = _run_background("sync_all", run_incremental_sync)
        return jsonify(body), code

    @app.post("/api/sync/extra-feeds")
    def api_sync_extra_feeds():
        """Sync CAPEC / Debian / Ubuntu / OSV / GHSA / PoC-in-GitHub only."""
        from .sync.pipeline import run_extra_feeds_sync

        body, code = _run_background("sync_extra_feeds", run_extra_feeds_sync)
        return jsonify(body), code

    @app.get("/api/schedule")
    def api_schedule_get():
        from .sync.scheduler import schedule_status

        return jsonify(schedule_status())

    @app.post("/api/schedule")
    def api_schedule_save():
        from .sync.scheduler import save_schedule

        body = request.get_json(silent=True) or {}
        saved = save_schedule(body if isinstance(body, dict) else {})
        return jsonify({"status": "ok", "schedule": saved})

    @app.post("/api/ingest/all")
    def api_ingest_all():
        """Full local load: respects Live status Sync switches."""

        def _maybe(name: str, fn):
            if not is_feed_enabled(name):
                set_progress(phase=name, label=f"{name} skipped", detail="disabled in Live status")
                return {"skipped": True, "disabled": True, "feed": name}
            return fn()

        def job():
            edb = _maybe("edb", edb_ingest.download_and_ingest)
            check_cancelled()

            def _cve_job():
                out: dict[str, Any] = {}
                out["cvelist"] = cve_ingest.download_and_ingest(
                    force_zip=cve_ingest.needs_full_ingest(),
                    prefer_zip_stream=True,
                )
                check_cancelled()
                # NVD year/modified/recent zips when NVD Sync is On (or corpus sparse).
                from .sync import feed_health as _fh

                if is_feed_enabled("nvd") or _fh.is_sparse("nvd_cves"):
                    out["nvd"] = nvd_ingest.download_and_ingest_for_cves(full=True)
                else:
                    out["nvd"] = {
                        "skipped_download": True,
                        "reason": "nvd_disabled",
                        "cves_mirror": nvd_ingest.mirror_to_cves(),
                    }
                return out

            cve = _maybe("cve", _cve_job)
            check_cancelled()
            cwe = _maybe("cwe", cwe_ingest.download_and_ingest)
            check_cancelled()
            cve_pulled_nvd = (
                isinstance(cve, dict)
                and isinstance(cve.get("nvd"), dict)
                and not cve.get("disabled")
                and not cve["nvd"].get("skipped_download")
            )
            if is_feed_enabled("nvd") and not cve_pulled_nvd:
                nvd = nvd_ingest.download_and_ingest(full=True)
                if is_feed_enabled("cve"):
                    nvd["cves_mirror"] = nvd_ingest.mirror_to_cves()
            else:
                nvd = {
                    "skipped": True,
                    "reason": "disabled" if not is_feed_enabled("nvd") else "ran_with_cve",
                }
            check_cancelled()
            cisa = _maybe("cisa", cisa_kev_ingest.download_and_ingest)
            check_cancelled()
            # Isolate advisory feeds so one 429 (Ubuntu) cannot abort the rest.
            extra: dict[str, Any] = {}
            for _name, _fn in (
                ("capec", capec_ingest.download_and_ingest),
                ("debian", debian_ingest.download_and_ingest),
                ("ghsa", ghsa_ingest.download_and_ingest),
                ("poc_github", poc_github_ingest.download_and_ingest),
                ("ubuntu", ubuntu_ingest.download_and_ingest),
                ("osv", osv_ingest.download_and_ingest),
            ):
                check_cancelled()
                if not is_feed_enabled(_name):
                    extra[_name] = {"skipped": True, "disabled": True}
                    continue
                try:
                    extra[_name] = _fn()
                except JobCancelled:
                    raise
                except Exception as exc:
                    log.exception("Full ingest feed %s failed — continuing", _name)
                    set_progress(phase=_name, label=f"{_name} failed", detail=str(exc)[:200])
                    extra[_name] = {"error": str(exc)}
            check_cancelled()
            nuclei = _maybe("nuclei", nuclei_ingest.download_and_ingest)
            check_cancelled()
            msf = _maybe("metasploit", metasploit_ingest.download_and_ingest)
            check_cancelled()
            nessus = _maybe("nessus", nessus_ingest.download_and_ingest)
            check_cancelled()
            msrc = _maybe("msrc", lambda: msrc_ingest.download_and_ingest(full=True))
            check_cancelled()
            with db_session() as conn:
                dedupe_cve_related(conn)
            set_progress(phase="nse_export", label="Exporting slim NSE SQLite", detail="plaintext")
            nse = export_nse_databases()
            with db_session() as conn:
                set_meta(conn, "last_sync_all", utc_now())
            return {
                "exploitdb": edb,
                "cve": cve,
                "cwe": cwe,
                "nvd": nvd,
                "cisa_kev": cisa,
                **extra,
                "nuclei": nuclei,
                "metasploit": msf,
                "nessus": nessus,
                "msrc": msrc,
                "nse": nse,
            }

        body, code = _run_background("ingest_all", job)
        return jsonify(body), code

    @app.post("/api/ingest/exploitdb")
    def api_ingest_edb():
        body, code = _run_background("exploitdb_ingest", edb_ingest.download_and_ingest)
        return jsonify(body), code

    @app.post("/api/ingest/cve")
    def api_ingest_cve():
        payload = request.get_json(silent=True) or {}
        force = bool(payload.get("force_zip", False)) or cve_ingest.needs_full_ingest()

        def job():
            out: dict[str, Any] = {
                "cvelist": cve_ingest.download_and_ingest(
                    force_zip=force, prefer_zip_stream=True
                )
            }
            check_cancelled()
            # Also ingest official NVD JSON 2.0 year + modified/recent feeds into cves.
            out["nvd"] = nvd_ingest.download_and_ingest_for_cves(full=None)
            return out

        body, code = _run_background("cve_bulk_ingest", job)
        return jsonify(body), code

    @app.post("/api/ingest/cve/local")
    def api_ingest_cve_local():
        body, code = _run_background("cve_local_ingest", lambda: cve_ingest.ingest_from_tree())
        return jsonify(body), code

    @app.post("/api/sync/cve")
    def api_sync_cve():
        def job():
            result = cve_ingest.sync_delta()
            if result.get("changed"):
                check_cancelled()
                set_progress(phase="nse_export", label="Exporting NSE SQLite", detail="backup + indexes")
                export_nse_databases()
            return result

        body, code = _run_background("cve_delta_sync", job)
        return jsonify(body), code

    @app.post("/api/sync/nvd")
    def api_sync_nvd():
        payload = request.get_json(silent=True) or {}
        full = payload.get("full")
        if full is not None:
            full = bool(full)

        def job():
            return nvd_ingest.download_and_ingest(full=full)

        body, code = _run_background("nvd_ingest", job)
        return jsonify(body), code

    @app.post("/api/sync/cwe")
    def api_sync_cwe():
        body, code = _run_background("cwe_ingest", cwe_ingest.download_and_ingest)
        return jsonify(body), code

    @app.post("/api/export/nse")
    def api_export_nse():
        body, code = _run_background("nse_export", export_nse_databases)
        return jsonify(body), code

    @app.get("/api/search")
    def api_search_unified():
        q = (request.args.get("q") or "").strip()
        limit = _safe_int(request.args.get("limit", 40), 40, lo=1, hi=100)
        return jsonify(search_local(q, limit=limit))

    @app.get("/api/search/cve")
    def api_search_cve():
        q = (request.args.get("q") or "").strip()
        limit = _safe_int(request.args.get("limit", 50), 50, lo=1, hi=200)
        if not q:
            return jsonify([])
        like = f"%{q}%"
        with db_session() as conn:
            rows = conn.execute(
                """
                SELECT cve_id, state, substr(description,1,280) AS description,
                       cvss_score, severity, date_updated
                FROM cves
                WHERE cve_id LIKE ? OR description LIKE ?
                ORDER BY COALESCE(cvss_score, 0) DESC, cve_id DESC
                LIMIT ?
                """,
                (like, like, limit),
            ).fetchall()
        return jsonify([dict(r) for r in rows])

    @app.get("/api/search/exploit")
    def api_search_exploit():
        q = (request.args.get("q") or "").strip()
        limit = _safe_int(request.args.get("limit", 50), 50, lo=1, hi=200)
        if not q:
            return jsonify([])
        like = f"%{q}%"
        with db_session() as conn:
            rows = conn.execute(
                """
                SELECT edb_id, title, platform, type, date_pub, author, codes, verified
                FROM exploits
                WHERE title LIKE ? OR codes LIKE ? OR platform LIKE ?
                ORDER BY edb_id DESC
                LIMIT ?
                """,
                (like, like, like, limit),
            ).fetchall()
        return jsonify([dict(r) for r in rows])

    @app.get("/api/nse/correlate")
    def api_nse_correlate():
        """Live CVE/Exploit correlation for vulnlocal.nse (vulnlocal.api=...)."""
        product = (request.args.get("product") or "").strip()
        version = (request.args.get("version") or "").strip()
        extrainfo = (request.args.get("extrainfo") or "").strip()
        limit = _safe_int(request.args.get("limit", 50), 50, lo=1, hi=100)
        cpes = request.args.getlist("cpe")
        if not cpes:
            raw = (request.args.get("cpes") or "").strip()
            if raw:
                cpes = [p.strip() for p in raw.split(",") if p.strip()]
        if not product and not cpes and not extrainfo:
            return jsonify({"error": "product, extrainfo, or cpe required"}), 400
        return jsonify(
            nse_correlate(
                product=product,
                version=version,
                cpes=cpes,
                extrainfo=extrainfo,
                limit=limit,
            )
        )

    @app.get("/download/database.zip")
    def download_database_zip():
        path = build_database_zip()
        return send_file(path, as_attachment=True, download_name="vulnlocal-database.zip")

    @app.get("/download/vulnlocal.db")
    def download_sqlite():
        path = copy_sqlite_snapshot()
        return send_file(path, as_attachment=True, download_name="vulnlocal.db")

    @app.get("/download/nse-script.zip")
    def download_nse_script():
        path = copy_nse_script_package()
        return send_file(path, as_attachment=True, download_name="vulnlocal-nse-script.zip")

    @app.get("/download/nse-db")
    def download_nse_db():
        path = copy_nse_sqlite()
        return send_file(path, as_attachment=True, download_name="vulnlocal-nse-pack.zip")

    @app.get("/download/nmap-scanner.zip")
    def download_nmap_scanner():
        path = build_nmap_scanner_zip(force_export=True)
        return send_file(path, as_attachment=True, download_name="vulnlocal-nmap-scanner.zip")

    @app.post("/api/package/nmap")
    def api_package_nmap():
        body, code = _run_background(
            "build_nmap_package",
            lambda: {"path": str(build_nmap_scanner_zip(force_export=True))},
        )
        return jsonify(body), code

    def _busy_if_job():
        running = _job_state.get("running")
        if running:
            return {"status": "busy", "running": running}, 409
        return None

    @app.get("/api/backup")
    def api_backup_list():
        return jsonify({"backups": list_backups()})

    @app.post("/api/backup")
    def api_backup_create():
        busy = _busy_if_job()
        if busy:
            return jsonify(busy[0]), busy[1]
        body = request.get_json(silent=True) or {}
        label = str(body.get("label") or "").strip()
        include_settings = body.get("include_settings", True)
        if isinstance(include_settings, str):
            include_settings = include_settings.lower() not in {"0", "false", "no"}
        try:
            result = create_backup(label=label, include_settings=bool(include_settings))
            return jsonify(result)
        except FileNotFoundError as exc:
            return jsonify({"error": str(exc)}), 404
        except Exception as exc:
            log.exception("Backup failed")
            return jsonify({"error": str(exc)}), 500

    @app.get("/api/backup/<name>")
    def api_backup_download(name: str):
        try:
            path = resolve_backup_path(name)
        except ValueError:
            return jsonify({"error": "invalid backup name"}), 400
        except FileNotFoundError as exc:
            return jsonify({"error": str(exc)}), 404
        return send_file(path, as_attachment=True, download_name=path.name)

    @app.delete("/api/backup/<name>")
    def api_backup_delete(name: str):
        try:
            return jsonify(delete_backup(name))
        except ValueError:
            return jsonify({"error": "invalid backup name"}), 400
        except FileNotFoundError as exc:
            return jsonify({"error": str(exc)}), 404

    @app.post("/api/backup/restore")
    def api_backup_restore():
        busy = _busy_if_job()
        if busy:
            return jsonify(busy[0]), busy[1]
        if not _job_lock.acquire(blocking=False):
            return jsonify({"status": "busy", "running": _job_state.get("running")}), 409
        try:
            body = request.get_json(silent=True) or {}
            name = str(body.get("name") or "").strip()
            restore_settings = body.get("restore_settings", True)
            if isinstance(restore_settings, str):
                restore_settings = restore_settings.lower() not in {"0", "false", "no"}
            if not name:
                return jsonify({"error": "name is required"}), 400
            result = restore_backup(name, restore_settings=bool(restore_settings))
            return jsonify(result)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except FileNotFoundError as exc:
            return jsonify({"error": str(exc)}), 404
        except Exception as exc:
            log.exception("Restore failed")
            return jsonify({"error": str(exc)}), 500
        finally:
            _job_lock.release()

    @app.post("/api/backup/upload")
    def api_backup_upload_restore():
        busy = _busy_if_job()
        if busy:
            return jsonify(busy[0]), busy[1]
        if "file" not in request.files:
            return jsonify({"error": "file is required"}), 400
        upload = request.files["file"]
        if not upload or not upload.filename:
            return jsonify({"error": "empty upload"}), 400
        fname = upload.filename.replace("\\", "/").split("/")[-1]
        lower = fname.lower()
        if not (lower.endswith(".db") or lower.endswith(".zip")):
            return jsonify({"error": "upload must be a .db or .zip backup"}), 400
        if not _job_lock.acquire(blocking=False):
            return jsonify({"status": "busy", "running": _job_state.get("running")}), 409
        staging = config.BACKUP_DIR / "_upload_staging"
        try:
            config.ensure_dirs()
            staging.mkdir(parents=True, exist_ok=True)
            # Normalize to a timestamped local backup name for safe storage
            from datetime import datetime, timezone

            stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            ext = ".zip" if lower.endswith(".zip") else ".db"
            dest = staging / f"vulnlocal-{stamp}-upload{ext}"
            upload.save(dest)
            # Keep a copy under backups/ then restore
            kept = config.BACKUP_DIR / dest.name
            if kept.exists():
                kept.unlink()
            dest.replace(kept)
            restore_settings = request.form.get("restore_settings", "1")
            restore_settings_b = str(restore_settings).lower() not in {"0", "false", "no"}
            result = restore_from_file(kept, restore_settings=restore_settings_b)
            result["saved_as"] = kept.name
            return jsonify(result)
        except Exception as exc:
            log.exception("Upload restore failed")
            return jsonify({"error": str(exc)}), 500
        finally:
            _job_lock.release()
            try:
                if staging.exists():
                    for p in staging.iterdir():
                        p.unlink(missing_ok=True)
            except OSError:
                pass

    @app.post("/api/purge")
    def api_purge_db():
        """Clear all ingested intelligence tables. Requires confirm=PURGE. Refuses while a job runs."""
        busy = _busy_if_job()
        if busy:
            return jsonify(busy[0]), busy[1]
        body = request.get_json(silent=True) or {}
        token = str(body.get("confirm") or "").strip().upper()
        if token != PURGE_CONFIRM_TOKEN:
            return (
                jsonify(
                    {
                        "error": f'Type confirm: "{PURGE_CONFIRM_TOKEN}" to purge ingested data',
                        "required": PURGE_CONFIRM_TOKEN,
                    }
                ),
                400,
            )
        if not _job_lock.acquire(blocking=False):
            return jsonify({"status": "busy", "running": _job_state.get("running")}), 409
        try:
            # Optional safety snapshot before wipe
            try:
                create_backup(label="pre-purge", include_settings=True)
            except Exception as exc:  # noqa: BLE001
                log.warning("Pre-purge backup skipped: %s", exc)
            result = purge_ingested_data(vacuum=True)
            _invalidate_home_caches()
            return jsonify(result)
        except Exception as exc:
            log.exception("Purge failed")
            return jsonify({"error": str(exc)}), 500
        finally:
            _job_lock.release()

    return app
