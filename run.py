"""CLI / entrypoint for the vulnlocal web application."""

from __future__ import annotations

import argparse
import os


def _env_flag(name: str) -> bool:
    return (os.environ.get(name) or "").strip().lower() in {"1", "true", "yes", "on"}


def _should_start_background(*, no_scheduler: bool, debug: bool, use_reloader: bool) -> bool:
    """Avoid starting sync threads twice under the Werkzeug debug reloader."""
    if no_scheduler:
        return False
    if debug and use_reloader:
        # Parent reloader process has WERKZEUG_RUN_MAIN unset; child is "true".
        return os.environ.get("WERKZEUG_RUN_MAIN") == "true"
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Local CVE + Exploit-DB mirror and NSE exporter")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument("--no-scheduler", action="store_true")
    parser.add_argument(
        "--dev",
        "-d",
        action="store_true",
        help="Development mode: Flask debug + reloader + template auto-reload "
        "(also set VULNLOCAL_DEV=1). Do not use on exposed hosts.",
    )
    parser.add_argument(
        "--no-reloader",
        action="store_true",
        help="With --dev, disable the auto-reloader (single process, still debug).",
    )
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("init-db", help="Create SQLite schema")
    sub.add_parser("ingest-edb", help="Download official Exploit-DB archive and ingest all CSV indexes")
    p_cve = sub.add_parser("ingest-cve", help="Ingest full CVE List V5 (local tree or official zip)")
    p_cve.add_argument("--force-zip", action="store_true")
    p_cve.add_argument("--limit", type=int, default=None, help="Optional limit for test runs")
    sub.add_parser("ingest-all", help="Full Exploit-DB + CVE ingest, then export NSE DBs")
    sub.add_parser("ingest-msrc", help="Download Microsoft Security Update Guide (MSRC CVRF) for offline use")
    sub.add_parser("sync-cve", help="Apply latest CVE delta.json updates")
    sub.add_parser("export-nse", help="Export offline CSV databases for NSE scripts")
    sub.add_parser("package-nmap", help="Build downloadable offline Nmap scanner zip")
    sub.add_parser("package-db", help="Build downloadable database zip")
    sub.add_parser(
        "clean-downloads",
        help="Delete ingest download zips/JSON under downloads/ (SQLite DB is kept)",
    )
    sub.add_parser(
        "prepare-repo",
        help="Clean downloads, temps, and caches so the tree is safe to push to GitHub",
    )

    args = parser.parse_args()

    from app.db import init_db
    from app.export.nse_db import export_nse_databases
    from app.export.packages import build_database_zip, build_nmap_scanner_zip
    from app.ingest import cve as cve_ingest
    from app.ingest import exploitdb as edb_ingest

    init_db()

    if args.cmd == "init-db":
        from app.settings_store import ensure_default_settings_persisted

        ensure_default_settings_persisted()
        print("Database ready.")
        print("Settings seeded with default sync source URLs.")
        return
    if args.cmd == "ingest-edb":
        from app.download_cleanup import clean_feed_downloads

        print(edb_ingest.download_and_ingest())
        print(clean_feed_downloads("edb"))
        return
    if args.cmd == "ingest-cve":
        from pathlib import Path

        from app.download_cleanup import clean_feed_downloads

        if args.limit:
            root = cve_ingest.resolve_cve_root()
            if root is None:
                downloaded = cve_ingest.download_cve_archive()
                root = cve_ingest.resolve_cve_root()
                if root is None:
                    print(cve_ingest.ingest_from_zip(Path(downloaded), limit=args.limit))
                    print(clean_feed_downloads("cve"))
                    return
            print(cve_ingest.ingest_from_tree(root, limit=args.limit))
            print(clean_feed_downloads("cve"))
            return
        print(
            cve_ingest.download_and_ingest(
                force_zip=bool(args.force_zip) or cve_ingest.needs_full_ingest(),
                prefer_zip_stream=True,
            )
        )
        print(clean_feed_downloads("cve"))
        return
    if args.cmd == "ingest-all":
        from app.download_cleanup import clean_all_downloads, clean_feed_downloads

        print(edb_ingest.download_and_ingest())
        print(clean_feed_downloads("edb"))
        print(
            cve_ingest.download_and_ingest(
                force_zip=cve_ingest.needs_full_ingest(),
                prefer_zip_stream=True,
            )
        )
        print(clean_feed_downloads("cve"))
        print(export_nse_databases())
        print(clean_all_downloads())
        return
    if args.cmd == "ingest-msrc":
        from app.download_cleanup import clean_feed_downloads
        from app.ingest import msrc as msrc_ingest

        print(msrc_ingest.download_and_ingest(full=True))
        print(clean_feed_downloads("msrc"))
        return
    if args.cmd == "sync-cve":
        print(cve_ingest.sync_delta())
        return
    if args.cmd == "export-nse":
        print(export_nse_databases())
        return
    if args.cmd == "package-nmap":
        print(build_nmap_scanner_zip())
        return
    if args.cmd == "package-db":
        print(build_database_zip())
        return
    if args.cmd == "clean-downloads":
        from app.download_cleanup import clean_all_downloads, clean_nse_temp_exports

        print(clean_all_downloads())
        print(clean_nse_temp_exports())
        return
    if args.cmd == "prepare-repo":
        from app.download_cleanup import prepare_repo_tree

        print(prepare_repo_tree(wipe_downloads=True))
        return

    from app import create_app
    from app import config as app_config

    debug = bool(args.dev) or _env_flag("VULNLOCAL_DEV") or _env_flag("FLASK_DEBUG")
    use_reloader = bool(debug) and not args.no_reloader

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        print(
            "WARNING: binding outside loopback exposes Manage/Settings/Backup APIs "
            "on the network. Prefer 127.0.0.1 or put a reverse proxy with auth in front."
        )
        if debug:
            print("ERROR: refusing --dev / debug mode on a non-loopback bind.")
            raise SystemExit(2)

    start_bg = _should_start_background(
        no_scheduler=args.no_scheduler,
        debug=debug,
        use_reloader=use_reloader,
    )
    app = create_app(start_bg=start_bg, debug=debug)

    if debug:
        print(
            f"Development mode on http://{args.host}:{args.port} "
            f"(reloader={'on' if use_reloader else 'off'}, scheduler={'on' if start_bg else 'off'})"
        )

    # Never restart mid-Sync because feed zips / .part files land under downloads/.
    # Also ignore DB backups and local data trees the reloader would otherwise watch.
    exclude_patterns = [
        "*/downloads/*",
        "*/downloads/**",
        "*/data/*",
        "*/data/**",
        "*/backups/*",
        "*/backups/**",
        "*/__pycache__/*",
        "*/.git/*",
        "*.db",
        "*.db-*",
        "*.zip",
        "*.zip.part",
        "*.etag",
        "*.etag.lastmod",
        "*.json.part",
    ]
    # Absolute globs help on Windows where relative patterns can miss paths.
    for root in (
        getattr(app_config, "DOWNLOAD_DIR", None),
        getattr(app_config, "DATA_DIR", None),
        getattr(app_config, "BACKUP_DIR", None),
    ):
        if root is None:
            continue
        p = str(root).replace("\\", "/")
        exclude_patterns.extend([f"{p}/*", f"{p}/**"])

    app.run(
        host=args.host,
        port=args.port,
        debug=debug,
        use_reloader=use_reloader,
        use_debugger=debug,
        threaded=True,
        exclude_patterns=exclude_patterns,
    )


if __name__ == "__main__":
    main()
