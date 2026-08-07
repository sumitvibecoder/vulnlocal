"""Build downloadable packages (SQLite DB + offline Nmap scanner)."""

from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

from .. import config
from ..db import db_session, set_meta, utc_now
from ..export.nse_db import export_nse_databases

INSTALL_TXT = """vulnlocal — Nmap vulnerability correlator
==========================================

Works on Windows and Linux/macOS.

Two modes:

1) Online API (vulnlocal app running; http or https):
   nmap -sV --script vulnlocal/vulnlocal \\
     --script-args vulnlocal.api=http://127.0.0.1:8088 <target>
   nmap -sV --script vulnlocal/vulnlocal \\
     --script-args vulnlocal.api=https://127.0.0.1:8443 <target>
   # bare host:port tries http then https
   nmap -sV --script vulnlocal/vulnlocal \\
     --script-args vulnlocal.api=127.0.0.1:8088 <target>

2) Offline pack (pure Lua — no sqlite3 CLI):
   nmap -sV --script vulnlocal/vulnlocal \\
     --script-args "vulnlocal.db=/path/to/vulnlocal.pack" <target>

   After Sync DB / export-nse, `vulnlocal.pack/` is a directory of plain
   TSV buckets. The NSE script reads it with Lua io.open only.

If both are set, API is tried first; the pack is used when the API is unreachable.

Install
-------
1. Copy `vulnlocal.nse` into your Nmap scripts directory, or keep the
   full `vulnlocal/` folder:

   Linux:   /usr/share/nmap/scripts/vulnlocal
   Windows: C:\\Program Files (x86)\\Nmap\\scripts\\vulnlocal

2. For offline mode, place `vulnlocal.pack/` under `db/`
   or pass vulnlocal.db=/path/to/vulnlocal.pack

   On Windows use forward slashes and quotes:
   --script-args "vulnlocal.db=D:/path/to/vulnlocal.pack"

3. Refresh the script database:

   nmap --script-updatedb

Optional script-args
--------------------
  vulnlocal.api=http://127.0.0.1:8088
  vulnlocal.api=https://127.0.0.1:8443
  vulnlocal.db=/path/to/vulnlocal.pack

Notes
-----
- Requires Nmap service/version detection (-sV)
- Findings are potential matches — advisory correlation only
- Rebuild/re-download the pack after syncing feeds
- The vulnlocal app working DB (data/vulnlocal.db) stays plaintext for the UI
"""


def build_nmap_scanner_zip(force_export: bool = True) -> Path:
    """Zip NSE script + offline pack for download."""
    config.ensure_dirs()
    if force_export:
        export_nse_databases()

    if not config.NSE_SCRIPT.is_file():
        raise FileNotFoundError(f"Missing NSE script: {config.NSE_SCRIPT}")
    if not config.NSE_PACK_PATH.is_dir() or not (config.NSE_PACK_PATH / "META").is_file():
        raise FileNotFoundError(f"Missing NSE pack: {config.NSE_PACK_PATH}")

    out = config.PACKAGE_DIR / "vulnlocal-nmap-scanner.zip"
    tmp = out.with_suffix(".zip.part")
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("vulnlocal/INSTALL.txt", INSTALL_TXT)
        zf.write(config.NSE_SCRIPT, arcname="vulnlocal/vulnlocal.nse")
        for path in config.NSE_PACK_PATH.rglob("*"):
            if path.is_file():
                arc = "vulnlocal/db/vulnlocal.pack/" + path.relative_to(config.NSE_PACK_PATH).as_posix()
                zf.write(path, arcname=arc)
    tmp.replace(out)

    with db_session() as conn:
        set_meta(conn, "nse_package_built", utc_now())
    return out


def copy_nse_script_package() -> Path:
    """Zip NSE script (no database) for download."""
    config.ensure_dirs()
    if not config.NSE_SCRIPT.is_file():
        raise FileNotFoundError(f"Missing NSE script: {config.NSE_SCRIPT}")

    out = config.PACKAGE_DIR / "vulnlocal-nse-script.zip"
    tmp = out.with_suffix(".zip.part")
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("vulnlocal/INSTALL.txt", INSTALL_TXT)
        zf.write(config.NSE_SCRIPT, arcname="vulnlocal/vulnlocal.nse")
    tmp.replace(out)
    with db_session() as conn:
        set_meta(conn, "nse_script_package_built", utc_now())
    return out


def copy_nse_sqlite() -> Path:
    """Export/refresh NSE pack and zip it for download."""
    config.ensure_dirs()
    export_nse_databases()
    if not config.NSE_PACK_PATH.is_dir():
        raise FileNotFoundError("NSE pack not found — sync data first")
    out = config.PACKAGE_DIR / "vulnlocal-nse-pack.zip"
    tmp = out.with_suffix(".zip.part")
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in config.NSE_PACK_PATH.rglob("*"):
            if path.is_file():
                arc = "vulnlocal.pack/" + path.relative_to(config.NSE_PACK_PATH).as_posix()
                zf.write(path, arcname=arc)
    tmp.replace(out)
    with db_session() as conn:
        set_meta(conn, "nse_db_package_built", utc_now())
    return out


def build_database_zip() -> Path:
    """Zip the SQLite DB for offline transfer."""
    config.ensure_dirs()
    if not config.SQLITE_PATH.is_file():
        raise FileNotFoundError("SQLite database not found — ingest data first")

    # Keep NSE copy in sync for convenience inside the zip
    try:
        export_nse_databases()
    except Exception:
        pass

    out = config.PACKAGE_DIR / "vulnlocal-database.zip"
    tmp = out.with_suffix(".zip.part")
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(config.SQLITE_PATH, arcname="vulnlocal.db")
        if config.NSE_PACK_PATH.is_dir():
            for path in config.NSE_PACK_PATH.rglob("*"):
                if path.is_file():
                    arc = "nse-vulnlocal.pack/" + path.relative_to(config.NSE_PACK_PATH).as_posix()
                    zf.write(path, arcname=arc)
    tmp.replace(out)

    with db_session() as conn:
        set_meta(conn, "db_package_built", utc_now())
    return out


def copy_sqlite_snapshot() -> Path:
    """Copy SQLite to packages/ for a clean single-file download."""
    config.ensure_dirs()
    if not config.SQLITE_PATH.is_file():
        raise FileNotFoundError("SQLite database not found — ingest data first")
    out = config.PACKAGE_DIR / "vulnlocal.db"
    shutil.copy2(config.SQLITE_PATH, out)
    return out
