"""Local SQLite database backup and restore (stored under data/backups/)."""

from __future__ import annotations

import re
import shutil
import sqlite3
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import config
from .db import set_meta, sqlite_uri, utc_now
from .settings_store import SETTINGS_PATH

_SAFE_NAME_RE = re.compile(r"^vulnlocal-\d{8}-\d{6}(?:-[a-z0-9-]+)?\.(?:db|zip)$", re.I)


def _backup_dir() -> Path:
    config.ensure_dirs()
    config.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    return config.BACKUP_DIR


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _safe_backup_name(name: str) -> str | None:
    base = Path(name or "").name
    if not _SAFE_NAME_RE.match(base):
        return None
    return base


def create_backup(*, label: str = "", include_settings: bool = True) -> dict[str, Any]:
    """
    Snapshot the live SQLite DB into data/backups/ using the SQLite backup API
    (safe with WAL). Optionally bundle settings.json in a zip.
    """
    if not config.SQLITE_PATH.is_file():
        raise FileNotFoundError("Database not found — sync or ingest data first.")

    backup_root = _backup_dir()
    stamp = _stamp()
    suffix = re.sub(r"[^a-z0-9]+", "-", (label or "").strip().lower()).strip("-")[:24]
    base = f"vulnlocal-{stamp}" + (f"-{suffix}" if suffix else "")

    db_path = backup_root / f"{base}.db"
    src = sqlite3.connect(sqlite_uri(config.SQLITE_PATH, mode="ro"), uri=True, timeout=120)
    try:
        dst = sqlite3.connect(str(db_path), timeout=120)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()

    out_path = db_path
    if include_settings and SETTINGS_PATH.is_file():
        zip_path = backup_root / f"{base}.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(db_path, arcname="vulnlocal.db")
            zf.write(SETTINGS_PATH, arcname="settings.json")
        db_path.unlink(missing_ok=True)
        out_path = zip_path

    # Record last backup time in the live DB (best-effort)
    try:
        conn = sqlite3.connect(str(config.SQLITE_PATH), timeout=30)
        try:
            set_meta(conn, "last_db_backup", utc_now())
            set_meta(conn, "last_db_backup_file", out_path.name)
            conn.commit()
        finally:
            conn.close()
    except sqlite3.Error:
        pass

    stat = out_path.stat()
    return {
        "status": "ok",
        "name": out_path.name,
        "path": str(out_path),
        "size": stat.st_size,
        "created_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        "includes_settings": out_path.suffix.lower() == ".zip",
    }


def list_backups() -> list[dict[str, Any]]:
    backup_root = _backup_dir()
    rows: list[dict[str, Any]] = []
    for path in sorted(backup_root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if path.suffix.lower() not in {".db", ".zip"}:
            continue
        if not path.name.lower().startswith("vulnlocal-"):
            continue
        st = path.stat()
        rows.append(
            {
                "name": path.name,
                "size": st.st_size,
                "created_at": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
                "includes_settings": path.suffix.lower() == ".zip",
            }
        )
    return rows


def _is_safe_zip_member(name: str) -> bool:
    """Reject zip-slip paths (absolute / parent traversal)."""
    if not name or name.endswith("/"):
        return False
    p = Path(name)
    if p.is_absolute() or ".." in p.parts:
        return False
    return True


def _extract_db_from_backup(backup_path: Path, work_dir: Path) -> Path:
    if backup_path.suffix.lower() == ".db":
        return backup_path
    if backup_path.suffix.lower() != ".zip":
        raise ValueError("Backup must be a .db or .zip file")
    with zipfile.ZipFile(backup_path, "r") as zf:
        names = [n for n in zf.namelist() if _is_safe_zip_member(n)]
        db_member = next((n for n in names if Path(n).name == "vulnlocal.db"), None)
        if not db_member:
            db_member = next((n for n in names if n.lower().endswith(".db")), None)
        if not db_member:
            raise ValueError("Zip backup does not contain vulnlocal.db")
        # Cap extracted DB size (~8 GiB) to limit zip-bomb impact on disk.
        info = zf.getinfo(db_member)
        if info.file_size > 8 * 1024 * 1024 * 1024:
            raise ValueError("Backup database is too large")
        target = work_dir / "restore-vulnlocal.db"
        with zf.open(db_member) as src, target.open("wb") as dst:
            shutil.copyfileobj(src, dst)
        settings_member = next((n for n in names if Path(n).name == "settings.json"), None)
        if settings_member:
            sinfo = zf.getinfo(settings_member)
            if sinfo.file_size > 2 * 1024 * 1024:
                raise ValueError("settings.json in backup is too large")
            settings_out = work_dir / "restore-settings.json"
            with zf.open(settings_member) as src, settings_out.open("wb") as dst:
                shutil.copyfileobj(src, dst)
        return target


def restore_backup(name: str, *, restore_settings: bool = True) -> dict[str, Any]:
    """Replace the live database contents from a named backup under data/backups/."""
    safe = _safe_backup_name(name)
    if not safe:
        raise ValueError("Invalid backup name")
    backup_path = _backup_dir() / safe
    if not backup_path.is_file():
        raise FileNotFoundError(f"Backup not found: {safe}")
    return restore_from_file(backup_path, restore_settings=restore_settings)


def restore_from_file(path: Path, *, restore_settings: bool = True) -> dict[str, Any]:
    """Restore live DB from a .db or .zip path (must already be trusted/local)."""
    if not path.is_file():
        raise FileNotFoundError(str(path))

    work = _backup_dir() / "_restore_work"
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)

    try:
        # Safety snapshot of current DB before overwrite
        if config.SQLITE_PATH.is_file():
            create_backup(label="pre-restore", include_settings=False)

        db_src = _extract_db_from_backup(path, work)
        # Verify readable SQLite
        probe = sqlite3.connect(sqlite_uri(db_src, mode="ro"), uri=True, timeout=30)
        try:
            probe.execute("SELECT count(*) FROM sqlite_master").fetchone()
        finally:
            probe.close()

        config.SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)
        dst = sqlite3.connect(str(config.SQLITE_PATH), timeout=120)
        src = sqlite3.connect(sqlite_uri(db_src, mode="ro"), uri=True, timeout=120)
        try:
            src.backup(dst)
            dst.commit()
        finally:
            src.close()
            dst.close()

        settings_restored = False
        settings_candidate = work / "restore-settings.json"
        if restore_settings and settings_candidate.is_file():
            SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(settings_candidate, SETTINGS_PATH)
            settings_restored = True
            try:
                from .settings_store import load_settings
                from . import httputil

                load_settings(force=True)
                httputil.reset_session()
            except Exception:
                pass

        return {
            "status": "ok",
            "restored_from": path.name,
            "settings_restored": settings_restored,
            "finished_at": utc_now(),
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)


def delete_backup(name: str) -> dict[str, Any]:
    safe = _safe_backup_name(name)
    if not safe:
        raise ValueError("Invalid backup name")
    path = _backup_dir() / safe
    if not path.is_file():
        raise FileNotFoundError(f"Backup not found: {safe}")
    path.unlink()
    return {"status": "deleted", "name": safe}


def resolve_backup_path(name: str) -> Path:
    safe = _safe_backup_name(name)
    if not safe:
        raise ValueError("Invalid backup name")
    path = _backup_dir() / safe
    if not path.is_file():
        raise FileNotFoundError(f"Backup not found: {safe}")
    return path
