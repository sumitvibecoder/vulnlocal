"""Remove bulk download artifacts after successful ingest.

Keeps the SQLite DB and settings; clears feed zips/JSON under downloads/
(and optional CVE extract tree) so the working tree stays publishable.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any

from . import config
from .progress import set_progress

log = logging.getLogger("vulnlocal.cleanup")


def _path_size(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    total = 0
    try:
        for p in path.rglob("*"):
            if p.is_file():
                try:
                    total += p.stat().st_size
                except OSError:
                    pass
    except OSError:
        return total
    return total


def remove_path(path: Path) -> dict[str, Any]:
    """Delete a file or directory tree. Returns size/bytes removed."""
    path = Path(path)
    if not path.exists():
        return {"path": str(path), "removed": False, "bytes": 0}
    nbytes = _path_size(path)
    neighbors: list[Path] = []
    if path.is_file():
        neighbors = [
            Path(str(path) + ".etag"),
            Path(str(path) + ".etag.lastmod"),
            Path(str(path) + ".part"),
            path.with_suffix(path.suffix + ".etag"),
            path.with_suffix(path.suffix + ".part"),
        ]
    try:
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)
        for neighbor in neighbors:
            if neighbor.exists() and neighbor.resolve() != path.resolve():
                try:
                    nbytes += _path_size(neighbor)
                    if neighbor.is_dir():
                        shutil.rmtree(neighbor, ignore_errors=True)
                    else:
                        neighbor.unlink(missing_ok=True)
                except OSError:
                    pass
        log.info("Removed ingest artifact %s (%s bytes)", path, nbytes)
        return {"path": str(path), "removed": True, "bytes": nbytes}
    except OSError as exc:
        log.warning("Failed to remove %s: %s", path, exc)
        return {"path": str(path), "removed": False, "bytes": 0, "error": str(exc)}


def feed_artifact_paths(feed: str) -> list[Path]:
    """Known download / extract paths for a Sync DB feed name."""
    d = config.DOWNLOAD_DIR
    mapping: dict[str, list[Path]] = {
        "edb": [
            d / "exploitdb-main.zip",
            d / "exploitdb-papers-main.zip",
            d / "files_exploits.csv",
            d / "files_shellcodes.csv",
            d / "files_papers.csv",
        ],
        "cve": [
            d / "cvelistV5-bulk.zip",
            d / "delta_cache",
            config.CVE_EXTRACT_DIR,
        ],
        "cwe": [config.CWE_DIR],
        "cisa": [config.CISA_KEV_DIR],
        "capec": [config.CAPEC_DIR],
        "debian": [config.DEBIAN_DIR],
        "ubuntu": [config.UBUNTU_DIR],
        "osv": [config.OSV_DIR],
        "ghsa": [config.GHSA_DIR],
        "poc_github": [config.POC_GITHUB_DIR, config.MARCIO_CVE_DIR, d / "poc_github_cache"],
        "nvd": [config.NVD_FEED_DIR],
        "nuclei": [config.NUCLEI_DIR],
        "metasploit": [config.METASPLOIT_DIR],
        "nessus": [config.NESSUS_PLUGINS_DIR],
        "msrc": [config.MSRC_DIR],
    }
    return list(mapping.get(feed, []))


def clean_feed_downloads(feed: str) -> dict[str, Any]:
    """Delete download artifacts for one feed after a successful ingest."""
    removed: list[dict[str, Any]] = []
    total = 0
    for path in feed_artifact_paths(feed):
        info = remove_path(path)
        if info.get("removed"):
            removed.append(info)
            total += int(info.get("bytes") or 0)
    if removed:
        set_progress(
            phase="cleanup",
            label=f"Freed {feed} downloads",
            detail=f"{len(removed)} path(s), {total:,} bytes",
        )
    return {"feed": feed, "removed": removed, "bytes": total}


def clean_all_downloads(*, also_cve_extract: bool = True) -> dict[str, Any]:
    """Wipe the entire downloads/ tree (and optional CVE extract under data/)."""
    set_progress(phase="cleanup", label="Removing ingest downloads", detail=str(config.DOWNLOAD_DIR))
    removed: list[dict[str, Any]] = []
    total = 0

    root = config.DOWNLOAD_DIR
    if root.is_dir():
        for child in list(root.iterdir()):
            info = remove_path(child)
            if info.get("removed"):
                removed.append(info)
                total += int(info.get("bytes") or 0)
        root.mkdir(parents=True, exist_ok=True)
        keep = root / ".gitkeep"
        if not keep.exists():
            keep.write_text("", encoding="utf-8")

    if also_cve_extract and config.CVE_EXTRACT_DIR.exists():
        info = remove_path(config.CVE_EXTRACT_DIR)
        if info.get("removed"):
            removed.append(info)
            total += int(info.get("bytes") or 0)

    # Drop stale online caches that are not needed offline
    for extra in (config.TENABLE_DIR, config.DOWNLOAD_DIR / "attackerkb", config.DOWNLOAD_DIR / "kevintel", config.DOWNLOAD_DIR / "epss_cache"):
        if extra.exists():
            info = remove_path(extra)
            if info.get("removed"):
                removed.append(info)
                total += int(info.get("bytes") or 0)

    set_progress(phase="idle", label="Idle", detail=f"Cleaned downloads ({total:,} bytes)")
    return {"removed": removed, "bytes": total, "paths": len(removed)}


def clean_nse_temp_exports() -> dict[str, Any]:
    """Remove leftover NSE export temps; keep published vulnlocal.pack (+ optional legacy .db)."""
    removed: list[str] = []
    total = 0
    db_dir = config.NSE_DB_DIR
    if not db_dir.is_dir():
        return {"removed": removed, "bytes": 0}
    keep_names = {
        "vulnlocal.pack",
        "vulnlocal.db",
        "vulnlocal.db-wal",
        "vulnlocal.db-shm",
        ".gitkeep",
    }
    for path in db_dir.iterdir():
        name = path.name
        if name in keep_names:
            continue
        if (
            name.startswith("vulnlocal.export.")
            or name.startswith("vulnlocal.nse.export.")
            or name.startswith("vulnlocal.pack.export.")
            or name.endswith(".db-journal")
        ):
            info = remove_path(path)
            if info.get("removed"):
                removed.append(str(path))
                total += int(info.get("bytes") or 0)
    return {"removed": removed, "bytes": total}


def clean_pycache(root: Path | None = None) -> int:
    root = root or config.BASE_DIR
    count = 0
    for path in root.rglob("__pycache__"):
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
            count += 1
    return count


def prepare_repo_tree(*, wipe_downloads: bool = True) -> dict[str, Any]:
    """Make the vulnlocal tree safe to commit: drop caches, temps, pyc."""
    out: dict[str, Any] = {}
    if wipe_downloads:
        out["downloads"] = clean_all_downloads(also_cve_extract=True)
    out["nse_temps"] = clean_nse_temp_exports()
    out["pycache_dirs"] = clean_pycache()

    # Generated packages / backups (regenerable) — keep settings + main SQLite locally
    extra_removed: list[dict[str, Any]] = []
    for path in (
        config.PACKAGE_DIR,
        config.BACKUP_DIR,
        config.CVE_EXTRACT_DIR,
        config.DATA_DIR / ".secret_key",
    ):
        if path.exists():
            info = remove_path(path)
            if info.get("removed"):
                extra_removed.append(info)
    out["data_extras"] = extra_removed

    # Dead nested / legacy NSE copies from older layouts
    legacy = [
        config.NSE_ROOT / "vulnlocal",
        config.NSE_ROOT / "localvuln",
        config.BASE_DIR.parent / "nse",
    ]
    legacy_removed = []
    for path in legacy:
        if path.exists():
            info = remove_path(path)
            if info.get("removed"):
                legacy_removed.append(info)
    out["legacy"] = legacy_removed

    # Ensure placeholder dirs exist for git
    for path in (config.DOWNLOAD_DIR, config.DATA_DIR, config.NSE_ROOT, config.NSE_DB_DIR):
        path.mkdir(parents=True, exist_ok=True)
    for path in (config.DOWNLOAD_DIR, config.DATA_DIR, config.NSE_DB_DIR):
        keep = path / ".gitkeep"
        if not keep.exists():
            keep.write_text("", encoding="utf-8")

    return out
