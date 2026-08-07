"""Shared helpers for incremental Sync DB (skip unchanged remote feeds)."""

from __future__ import annotations

from pathlib import Path

from ..db import db_session, get_meta


def archive_signature(path: Path) -> str:
    """Cheap local fingerprint (size + mtime) to skip re-parsing local archives."""
    st = path.stat()
    return f"{st.st_size}:{int(st.st_mtime)}"


def count_or_zero(table: str) -> int:
    try:
        with db_session() as conn:
            return int(conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"])
    except Exception:
        return 0


def meta_equals(key: str, value: str) -> bool:
    with db_session() as conn:
        return (get_meta(conn, key) or "") == (value or "")
