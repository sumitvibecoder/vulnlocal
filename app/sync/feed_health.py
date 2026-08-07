"""Detect sparse / stuck local feed counts so Sync can force a full reload.

ETag / delta shortcuts are fine once a corpus is healthy. They must not leave
Manage permanently stuck on a tiny seed (CVE limit tests, old GHSA REST ~100, etc.).
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Any

from ..db import db_session

log = logging.getLogger("vulnlocal.feed_health")

# Soft floors — below these, Sync should re-download / re-parse the feed.
FEED_MIN_COUNTS: dict[str, int] = {
    "cves": 100_000,
    "nvd_cves": 100_000,
    "ghsa_advisories": 20_000,
    "exploits": 20_000,
    "cwe": 400,
    "cisa_kev": 500,
    "capec": 400,
    "debian_cves": 10_000,
    "ubuntu_cves": 10_000,
    "osv_vulns": 50_000,
    "poc_github": 5_000,
    "metasploit_modules": 2_000,
    "nessus_plugins": 50_000,
    "msrc_cves": 5_000,
}

# Nuclei after CVE/exploit filter should be far below the full template zip.
NUCLEI_ALL_TEMPLATES_CEILING = 8_000


def _count(conn: sqlite3.Connection, table: str) -> int:
    try:
        return int(conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"])
    except sqlite3.Error:
        return 0


def current_counts(conn: sqlite3.Connection | None = None) -> dict[str, int]:
    def read(c: sqlite3.Connection) -> dict[str, int]:
        out = {name: _count(c, name) for name in FEED_MIN_COUNTS}
        out["nuclei_templates"] = _count(c, "nuclei_templates")
        out["nuclei_template_cves"] = _count(c, "nuclei_template_cves")
        return out

    if conn is not None:
        return read(conn)
    with db_session() as c:
        return read(c)


def sparse_feeds(counts: dict[str, int] | None = None) -> dict[str, dict[str, Any]]:
    """Return {table: {count, minimum, reason}} for feeds that look incomplete."""
    counts = counts or current_counts()
    sparse: dict[str, dict[str, Any]] = {}
    for table, minimum in FEED_MIN_COUNTS.items():
        n = int(counts.get(table) or 0)
        if n < minimum:
            sparse[table] = {
                "count": n,
                "minimum": minimum,
                "reason": f"{n:,} < minimum {minimum:,}",
            }

    nuclei_n = int(counts.get("nuclei_templates") or 0)
    linked = int(counts.get("nuclei_template_cves") or 0)
    # Distinct template ids with CVE links (approx via link rows / templates).
    if nuclei_n > NUCLEI_ALL_TEMPLATES_CEILING:
        sparse["nuclei_templates"] = {
            "count": nuclei_n,
            "minimum": 0,
            "maximum": NUCLEI_ALL_TEMPLATES_CEILING,
            "reason": f"{nuclei_n:,} looks like full template zip (want CVE/exploit only)",
        }
    elif nuclei_n > 0 and linked < int(nuclei_n * 0.5):
        # Many stored templates lack CVE links — reparse with filter.
        sparse["nuclei_templates"] = {
            "count": nuclei_n,
            "linked_rows": linked,
            "reason": f"only {linked:,} CVE link rows for {nuclei_n:,} templates",
        }
    return sparse


def is_sparse(table: str, counts: dict[str, int] | None = None) -> bool:
    return table in sparse_feeds(counts)


def log_sparse_summary(counts: dict[str, int] | None = None) -> dict[str, dict[str, Any]]:
    sparse = sparse_feeds(counts)
    if sparse:
        bits = [f"{k}={v.get('count', 0)}" for k, v in sparse.items()]
        log.warning("Sparse / stuck feeds detected: %s", ", ".join(bits))
    else:
        log.info("Feed health OK — no sparse Manage counts")
    return sparse
