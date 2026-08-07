"""Purge ingested intelligence tables from the live SQLite DB."""

from __future__ import annotations

import logging
from typing import Any

from .db import connect, db_session, init_db, set_meta, utc_now
from .progress import set_progress

log = logging.getLogger("vulnlocal.purge")

# Order: children / link tables before parents where FKs exist
PURGE_TABLES = (
    "exploit_cves",
    "exploits",
    "cve_products",
    "cve_cpes",
    "cves",
    "nvd_cves",
    "cwe",
    "tenable_plugin_cves",
    "tenable_plugins",
    "tenable_cves",
    "tenable_attack_techniques",
    "cisa_kev",
    "kevintel_cves",
    "nuclei_template_cves",
    "nuclei_templates",
    "metasploit_module_cves",
    "metasploit_modules",
    "nessus_plugin_cves",
    "nessus_plugins",
    "msrc_remediations",
    "msrc_products",
    "msrc_cves",
    "msrc_updates",
    "capec_cwes",
    "capec",
    "debian_cves",
    "ubuntu_cves",
    "osv_cves",
    "osv_vulns",
    "ghsa_advisories",
    "poc_github",
    "sync_meta",
    "job_log",
)

CONFIRM_TOKEN = "PURGE"
_PURGE_TABLE_SET = frozenset(PURGE_TABLES)


def purge_ingested_data(*, vacuum: bool = True) -> dict[str, Any]:
    """
    Delete all ingested feed rows from the live database.
    Keeps the DB file and schema; does not delete settings.json or downloads/.
    """
    init_db()
    set_progress(phase="purge", label="Purging database", detail="clearing ingested tables")
    cleared: dict[str, int] = {}
    with db_session() as conn:
        for table in PURGE_TABLES:
            if table not in _PURGE_TABLE_SET:
                continue
            try:
                # Table names come only from the frozen PURGE_TABLES constant.
                cur = conn.execute(f"DELETE FROM {table}")  # nosec B608
                cleared[table] = int(cur.rowcount or 0)
            except Exception as exc:  # noqa: BLE001
                log.warning("purge skip %s: %s", table, exc)
                cleared[table] = -1
        set_meta(conn, "last_purge", utc_now())
        set_meta(conn, "last_purge_tables", str(len(PURGE_TABLES)))
        conn.commit()

    if vacuum:
        set_progress(phase="purge", label="Compacting database", detail="VACUUM")
        # VACUUM cannot run inside an open transaction / some WAL contexts — use a fresh connection
        with connect() as conn:
            try:
                conn.isolation_level = None
                conn.execute("VACUUM")
            except Exception as exc:  # noqa: BLE001
                log.warning("VACUUM after purge failed: %s", exc)

    total_rows = sum(n for n in cleared.values() if n > 0)
    set_progress(phase="idle", label="Idle", detail=f"Purged {total_rows:,} rows")
    return {
        "status": "ok",
        "confirm": CONFIRM_TOKEN,
        "tables": cleared,
        "rows_deleted": total_rows,
        "finished_at": utc_now(),
    }
