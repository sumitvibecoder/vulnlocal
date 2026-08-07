"""SQLite helpers and schema."""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from . import config

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS exploits (
    edb_id           INTEGER PRIMARY KEY,
    path             TEXT,
    title            TEXT NOT NULL,
    date_pub         TEXT,
    author           TEXT,
    type             TEXT,
    platform         TEXT,
    port             TEXT,
    codes            TEXT,
    tags             TEXT,
    verified         INTEGER DEFAULT 0,
    kind             TEXT DEFAULT 'exploit',
    aliases          TEXT,
    application_url  TEXT,
    source_url       TEXT,
    screenshot_url   TEXT,
    date_added       TEXT,
    date_updated     TEXT,
    updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exploits_title ON exploits(title);
CREATE INDEX IF NOT EXISTS idx_exploits_platform ON exploits(platform);
CREATE INDEX IF NOT EXISTS idx_exploits_type ON exploits(type);
CREATE INDEX IF NOT EXISTS idx_exploits_date_pub ON exploits(date_pub);

CREATE TABLE IF NOT EXISTS exploit_cves (
    edb_id  INTEGER NOT NULL,
    cve_id  TEXT NOT NULL,
    PRIMARY KEY (edb_id, cve_id),
    FOREIGN KEY (edb_id) REFERENCES exploits(edb_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_exploit_cves_cve ON exploit_cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_exploit_cves_edb ON exploit_cves(edb_id);

CREATE TABLE IF NOT EXISTS cves (
    cve_id          TEXT PRIMARY KEY,
    state           TEXT,
    description     TEXT,
    date_published  TEXT,
    date_updated    TEXT,
    cvss_score      REAL,
    cvss_vector     TEXT,
    severity        TEXT,
    assigner        TEXT,
    source_path     TEXT,
    updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cves_updated ON cves(date_updated);
CREATE INDEX IF NOT EXISTS idx_cves_score ON cves(cvss_score);
CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(date_published);

CREATE TABLE IF NOT EXISTS cve_products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id      TEXT NOT NULL,
    vendor      TEXT,
    product     TEXT,
    version     TEXT,
    status      TEXT,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cve_products_product ON cve_products(product);
CREATE INDEX IF NOT EXISTS idx_cve_products_vendor ON cve_products(vendor);
CREATE INDEX IF NOT EXISTS idx_cve_products_cve ON cve_products(cve_id);

CREATE TABLE IF NOT EXISTS cve_cpes (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id  TEXT NOT NULL,
    cpe     TEXT NOT NULL,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cve_cpes_cpe ON cve_cpes(cpe);
CREATE INDEX IF NOT EXISTS idx_cve_cpes_cve ON cve_cpes(cve_id);

-- NVD cpeMatch rows with versionStart/End bounds (Vulners-like range matching).
CREATE TABLE IF NOT EXISTS cve_cpe_matches (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id          TEXT NOT NULL,
    cpe             TEXT NOT NULL,
    soft            TEXT,
    version         TEXT,
    update_token    TEXT,
    ver_start_incl  TEXT,
    ver_start_excl  TEXT,
    ver_end_incl    TEXT,
    ver_end_excl    TEXT,
    vulnerable      INTEGER DEFAULT 1,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cve_cpe_matches_soft ON cve_cpe_matches(soft);
CREATE INDEX IF NOT EXISTS idx_cve_cpe_matches_cve ON cve_cpe_matches(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_cpe_matches_cpe ON cve_cpe_matches(cpe);

CREATE TABLE IF NOT EXISTS nvd_cves (
    cve_id          TEXT PRIMARY KEY,
    vuln_status     TEXT,
    source_id       TEXT,
    published       TEXT,
    last_modified   TEXT,
    description     TEXT,
    cvss_version    TEXT,
    cvss_score      REAL,
    cvss_vector     TEXT,
    severity        TEXT,
    cwe_ids         TEXT,
    cpes_json       TEXT,
    cpe_matches_json TEXT,
    references_json TEXT,
    metrics_json    TEXT,
    updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nvd_cves_score ON nvd_cves(cvss_score);
CREATE INDEX IF NOT EXISTS idx_nvd_cves_modified ON nvd_cves(last_modified);

CREATE TABLE IF NOT EXISTS cwe (
    cwe_id      TEXT PRIMARY KEY,
    name        TEXT,
    abstraction TEXT,
    description TEXT,
    url         TEXT,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenable_plugins (
    plugin_id       TEXT NOT NULL,
    sensor          TEXT NOT NULL,
    name            TEXT,
    family          TEXT,
    severity        TEXT,
    synopsis        TEXT,
    description     TEXT,
    solution        TEXT,
    see_also_json   TEXT,
    references_json TEXT,
    cves_json       TEXT,
    cwe_json        TEXT,
    cvss_score      REAL,
    cvss_vector     TEXT,
    vpr_score       REAL,
    exploit_available INTEGER DEFAULT 0,
    exploitability  TEXT,
    plugin_type     TEXT,
    published       TEXT,
    modified        TEXT,
    detail_url      TEXT,
    raw_json        TEXT,
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (plugin_id, sensor)
);

CREATE INDEX IF NOT EXISTS idx_tenable_plugins_name ON tenable_plugins(name);

CREATE TABLE IF NOT EXISTS tenable_plugin_cves (
    plugin_id   TEXT NOT NULL,
    sensor      TEXT NOT NULL,
    cve_id      TEXT NOT NULL,
    PRIMARY KEY (plugin_id, sensor, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_tenable_plugin_cves_cve ON tenable_plugin_cves(cve_id);

CREATE TABLE IF NOT EXISTS tenable_cves (
    cve_id          TEXT PRIMARY KEY,
    description     TEXT,
    severity        TEXT,
    cvss3_score     REAL,
    cvss3_vector    TEXT,
    epss_score      REAL,
    cisa_kev        TEXT,
    references_json TEXT,
    cpes_json       TEXT,
    detail_url      TEXT,
    raw_json        TEXT,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenable_attack_techniques (
    attack_id       TEXT PRIMARY KEY,
    name            TEXT,
    platforms_json  TEXT,
    families_json   TEXT,
    framework       TEXT,
    description     TEXT,
    detail_url      TEXT,
    raw_json        TEXT,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cisa_kev (
    cve_id              TEXT PRIMARY KEY,
    vendor_project      TEXT,
    product             TEXT,
    vulnerability_name  TEXT,
    date_added          TEXT,
    short_description   TEXT,
    required_action     TEXT,
    due_date            TEXT,
    known_ransomware    TEXT,
    notes               TEXT,
    cwes_json           TEXT,
    detail_url          TEXT,
    raw_json            TEXT,
    updated_at          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cisa_kev_date ON cisa_kev(date_added);

CREATE TABLE IF NOT EXISTS kevintel_cves (
    cve_id                  TEXT PRIMARY KEY,
    title                   TEXT,
    vendor                  TEXT,
    product                 TEXT,
    confidence              TEXT,
    in_cisa_kev             INTEGER DEFAULT 0,
    not_yet_in_cisa_kev     INTEGER DEFAULT 0,
    observed_in_sensors     INTEGER DEFAULT 0,
    total_attempts          INTEGER,
    unique_attacker_ips     INTEGER,
    countries_json          TEXT,
    sensors_json            TEXT,
    first_observed          TEXT,
    last_observed           TEXT,
    used_in_malware         TEXT,
    has_poc                 INTEGER DEFAULT 0,
    has_nuclei              INTEGER DEFAULT 0,
    has_metasploit          INTEGER DEFAULT 0,
    virtual_patch           INTEGER DEFAULT 0,
    added_date              TEXT,
    detail_url              TEXT,
    observations_json       TEXT,
    raw_json                TEXT,
    updated_at              TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_kevintel_observed ON kevintel_cves(observed_in_sensors);

CREATE TABLE IF NOT EXISTS nuclei_templates (
    template_id     TEXT PRIMARY KEY,
    name            TEXT,
    severity        TEXT,
    author          TEXT,
    description     TEXT,
    tags            TEXT,
    path            TEXT,
    detail_url      TEXT,
    raw_json        TEXT,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nuclei_template_cves (
    template_id TEXT NOT NULL,
    cve_id      TEXT NOT NULL,
    PRIMARY KEY (template_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_nuclei_template_cves_cve ON nuclei_template_cves(cve_id);

CREATE TABLE IF NOT EXISTS metasploit_modules (
    fullname        TEXT PRIMARY KEY,
    name            TEXT,
    module_type     TEXT,
    rank            TEXT,
    description     TEXT,
    platform        TEXT,
    arch            TEXT,
    path            TEXT,
    detail_url      TEXT,
    edb_ids_json    TEXT,
    raw_json        TEXT,
    updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_metasploit_modules_type ON metasploit_modules(module_type);

CREATE TABLE IF NOT EXISTS metasploit_module_cves (
    fullname    TEXT NOT NULL,
    cve_id      TEXT NOT NULL,
    PRIMARY KEY (fullname, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_metasploit_module_cves_cve ON metasploit_module_cves(cve_id);

CREATE TABLE IF NOT EXISTS nessus_plugins (
    plugin_id       TEXT PRIMARY KEY,
    name            TEXT,
    summary         TEXT,
    synopsis        TEXT,
    description     TEXT,
    solution        TEXT,
    family          TEXT,
    risk_factor     TEXT,
    filename        TEXT,
    version         TEXT,
    see_also_json   TEXT,
    xrefs_json      TEXT,
    edb_ids_json    TEXT,
    detail_url      TEXT,
    raw_json        TEXT,
    updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nessus_plugins_name ON nessus_plugins(name);

CREATE TABLE IF NOT EXISTS nessus_plugin_cves (
    plugin_id   TEXT NOT NULL,
    cve_id      TEXT NOT NULL,
    PRIMARY KEY (plugin_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_nessus_plugin_cves_cve ON nessus_plugin_cves(cve_id);

CREATE TABLE IF NOT EXISTS msrc_updates (
    update_id         TEXT PRIMARY KEY,
    title             TEXT,
    initial_release   TEXT,
    current_release   TEXT,
    cvrf_url          TEXT,
    vuln_count        INTEGER DEFAULT 0,
    updated_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS msrc_products (
    update_id   TEXT NOT NULL,
    product_id  TEXT NOT NULL,
    name        TEXT,
    cpe         TEXT,
    PRIMARY KEY (update_id, product_id)
);

CREATE TABLE IF NOT EXISTS msrc_cves (
    cve_id          TEXT NOT NULL,
    update_id       TEXT NOT NULL,
    title           TEXT,
    severity        TEXT,
    impact          TEXT,
    cvss_score      REAL,
    cvss_vector     TEXT,
    exploit_status  TEXT,
    detail_url      TEXT,
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (cve_id, update_id)
);

CREATE INDEX IF NOT EXISTS idx_msrc_cves_cve ON msrc_cves(cve_id);

CREATE TABLE IF NOT EXISTS msrc_remediations (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id            TEXT NOT NULL,
    update_id         TEXT NOT NULL,
    kb                TEXT,
    url               TEXT,
    subtype           TEXT,
    fixed_build       TEXT,
    restart_required  TEXT,
    product_names     TEXT
);

CREATE INDEX IF NOT EXISTS idx_msrc_remediations_cve ON msrc_remediations(cve_id);

CREATE TABLE IF NOT EXISTS capec (
    capec_id        TEXT PRIMARY KEY,
    name            TEXT,
    abstraction     TEXT,
    status          TEXT,
    description     TEXT,
    likelihood      TEXT,
    severity        TEXT,
    detail_url      TEXT,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS capec_cwes (
    capec_id    TEXT NOT NULL,
    cwe_id      TEXT NOT NULL,
    PRIMARY KEY (capec_id, cwe_id)
);
CREATE INDEX IF NOT EXISTS idx_capec_cwes_cwe ON capec_cwes(cwe_id);

CREATE TABLE IF NOT EXISTS debian_cves (
    cve_id          TEXT PRIMARY KEY,
    scope           TEXT,
    description     TEXT,
    debianbug       TEXT,
    packages_json   TEXT,
    detail_url      TEXT,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ubuntu_cves (
    cve_id          TEXT PRIMARY KEY,
    title           TEXT,
    description     TEXT,
    priority        TEXT,
    published       TEXT,
    packages_json   TEXT,
    notices_json    TEXT,
    detail_url      TEXT,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS osv_vulns (
    osv_id          TEXT PRIMARY KEY,
    summary         TEXT,
    details         TEXT,
    severity        TEXT,
    published       TEXT,
    modified        TEXT,
    aliases_json    TEXT,
    packages_json   TEXT,
    detail_url      TEXT,
    updated_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS osv_cves (
    osv_id  TEXT NOT NULL,
    cve_id  TEXT NOT NULL,
    PRIMARY KEY (osv_id, cve_id)
);
CREATE INDEX IF NOT EXISTS idx_osv_cves_cve ON osv_cves(cve_id);

CREATE TABLE IF NOT EXISTS ghsa_advisories (
    ghsa_id         TEXT PRIMARY KEY,
    cve_id          TEXT,
    summary         TEXT,
    severity        TEXT,
    published_at    TEXT,
    updated_at_src  TEXT,
    html_url        TEXT,
    packages_json   TEXT,
    updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ghsa_cve ON ghsa_advisories(cve_id);

CREATE TABLE IF NOT EXISTS poc_github (
    cve_id          TEXT NOT NULL,
    html_url        TEXT NOT NULL,
    full_name       TEXT,
    description     TEXT,
    stargazers      INTEGER,
    language        TEXT,
    updated_at_src  TEXT,
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (cve_id, html_url)
);
CREATE INDEX IF NOT EXISTS idx_poc_github_cve ON poc_github(cve_id);

CREATE TABLE IF NOT EXISTS sync_meta (
    key         TEXT PRIMARY KEY,
    value       TEXT,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS job_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    job_name    TEXT NOT NULL,
    status      TEXT NOT NULL,
    message     TEXT,
    started_at  TEXT NOT NULL,
    finished_at TEXT
);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sqlite_uri(path: Path | str, *, mode: str = "ro") -> str:
    """Build a portable ``file:`` URI for sqlite3 (Windows + Linux/macOS).

    Prefer this over ``f"file:{path}?mode=…"`` so drive letters, spaces, and
    backslashes are encoded correctly via :meth:`Path.as_uri`.
    """
    return f"{Path(path).expanduser().resolve().as_uri()}?mode={mode}"


def connect(db_path: Path | None = None) -> sqlite3.Connection:
    config.ensure_dirs()
    path = db_path or config.SQLITE_PATH
    conn = sqlite3.connect(str(path), check_same_thread=False, timeout=120)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=120000")
    return conn


_EXPLOIT_EXTRA_COLUMNS: dict[str, str] = {
    "aliases": "TEXT",
    "application_url": "TEXT",
    "source_url": "TEXT",
    "screenshot_url": "TEXT",
    "date_added": "TEXT",
    "date_updated": "TEXT",
}


def _ensure_table_columns(
    conn: sqlite3.Connection,
    table: str,
    columns: dict[str, str],
) -> None:
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    for name, col_type in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {col_type}")


def init_db(db_path: Path | None = None) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)
        # Drop retired feeds (schema no longer creates these tables).
        conn.execute("DROP TABLE IF EXISTS attackerkb_topics")
        _ensure_table_columns(conn, "exploits", _EXPLOIT_EXTRA_COLUMNS)
        _ensure_table_columns(
            conn,
            "nvd_cves",
            {"cpe_matches_json": "TEXT"},
        )
        _ensure_exploit_cve_map(conn)
        conn.commit()


_CVE_IN_CODES_RE = re.compile(r"CVE-\d{4}-\d+", re.I)


def extract_cve_ids_from_codes(codes: str | None) -> list[str]:
    """Pull CVE-YYYY-NNNN tokens from an Exploit-DB codes field."""
    if not codes:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for m in _CVE_IN_CODES_RE.finditer(codes):
        cve_id = m.group(0).upper()
        if cve_id not in seen:
            seen.add(cve_id)
            out.append(cve_id)
    return out


def replace_exploit_cve_links(conn: sqlite3.Connection, rows: list[dict[str, Any]]) -> int:
    """Refresh exploit_cves rows for the given exploit upsert batch."""
    if not rows:
        return 0
    edb_ids = [(int(r["edb_id"]),) for r in rows]
    conn.executemany("DELETE FROM exploit_cves WHERE edb_id = ?", edb_ids)
    links: list[tuple[int, str]] = []
    for r in rows:
        edb_id = int(r["edb_id"])
        for cve_id in extract_cve_ids_from_codes(r.get("codes")):
            links.append((edb_id, cve_id))
    if links:
        conn.executemany(
            "INSERT OR IGNORE INTO exploit_cves(edb_id, cve_id) VALUES (?, ?)",
            links,
        )
    return len(links)


def rebuild_exploit_cve_map(conn: sqlite3.Connection) -> int:
    """Full rebuild of CVE↔EDB links from exploits.codes (one-time / repair)."""
    conn.execute("DELETE FROM exploit_cves")
    links: list[tuple[int, str]] = []
    for row in conn.execute(
        "SELECT edb_id, codes FROM exploits WHERE codes IS NOT NULL AND codes != ''"
    ):
        for cve_id in extract_cve_ids_from_codes(row["codes"]):
            links.append((int(row["edb_id"]), cve_id))
    if links:
        conn.executemany(
            "INSERT OR IGNORE INTO exploit_cves(edb_id, cve_id) VALUES (?, ?)",
            links,
        )
    set_meta(conn, "exploit_cve_map_count", str(len(links)))
    set_meta(conn, "exploit_cve_map_built", utc_now())
    return len(links)


def _ensure_exploit_cve_map(conn: sqlite3.Connection) -> None:
    """Build the CVE↔EDB index once if exploits exist but the map is empty."""
    mapped = conn.execute("SELECT COUNT(*) AS n FROM exploit_cves").fetchone()["n"]
    if mapped:
        return
    with_cve = conn.execute(
        "SELECT COUNT(*) AS n FROM exploits WHERE codes LIKE '%CVE-%' OR codes LIKE '%cve-%'"
    ).fetchone()["n"]
    if with_cve:
        rebuild_exploit_cve_map(conn)


@contextmanager
def db_session(db_path: Path | None = None) -> Iterator[sqlite3.Connection]:
    conn = connect(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        """
        INSERT INTO sync_meta(key, value, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
        """,
        (key, value, utc_now()),
    )


def get_meta(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM sync_meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def log_job_start(conn: sqlite3.Connection, job_name: str) -> int:
    cur = conn.execute(
        "INSERT INTO job_log(job_name, status, message, started_at) VALUES (?, ?, ?, ?)",
        (job_name, "running", "", utc_now()),
    )
    return int(cur.lastrowid)


def log_job_finish(
    conn: sqlite3.Connection,
    job_id: int,
    status: str,
    message: str = "",
) -> None:
    conn.execute(
        "UPDATE job_log SET status=?, message=?, finished_at=? WHERE id=?",
        (status, message, utc_now(), job_id),
    )


_overview_refresh_hook: Any = None


def set_overview_refresh_hook(fn: Any) -> None:
    """Optional callback after overview cache rewrite (e.g. invalidate home SSR cache)."""
    global _overview_refresh_hook
    _overview_refresh_hook = fn


def invalidate_nvd_product_counts(conn: sqlite3.Connection) -> None:
    set_meta(conn, "nvd_product_counts_json", "")


def _nvd_product_vendor_counts(conn: sqlite3.Connection, nvd_n: int) -> tuple[int, int]:
    """Distinct product/vendor counts from NVD CPEs (cached; ~15s full scan)."""
    raw = get_meta(conn, "nvd_product_counts_json")
    if raw:
        try:
            cached = json.loads(raw)
            cached_n = int(cached.get("nvd_n") or 0)
            # Reuse while NVD row count is close (avoids rescanning mid-sync).
            if abs(cached_n - nvd_n) <= max(500, int(nvd_n * 0.01)):
                return int(cached.get("products") or 0), int(cached.get("vendors") or 0)
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

    prod_set: set[str] = set()
    vend_set: set[str] = set()
    for (raw_cpe,) in conn.execute(
        "SELECT cpes_json FROM nvd_cves WHERE cpes_json IS NOT NULL AND length(cpes_json) > 4"
    ):
        try:
            arr = json.loads(raw_cpe)
        except json.JSONDecodeError:
            continue
        if not isinstance(arr, list):
            continue
        for cpe in arr:
            parts = str(cpe).split(":")
            if len(parts) < 5:
                continue
            if parts[3] and parts[3] != "*":
                vend_set.add(parts[3].lower())
            if parts[4] and parts[4] != "*":
                prod_set.add(parts[4].lower())
    products = len(prod_set)
    vendors = len(vend_set)
    set_meta(
        conn,
        "nvd_product_counts_json",
        json.dumps({"nvd_n": nvd_n, "products": products, "vendors": vendors}),
    )
    return products, vendors


def compute_overview(conn: sqlite3.Connection, *, allow_nvd_product_scan: bool = True) -> dict[str, Any]:
    """Aggregate home-screen overview: products, threat categories, severity.

    Severity prefers the richest table (usually NVD). Product counts fall back to
    cached NVD CPE distincts when CVE List products are sparse.
    """
    from .threat_categories import category_labels, merge_overview_categories, overview_category_counts_sql

    products = int(
        conn.execute(
            """
            SELECT COUNT(DISTINCT lower(product)) AS n
            FROM cve_products
            WHERE product IS NOT NULL AND trim(product) != ''
            """
        ).fetchone()["n"]
    )
    vendors = int(
        conn.execute(
            """
            SELECT COUNT(DISTINCT lower(vendor)) AS n
            FROM cve_products
            WHERE vendor IS NOT NULL AND trim(vendor) != ''
            """
        ).fetchone()["n"]
    )
    product_source = "cve_products"

    edb_rows = conn.execute(
        """
        SELECT lower(type) AS name, COUNT(*) AS n
        FROM exploits
        WHERE type IS NOT NULL AND trim(type) != ''
        GROUP BY lower(type)
        ORDER BY n DESC
        """
    ).fetchall()
    edb_categories = [{"name": r["name"], "count": int(r["n"])} for r in edb_rows]

    cve_categories: list[dict[str, Any]] = []
    try:
        # Full description CASE over 300k+ rows is too slow; sample newest instead.
        cve_n_cats = int(conn.execute("SELECT COUNT(*) AS n FROM cves").fetchone()["n"])
        try:
            nvd_n_cats = int(conn.execute("SELECT COUNT(*) AS n FROM nvd_cves").fetchone()["n"])
        except sqlite3.Error:
            nvd_n_cats = 0
        cat_table = "nvd_cves" if nvd_n_cats >= max(cve_n_cats, 1) else "cves"
        sample = 40_000 if max(cve_n_cats, nvd_n_cats) > 25_000 else None
        cve_rows = conn.execute(
            overview_category_counts_sql(table=cat_table, sample_limit=sample)
        ).fetchall()
        cve_categories = [{"name": r["name"], "count": int(r["n"])} for r in cve_rows]
        # Scale sample counts up to corpus size so home bars reflect full volume.
        if sample and cve_categories:
            corpus = nvd_n_cats if cat_table == "nvd_cves" else cve_n_cats
            sampled = sum(int(r["count"]) for r in cve_categories)
            if sampled > 0 and corpus > sampled:
                scale = corpus / sampled
                cve_categories = [
                    {"name": r["name"], "count": int(round(int(r["count"]) * scale))}
                    for r in cve_categories
                ]
    except sqlite3.Error:
        cve_categories = []

    categories = merge_overview_categories(cve_categories, edb_categories)

    # Prefer the richest severity corpus. CVE List may be sparse while NVD is full.
    cve_n = int(conn.execute("SELECT COUNT(*) AS n FROM cves").fetchone()["n"])
    try:
        nvd_n = int(conn.execute("SELECT COUNT(*) AS n FROM nvd_cves").fetchone()["n"])
    except sqlite3.Error:
        nvd_n = 0

    # Prefer NVD CPE product/vendor distincts whenever they beat thin cve_products.
    # (Do NOT require nvd_n > cve_n — after CVE↔NVD mirror the counts are ~equal.)
    if nvd_n > 1_000 and products < 5_000:
        raw_pc = get_meta(conn, "nvd_product_counts_json")
        have_cache = False
        if raw_pc:
            try:
                cached_pc = json.loads(raw_pc)
                cached_n = int(cached_pc.get("nvd_n") or 0)
                if abs(cached_n - nvd_n) <= max(500, int(nvd_n * 0.01)):
                    nvd_products = int(cached_pc.get("products") or 0)
                    nvd_vendors = int(cached_pc.get("vendors") or 0)
                    have_cache = nvd_products > 0
                    if have_cache and nvd_products > products:
                        products = nvd_products
                        vendors = nvd_vendors
                        product_source = "nvd_cpes"
            except (json.JSONDecodeError, TypeError, ValueError):
                have_cache = False
        if not have_cache and allow_nvd_product_scan:
            nvd_products, nvd_vendors = _nvd_product_vendor_counts(conn, nvd_n)
            if nvd_products > products:
                products = nvd_products
                vendors = nvd_vendors
                product_source = "nvd_cpes"
        elif not have_cache and not allow_nvd_product_scan:
            # Still try previously stored cache even if nvd_n drifted slightly.
            if raw_pc:
                try:
                    cached_pc = json.loads(raw_pc)
                    nvd_products = int(cached_pc.get("products") or 0)
                    nvd_vendors = int(cached_pc.get("vendors") or 0)
                    if nvd_products > products:
                        products = nvd_products
                        vendors = nvd_vendors
                        product_source = "nvd_cpes"
                except (json.JSONDecodeError, TypeError, ValueError):
                    pass

    # Prefer NVD severity when it is at least as complete as CVE List.
    sev_table = "nvd_cves" if nvd_n >= max(cve_n, 1) or (
        nvd_n > 100_000 and nvd_n >= int(cve_n * 0.9)
    ) else "cves"
    if sev_table not in {"cves", "nvd_cves"}:
        sev_table = "cves"

    sev_rows = conn.execute(
        f"""
        SELECT
          CASE
            WHEN upper(severity) IN ('CRITICAL','HIGH','MEDIUM','LOW') THEN upper(severity)
            WHEN cvss_score >= 9 THEN 'CRITICAL'
            WHEN cvss_score >= 7 THEN 'HIGH'
            WHEN cvss_score >= 4 THEN 'MEDIUM'
            WHEN cvss_score > 0 THEN 'LOW'
            ELSE NULL
          END AS sev,
          COUNT(*) AS n
        FROM {sev_table}
        GROUP BY sev
        """  # nosec B608 — table name is allowlisted above
    ).fetchall()
    severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unrated": 0}
    for r in sev_rows:
        key = (r["sev"] or "unrated").lower()
        if key in severity:
            severity[key] = int(r["n"])
        else:
            severity["unrated"] += int(r["n"])

    rated = severity["critical"] + severity["high"] + severity["medium"] + severity["low"]
    return {
        "affected_products": int(products),
        "vendors": int(vendors),
        "threat_categories": len(category_labels()),
        "categories": categories,
        "vulnerabilities": {
            **severity,
            "rated": rated,
            "total": rated + severity["unrated"],
        },
        "severity_source": sev_table,
        "product_source": product_source,
        "cve_rows": cve_n,
        "nvd_rows": nvd_n,
        "updated_at": utc_now(),
    }


def refresh_overview(conn: sqlite3.Connection, *, allow_nvd_product_scan: bool = True) -> dict[str, Any]:
    data = compute_overview(conn, allow_nvd_product_scan=allow_nvd_product_scan)
    set_meta(conn, "overview_stats_json", json.dumps(data))
    hook = _overview_refresh_hook
    if callable(hook):
        try:
            hook()
        except Exception:
            pass
    return data


def _overview_is_stale(conn: sqlite3.Connection, data: dict[str, Any]) -> bool:
    """True when cached home overview does not reflect the richest synced sources."""
    vuln = data.get("vulnerabilities") or {}
    total = int(vuln.get("total") or 0)
    products = int(data.get("affected_products") or 0)
    sev_src = str(data.get("severity_source") or "")
    try:
        cve_n = int(conn.execute("SELECT COUNT(*) AS n FROM cves").fetchone()["n"])
    except sqlite3.Error:
        cve_n = 0
    try:
        nvd_n = int(conn.execute("SELECT COUNT(*) AS n FROM nvd_cves").fetchone()["n"])
    except sqlite3.Error:
        nvd_n = 0
    try:
        edb_n = int(conn.execute("SELECT COUNT(*) AS n FROM exploits").fetchone()["n"])
    except sqlite3.Error:
        edb_n = 0

    # NVD is rich but overview still shows CVE-List-sized totals
    if nvd_n > 10_000 and total < max(1000, int(nvd_n * 0.05)):
        return True
    if nvd_n > max(cve_n * 5, 1000) and sev_src in {"", "cves"}:
        return True
    if nvd_n > 10_000 and products < 1000:
        return True
    # Cached NVD CPE distincts exist but overview still shows thin cve_products
    if products < 5_000 and nvd_n > 10_000:
        raw_pc = get_meta(conn, "nvd_product_counts_json")
        if raw_pc:
            try:
                cached_pc = json.loads(raw_pc)
                if int(cached_pc.get("products") or 0) > max(products * 2, 1000):
                    return True
            except (json.JSONDecodeError, TypeError, ValueError):
                pass
    # Totals drifted after a later NVD sync (more than 2% behind)
    if nvd_n > 10_000 and sev_src == "nvd_cves" and total < int(nvd_n * 0.98):
        return True
    # Categories empty while Exploit-DB is loaded
    cats = data.get("categories") or []
    if edb_n > 1000 and not cats:
        return True
    return False


def peek_overview(conn: sqlite3.Connection) -> dict[str, Any]:
    """Return cached overview JSON only — never recompute (safe for home polls).

    Applies a cheap NVD product-count overlay when the cached overview still has
    sparse cve_products distincts but nvd_product_counts_json is already rich.
    """
    raw = get_meta(conn, "overview_stats_json")
    data: dict[str, Any] = {}
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                data = parsed
        except json.JSONDecodeError:
            data = {}
    if not data:
        return {}

    from .threat_categories import category_labels

    # Always report full taxonomy size on the home tile (40 named + Uncategorized).
    data = dict(data)
    data["threat_categories"] = len(category_labels())

    products = int(data.get("affected_products") or 0)
    if products < 5_000:
        raw_pc = get_meta(conn, "nvd_product_counts_json")
        if raw_pc:
            try:
                cached_pc = json.loads(raw_pc)
                nvd_products = int(cached_pc.get("products") or 0)
                nvd_vendors = int(cached_pc.get("vendors") or 0)
                if nvd_products > products:
                    data["affected_products"] = nvd_products
                    data["vendors"] = nvd_vendors
                    data["product_source"] = "nvd_cpes"
            except (json.JSONDecodeError, TypeError, ValueError):
                pass
    return data


def get_overview(conn: sqlite3.Connection, *, force: bool = False, heal: bool = True) -> dict[str, Any]:
    if not force:
        raw = get_meta(conn, "overview_stats_json")
        if raw:
            try:
                data = json.loads(raw)
                if heal and _overview_is_stale(conn, data):
                    # Fast path first (skip CPE scan); full scan only if products still sparse.
                    data = refresh_overview(conn, allow_nvd_product_scan=False)
                    if int(data.get("affected_products") or 0) < 1000:
                        data = refresh_overview(conn, allow_nvd_product_scan=True)
                    return data
                return data
            except json.JSONDecodeError:
                pass
    return refresh_overview(conn, allow_nvd_product_scan=True)


def visual_overview(overview: dict[str, Any] | None) -> dict[str, Any]:
    """Chart-ready severity + category breakdown for the home page."""
    ov = overview or {}
    vuln = ov.get("vulnerabilities") or {}
    crit = int(vuln.get("critical") or 0)
    high = int(vuln.get("high") or 0)
    med = int(vuln.get("medium") or 0)
    low = int(vuln.get("low") or 0)
    rated = int(vuln.get("rated") or (crit + high + med + low))
    unrated = int(vuln.get("unrated") or 0)
    total = int(vuln.get("total") or (rated + unrated))
    max_sev = max(crit, high, med, low, 1)

    def pct(n: int) -> float:
        return round((n / rated * 100.0), 1) if rated else 0.0

    def bar_w(n: int) -> float:
        return round((n / max_sev * 100.0), 1)

    # Donut stroke-dashoffset: start at 25 (12 o'clock) with circumference=100
    c_pct = pct(crit)
    h_pct = pct(high)
    m_pct = pct(med)
    l_pct = pct(low)
    offsets = {
        "critical": round(25 - 0, 2),
        "high": round(25 - c_pct, 2),
        "medium": round(25 - (c_pct + h_pct), 2),
        "low": round(25 - (c_pct + h_pct + m_pct), 2),
    }

    categories = []
    # Chart shows top 5 named threats; overview tile still reports full taxonomy (41).
    raw_cats = [
        c
        for c in (ov.get("categories") or [])
        if (c.get("name") or "").strip() and (c.get("name") or "").strip() != "Uncategorized"
    ]
    raw_cats = sorted(raw_cats, key=lambda c: -int(c.get("count") or 0))[:5]
    cat_max = max((int(c.get("count") or 0) for c in raw_cats), default=1) or 1
    for c in raw_cats:
        count = int(c.get("count") or 0)
        categories.append(
            {
                "name": c.get("name") or "",
                "count": count,
                "width": round((count / cat_max * 100.0), 1) if count > 0 else 0.0,
            }
        )

    return {
        "critical": crit,
        "high": high,
        "medium": med,
        "low": low,
        "rated": rated,
        "unrated": unrated,
        "total": total,
        "pct": {
            "critical": c_pct,
            "high": h_pct,
            "medium": m_pct,
            "low": l_pct,
        },
        "bar": {
            "critical": bar_w(crit),
            "high": bar_w(high),
            "medium": bar_w(med),
            "low": bar_w(low),
        },
        "donut_offset": offsets,
        "categories": categories,
    }


def stats(conn: sqlite3.Connection, *, heal_overview: bool = False) -> dict[str, Any]:
    """Table counts + overview. Default: never recompute overview on the request path."""
    overview = get_overview(conn, heal=heal_overview) if heal_overview else peek_overview(conn)
    if not overview and heal_overview:
        overview = get_overview(conn, heal=True)
    allowed = {
        "exploits",
        "cves",
        "nvd_cves",
        "cwe",
        "cisa_kev",
        "nuclei_templates",
        "metasploit_modules",
        "nessus_plugins",
        "msrc_cves",
        "msrc_updates",
        "msrc_remediations",
        "cve_products",
        "cve_cpes",
        "cve_cpe_matches",
        "exploit_cves",
        "capec",
        "debian_cves",
        "ubuntu_cves",
        "osv_vulns",
        "ghsa_advisories",
        "poc_github",
    }

    def _count(table: str) -> int:
        if table not in allowed:
            return 0
        try:
            return int(conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"])  # nosec B608
        except sqlite3.Error:
            return 0

    return {
        "exploits": _count("exploits"),
        "cves": _count("cves"),
        "nvd_cves": _count("nvd_cves"),
        "cwe": _count("cwe"),
        "cisa_kev": _count("cisa_kev"),
        "nuclei_templates": _count("nuclei_templates"),
        "metasploit_modules": _count("metasploit_modules"),
        "nessus_plugins": _count("nessus_plugins"),
        "msrc_cves": _count("msrc_cves"),
        "msrc_updates": _count("msrc_updates"),
        "msrc_remediations": _count("msrc_remediations"),
        "cve_products": _count("cve_products"),
        "cve_cpes": _count("cve_cpes"),
        "exploit_cve_links": _count("exploit_cves"),
        "capec": _count("capec"),
        "debian_cves": _count("debian_cves"),
        "ubuntu_cves": _count("ubuntu_cves"),
        "osv_vulns": _count("osv_vulns"),
        "ghsa_advisories": _count("ghsa_advisories"),
        "poc_github": _count("poc_github"),
        "overview": overview,
        "last_sync": get_meta(conn, "last_sync_all")
        or get_meta(conn, "nse_last_export")
        or get_meta(conn, "cve_last_ingest")
        or get_meta(conn, "edb_last_ingest"),
    }


def dedupe_cve_related(conn: sqlite3.Connection) -> dict[str, int]:
    """
    Remove duplicate child rows for the same CVE (products/CPEs/links).
    CVE primary rows are already unique via PRIMARY KEY(cve_id).
    """
    removed: dict[str, int] = {}
    statements = {
        "cve_products": """
            DELETE FROM cve_products WHERE id NOT IN (
              SELECT MIN(id) FROM cve_products
              GROUP BY cve_id, COALESCE(vendor,''), COALESCE(product,''),
                       COALESCE(version,''), COALESCE(status,'')
            )
            """,
        "cve_cpes": """
            DELETE FROM cve_cpes WHERE id NOT IN (
              SELECT MIN(id) FROM cve_cpes GROUP BY cve_id, cpe
            )
            """,
        "exploit_cves": """
            DELETE FROM exploit_cves WHERE rowid NOT IN (
              SELECT MIN(rowid) FROM exploit_cves GROUP BY edb_id, cve_id
            )
            """,
    }
    for name, sql in statements.items():
        try:
            cur = conn.execute(sql)
            removed[name] = int(cur.rowcount or 0)
        except sqlite3.Error:
            removed[name] = 0
    set_meta(conn, "last_cve_dedupe", utc_now())
    return removed
