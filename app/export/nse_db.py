"""Export offline vulnerability index for the vulnlocal NSE script.

Primary artifact: vulnlocal.pack/ — plain TSV buckets that Nmap Lua can read
with io.open only (no sqlite3.exe / external CLI).

Legacy slim SQLite (vulnlocal.db) is still built for optional tooling, but the
NSE script no longer requires it.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import time
from pathlib import Path

from .. import config
from ..db import db_session, set_meta, sqlite_uri, utc_now

NSE_SCHEMA = """
PRAGMA journal_mode=OFF;
PRAGMA synchronous=OFF;

CREATE TABLE cves (
    cve_id      TEXT PRIMARY KEY,
    title       TEXT,
    cvss_score  REAL
);
CREATE TABLE cve_products (
    cve_id   TEXT NOT NULL,
    vendor   TEXT,
    product  TEXT,
    version  TEXT
);
CREATE TABLE cve_cpes (
    cve_id TEXT NOT NULL,
    cpe    TEXT NOT NULL
);
CREATE TABLE cve_cpe_matches (
    cve_id          TEXT NOT NULL,
    cpe             TEXT NOT NULL,
    soft            TEXT,
    version         TEXT,
    update_token    TEXT,
    ver_start_incl  TEXT,
    ver_start_excl  TEXT,
    ver_end_incl    TEXT,
    ver_end_excl    TEXT,
    vulnerable      INTEGER DEFAULT 1
);
CREATE INDEX idx_nse_products_lprod ON cve_products(product COLLATE NOCASE);
CREATE INDEX idx_nse_products_cve ON cve_products(cve_id);
CREATE INDEX idx_nse_cpes_lcpe ON cve_cpes(cpe COLLATE NOCASE);
CREATE INDEX idx_nse_cpes_cve ON cve_cpes(cve_id);
CREATE INDEX idx_nse_matches_soft ON cve_cpe_matches(soft COLLATE NOCASE);
CREATE INDEX idx_nse_matches_cve ON cve_cpe_matches(cve_id);
CREATE INDEX idx_nse_cves_title ON cves(title);
"""

PACK_FORMAT = "vulnlocal-pack-1"
PACK_BUCKETS = 256


def pack_bucket(key: str) -> str:
    """8-bit bucket id — must match Lua NSE bucket8()."""
    h = 0
    for b in (key or "").lower().encode("utf-8"):
        h = ((h * 31) + b) % 256
    return f"{h:02x}"


def _tsv_cell(value: object) -> str:
    s = "" if value is None else str(value)
    s = s.replace("\t", " ").replace("\r", " ").replace("\n", " ").strip()
    return s


def export_nse_pack(
    out_dir: Path | None = None,
    *,
    src_sqlite: Path | None = None,
) -> dict:
    """Build vulnlocal.pack/ TSV buckets for pure-Lua NSE offline mode."""
    from ..progress import check_cancelled, set_progress

    config.ensure_dirs()
    dest = out_dir or config.NSE_PACK_PATH
    src_path = src_sqlite
    if src_path is None:
        if config.NSE_SQLITE_PATH.is_file():
            src_path = config.NSE_SQLITE_PATH
        elif config.SQLITE_PATH.is_file():
            src_path = config.SQLITE_PATH
        else:
            raise FileNotFoundError(
                f"No source DB for NSE pack (tried {config.NSE_SQLITE_PATH} and {config.SQLITE_PATH})"
            )

    check_cancelled()
    set_progress(phase="nse_export", label="Building NSE pack", detail=str(dest.name))

    tmp = dest.parent / f"vulnlocal.pack.export.{os.getpid()}.{int(time.time())}"
    if tmp.exists():
        shutil.rmtree(tmp, ignore_errors=True)
    matches_dir = tmp / "matches"
    products_dir = tmp / "products"
    matches_dir.mkdir(parents=True)
    products_dir.mkdir(parents=True)

    match_handles: dict[str, any] = {}
    product_handles: dict[str, any] = {}
    match_rows = 0
    product_rows = 0

    def mh(bucket: str):
        h = match_handles.get(bucket)
        if h is None:
            h = open(matches_dir / f"{bucket}.tsv", "w", encoding="utf-8", newline="\n")
            match_handles[bucket] = h
        return h

    def ph(bucket: str):
        h = product_handles.get(bucket)
        if h is None:
            h = open(products_dir / f"{bucket}.tsv", "w", encoding="utf-8", newline="\n")
            product_handles[bucket] = h
        return h

    conn = sqlite3.connect(sqlite_uri(src_path, mode="ro"), uri=True, timeout=120)
    conn.row_factory = sqlite3.Row
    try:
        # Detect schema: slim NSE DB vs full app DB (description vs title).
        cols = {r[1] for r in conn.execute("PRAGMA table_info(cves)")}
        title_expr = "COALESCE(title, '')" if "title" in cols else "COALESCE(description, '')"

        check_cancelled()
        set_progress(phase="nse_export", label="Writing match buckets", detail="cve_cpe_matches")
        try:
            cur = conn.execute(
                f"""
                SELECT m.soft, m.cve_id, m.cpe, m.version, m.update_token,
                       m.ver_start_incl, m.ver_start_excl, m.ver_end_incl, m.ver_end_excl,
                       m.vulnerable, COALESCE(c.cvss_score, 0) AS score,
                       {title_expr} AS title
                FROM cve_cpe_matches m
                LEFT JOIN cves c ON c.cve_id = m.cve_id
                WHERE m.vulnerable IS NULL OR m.vulnerable != 0
                """
            )
        except sqlite3.OperationalError:
            cur = None

        if cur is not None:
            while True:
                batch = cur.fetchmany(5000)
                if not batch:
                    break
                for r in batch:
                    soft = _tsv_cell(r["soft"] or "").lower()
                    if not soft:
                        soft = _tsv_cell(r["cpe"]).lower()
                    version = _tsv_cell(r["version"])
                    si = _tsv_cell(r["ver_start_incl"])
                    sx = _tsv_cell(r["ver_start_excl"])
                    ei = _tsv_cell(r["ver_end_incl"])
                    ex = _tsv_cell(r["ver_end_excl"])
                    # Skip bare wildcards with no range (cannot match a concrete version).
                    wild = {"", "*", "-", "n/a", "any"}
                    has_range = any(x and x.lower() not in wild for x in (si, sx, ei, ex))
                    has_ver = version.lower() not in wild
                    if not has_range and not has_ver:
                        continue
                    line = "\t".join(
                        [
                            soft,
                            _tsv_cell(r["cve_id"]),
                            _tsv_cell(r["cpe"]),
                            version,
                            _tsv_cell(r["update_token"]),
                            si,
                            sx,
                            ei,
                            ex,
                            _tsv_cell(r["vulnerable"] if r["vulnerable"] is not None else 1),
                            _tsv_cell(r["score"] or 0),
                            _tsv_cell(r["title"])[:240],
                        ]
                    )
                    mh(pack_bucket(soft)).write(line + "\n")
                    match_rows += 1
                if match_rows % 100_000 < 5000:
                    set_progress(
                        phase="nse_export",
                        label="Writing match buckets",
                        detail=f"{match_rows:,} rows",
                        current=match_rows,
                    )
                check_cancelled()

        check_cancelled()
        set_progress(phase="nse_export", label="Writing product buckets", detail="cve_products")
        try:
            cur = conn.execute(
                f"""
                SELECT cp.vendor, cp.product, cp.version, cp.cve_id,
                       COALESCE(c.cvss_score, 0) AS score,
                       {title_expr} AS title
                FROM cve_products cp
                LEFT JOIN cves c ON c.cve_id = cp.cve_id
                WHERE trim(COALESCE(cp.version, '')) NOT IN ('', '*', '-', 'n/a', 'any')
                """
            )
        except sqlite3.OperationalError:
            cur = None

        if cur is not None:
            while True:
                batch = cur.fetchmany(5000)
                if not batch:
                    break
                for r in batch:
                    prod = _tsv_cell(r["product"]).lower()
                    if not prod:
                        continue
                    line = "\t".join(
                        [
                            prod,
                            _tsv_cell(r["vendor"]),
                            _tsv_cell(r["product"]),
                            _tsv_cell(r["version"]),
                            _tsv_cell(r["cve_id"]),
                            _tsv_cell(r["score"] or 0),
                            _tsv_cell(r["title"])[:240],
                        ]
                    )
                    ph(pack_bucket(prod)).write(line + "\n")
                    product_rows += 1
                check_cancelled()
    finally:
        for h in match_handles.values():
            h.close()
        for h in product_handles.values():
            h.close()
        conn.close()

    (tmp / "META").write_text(
        "\n".join(
            [
                f"format={PACK_FORMAT}",
                f"buckets={PACK_BUCKETS}",
                "sep=tab",
                f"match_rows={match_rows}",
                f"product_rows={product_rows}",
                f"built={utc_now()}",
                "matches_cols=soft,cve_id,cpe,version,update,si,sx,ei,ex,vulnerable,score,title",
                "products_cols=product_key,vendor,product,version,cve_id,score,title",
                "",
            ]
        ),
        encoding="utf-8",
    )

    check_cancelled()
    set_progress(phase="nse_export", label="Publishing NSE pack", detail=dest.name)
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    os.replace(str(tmp), str(dest))

    # Size of pack tree
    total_bytes = sum(p.stat().st_size for p in dest.rglob("*") if p.is_file())

    with db_session() as conn:
        set_meta(conn, "nse_last_export", utc_now())
        set_meta(conn, "nse_export_pack", str(dest))
        set_meta(conn, "nse_pack_format", PACK_FORMAT)
        set_meta(conn, "nse_db_slim", "1")

    set_progress(
        phase="nse_done",
        label="NSE pack export complete",
        current=1,
        total=1,
        unit="pack",
        detail=(
            f"{dest.name} · {total_bytes / (1024 * 1024):.1f} MB · "
            f"matches={match_rows:,} · products={product_rows:,}"
        ),
    )
    return {
        "status": "ok",
        "pack": str(dest),
        "format": PACK_FORMAT,
        "bytes": total_bytes,
        "counts": {"match_rows": match_rows, "product_rows": product_rows},
        "source": str(src_path),
    }


def export_nse_sqlite(out_path: Path | None = None) -> dict:
    """Build legacy slim plaintext SQLite (optional; NSE prefers .pack)."""
    from ..progress import check_cancelled, set_progress

    config.ensure_dirs()
    if not config.SQLITE_PATH.is_file():
        raise FileNotFoundError(
            f"Main database missing: {config.SQLITE_PATH}. Ingest data first."
        )

    try:
        from ..ingest import nvd as nvd_ingest

        set_progress(phase="nse_export", label="Expanding NVD CPEs for NSE", detail="lookup tables")
        expand_info = nvd_ingest.expand_nvd_cpes_into_lookup_tables(force=False)
    except Exception as exc:
        expand_info = {"error": str(exc)}

    dest = out_path or config.NSE_SQLITE_PATH
    dest.parent.mkdir(parents=True, exist_ok=True)

    for stale in dest.parent.glob("*.csv"):
        try:
            stale.unlink()
        except OSError:
            pass

    check_cancelled()
    set_progress(phase="nse_export", label="Building slim NSE SQLite", detail="CVE id + title…")

    tmp = dest.parent / f"vulnlocal.nse.export.{os.getpid()}.{int(time.time())}.db"
    if tmp.exists():
        try:
            tmp.unlink()
        except OSError:
            pass

    src = sqlite3.connect(sqlite_uri(config.SQLITE_PATH, mode="ro"), uri=True, timeout=120)
    src.row_factory = sqlite3.Row
    dst = sqlite3.connect(str(tmp), timeout=120)
    try:
        dst.executescript(NSE_SCHEMA)
        check_cancelled()
        set_progress(phase="nse_export", label="Copying CVE titles", detail="cves")
        dst.executemany(
            "INSERT OR REPLACE INTO cves(cve_id, title, cvss_score) VALUES (?, ?, ?)",
            [
                (
                    r["cve_id"],
                    (r["description"] or r["cve_id"] or "")[:240],
                    r["cvss_score"],
                )
                for r in src.execute(
                    "SELECT cve_id, description, cvss_score FROM cves"
                )
            ],
        )
        check_cancelled()
        set_progress(phase="nse_export", label="Copying products", detail="cve_products")
        dst.executemany(
            "INSERT INTO cve_products(cve_id, vendor, product, version) VALUES (?, ?, ?, ?)",
            [
                (r["cve_id"], r["vendor"], r["product"], r["version"])
                for r in src.execute(
                    "SELECT cve_id, vendor, product, version FROM cve_products"
                )
            ],
        )
        check_cancelled()
        set_progress(phase="nse_export", label="Copying CPEs", detail="cve_cpes")
        dst.executemany(
            "INSERT INTO cve_cpes(cve_id, cpe) VALUES (?, ?)",
            [(r["cve_id"], r["cpe"]) for r in src.execute("SELECT cve_id, cpe FROM cve_cpes")],
        )
        check_cancelled()
        set_progress(phase="nse_export", label="Copying CPE ranges", detail="cve_cpe_matches")
        try:
            match_rows = src.execute(
                """
                SELECT cve_id, cpe, soft, version, update_token,
                       ver_start_incl, ver_start_excl, ver_end_incl, ver_end_excl, vulnerable
                FROM cve_cpe_matches
                """
            ).fetchall()
        except sqlite3.OperationalError:
            match_rows = []
        dst.executemany(
            """
            INSERT INTO cve_cpe_matches(
                cve_id, cpe, soft, version, update_token,
                ver_start_incl, ver_start_excl, ver_end_incl, ver_end_excl, vulnerable
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    r["cve_id"],
                    r["cpe"],
                    r["soft"],
                    r["version"],
                    r["update_token"],
                    r["ver_start_incl"],
                    r["ver_start_excl"],
                    r["ver_end_incl"],
                    r["ver_end_excl"],
                    r["vulnerable"],
                )
                for r in match_rows
            ],
        )
        dst.execute("ANALYZE")
        dst.commit()
        counts = {
            "cves": dst.execute("SELECT COUNT(*) FROM cves").fetchone()[0],
            "cve_products": dst.execute("SELECT COUNT(*) FROM cve_products").fetchone()[0],
            "cve_cpes": dst.execute("SELECT COUNT(*) FROM cve_cpes").fetchone()[0],
            "cve_cpe_matches": dst.execute("SELECT COUNT(*) FROM cve_cpe_matches").fetchone()[0],
        }
    finally:
        dst.close()
        src.close()

    check_cancelled()
    set_progress(phase="nse_export", label="Publishing NSE SQLite", detail="plaintext…")
    try:
        if dest.exists():
            dest.unlink()
    except OSError:
        pass
    try:
        os.replace(str(tmp), str(dest))
    except OSError:
        shutil.copy2(str(tmp), str(dest))
        try:
            tmp.unlink()
        except OSError:
            pass
    size = dest.stat().st_size

    with db_session() as conn:
        set_meta(conn, "nse_export_db", str(dest))
        set_meta(conn, "nse_db_encrypted", "0")

    return {
        "status": "ok",
        "database": str(dest),
        "encrypted": False,
        "slim": True,
        "bytes": size,
        "counts": counts,
        "cpe_expand": expand_info,
    }


def export_nse_databases(out_path: Path | None = None) -> dict:
    """Build NSE offline pack from the app SQLite DB (no legacy NSE .db)."""
    from ..progress import set_progress

    if not config.SQLITE_PATH.is_file():
        raise FileNotFoundError(
            f"Main database missing: {config.SQLITE_PATH}. Ingest data first."
        )

    # Expand NVD CPE lookup tables before packaging (best-effort).
    expand_info: dict = {}
    try:
        from ..ingest import nvd as nvd_ingest

        set_progress(phase="nse_export", label="Expanding NVD CPEs for NSE", detail="lookup tables")
        expand_info = nvd_ingest.expand_nvd_cpes_into_lookup_tables(force=False)
    except Exception as exc:
        expand_info = {"error": str(exc)}

    pack_info = export_nse_pack(
        out_dir=(out_path.parent / "vulnlocal.pack") if out_path else None,
        src_sqlite=config.SQLITE_PATH,
    )

    set_progress(
        phase="nse_done",
        label="NSE export complete",
        current=1,
        total=1,
        unit="file",
        detail=f"pack={pack_info.get('bytes', 0) / (1024 * 1024):.1f} MB",
    )
    return {
        "status": "ok",
        "pack": pack_info,
        "cpe_expand": expand_info,
        "database": pack_info.get("pack"),
        "encrypted": False,
        "slim": True,
        "bytes": pack_info.get("bytes"),
        "counts": pack_info.get("counts"),
    }
