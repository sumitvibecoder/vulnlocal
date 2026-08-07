"""Version-aware local search across CVE + Exploit-DB (with CVE↔EDB mapping)."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .db import db_session, extract_cve_ids_from_codes

_VERSION_RE = re.compile(
    r"(?P<product>.+?)\s+(?P<version>\d+(?:\.\d+)*(?:[a-zA-Z0-9._-]*)?)\s*$"
)
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d+$", re.I)
_EDB_ID_RE = re.compile(r"^(?:EDB-?)?(\d+)$", re.I)


def parse_query(q: str) -> dict[str, str]:
    q = (q or "").strip()
    out = {"raw": q, "product": "", "version": "", "cve_id": "", "edb_id": ""}
    if not q:
        return out
    if _CVE_ID_RE.match(q):
        out["cve_id"] = q.upper()
        return out
    m_edb = _EDB_ID_RE.match(q)
    if m_edb and ("EDB" in q.upper() or q.isdigit()):
        # Bare numeric IDs are treated as free-text unless prefixed with EDB-
        if q.upper().startswith("EDB") or q.lower().startswith("edb-"):
            out["edb_id"] = m_edb.group(1)
            return out
    m = _VERSION_RE.match(q)
    if m:
        out["product"] = m.group("product").strip()
        out["version"] = m.group("version").strip()
    else:
        out["product"] = q
    return out


def _version_prefixes(version: str) -> list[str]:
    if not version:
        return []
    parts = []
    for i in range(len(version), 0, -1):
        piece = version[:i]
        if piece and piece[-1] != ".":
            parts.append(piece)
    uniq: list[str] = []
    seen = set()
    for p in parts:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq[:12]


def _fetch_edb_for_cves(conn, cve_ids: list[str]) -> dict[str, list[dict[str, Any]]]:
    """Map CVE ID → list of linked Exploit-DB entries."""
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if not cve_ids:
        return out
    # Chunk IN clauses for SQLite limits
    chunk = 400
    for i in range(0, len(cve_ids), chunk):
        ids = cve_ids[i : i + chunk]
        placeholders = ",".join("?" * len(ids))
        rows = conn.execute(
            f"""
            SELECT ec.cve_id, e.edb_id, e.title, e.platform, e.type,
                   e.date_pub, e.author, e.verified, e.kind, e.codes
            FROM exploit_cves ec
            JOIN exploits e ON e.edb_id = ec.edb_id
            WHERE ec.cve_id IN ({placeholders})
            ORDER BY e.verified DESC, e.edb_id DESC
            """,
            ids,
        ).fetchall()
        for r in rows:
            d = dict(r)
            cve_id = d.pop("cve_id")
            out[cve_id].append(d)
    return out


def _fetch_cves_for_edb(conn, edb_ids: list[int]) -> dict[int, list[dict[str, Any]]]:
    """Map EDB ID → list of linked CVE summaries."""
    out: dict[int, list[dict[str, Any]]] = defaultdict(list)
    if not edb_ids:
        return out
    placeholders = ",".join("?" * len(edb_ids))
    rows = conn.execute(
        f"""
        SELECT ec.edb_id, c.cve_id, c.state, substr(c.description,1,240) AS description,
               c.cvss_score, c.severity, c.date_updated
        FROM exploit_cves ec
        JOIN cves c ON c.cve_id = ec.cve_id
        WHERE ec.edb_id IN ({placeholders})
        ORDER BY COALESCE(c.cvss_score, 0) DESC, c.cve_id DESC
        """,
        edb_ids,
    ).fetchall()
    for r in rows:
        d = dict(r)
        edb_id = int(d.pop("edb_id"))
        out[edb_id].append(d)
    return out


def _attach_edb_to_cves(conn, cves: list[dict[str, Any]]) -> None:
    by_cve = _fetch_edb_for_cves(conn, [c["cve_id"] for c in cves if c.get("cve_id")])
    for c in cves:
        linked = by_cve.get(c["cve_id"], [])
        c["edb"] = linked
        c["edb_ids"] = [int(x["edb_id"]) for x in linked]
        c["edb_count"] = len(linked)


def _attach_cves_to_exploits(conn, exploits: list[dict[str, Any]]) -> None:
    # Prefer indexed map; fall back to parsing codes for rows not yet mapped
    edb_ids = [int(e["edb_id"]) for e in exploits if e.get("edb_id") is not None]
    by_edb = _fetch_cves_for_edb(conn, edb_ids)
    for e in exploits:
        edb_id = int(e["edb_id"])
        linked = by_edb.get(edb_id)
        if linked is None:
            # Fallback: parse codes + look up any matching CVEs we have locally
            cve_ids = extract_cve_ids_from_codes(e.get("codes"))
            linked = []
            if cve_ids:
                placeholders = ",".join("?" * len(cve_ids))
                rows = conn.execute(
                    f"""
                    SELECT cve_id, state, substr(description,1,240) AS description,
                           cvss_score, severity, date_updated
                    FROM cves WHERE cve_id IN ({placeholders})
                    ORDER BY COALESCE(cvss_score, 0) DESC
                    """,
                    cve_ids,
                ).fetchall()
                linked = [dict(r) for r in rows]
                # Still surface CVE ids even if not in local CVE table
                have = {r["cve_id"] for r in linked}
                for cid in cve_ids:
                    if cid not in have:
                        linked.append(
                            {
                                "cve_id": cid,
                                "state": None,
                                "description": "",
                                "cvss_score": None,
                                "severity": None,
                                "date_updated": None,
                            }
                        )
        e["cves"] = linked or []
        e["cve_ids"] = [x["cve_id"] for x in e["cves"]]
        e["cve_count"] = len(e["cve_ids"])


def _merge_linked_exploits(
    exploits: list[dict[str, Any]],
    cves: list[dict[str, Any]],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    """Ensure Exploit-DB entries linked from CVE hits appear in the exploits list."""
    seen = {int(e["edb_id"]) for e in exploits if e.get("edb_id") is not None}
    merged = list(exploits)
    for c in cves:
        for edb in c.get("edb") or []:
            edb_id = int(edb["edb_id"])
            if edb_id in seen:
                continue
            d = dict(edb)
            d["match_reason"] = f"linked via {c['cve_id']}"
            d["linked_cve_id"] = c["cve_id"]
            merged.append(d)
            seen.add(edb_id)
            if len(merged) >= limit * 2:
                break
        if len(merged) >= limit * 2:
            break
    return merged[: max(limit, len(exploits))]


def search_local(q: str, limit: int = 40) -> dict[str, Any]:
    parsed = parse_query(q)
    limit = max(1, min(int(limit), 100))
    if len(parsed["raw"]) < 2 and not parsed["cve_id"] and not parsed["edb_id"]:
        return {"query": parsed, "cves": [], "exploits": []}

    with db_session() as conn:
        if parsed["cve_id"]:
            rows = conn.execute(
                """
                SELECT cve_id, state, substr(description,1,320) AS description,
                       cvss_score, severity, date_updated
                FROM cves WHERE cve_id = ?
                """,
                (parsed["cve_id"],),
            ).fetchall()
            cves = [dict(r) for r in rows]
            for c in cves:
                c["match_reason"] = "exact CVE id"
            _attach_edb_to_cves(conn, cves)
            exploits = _merge_linked_exploits([], cves, limit=limit)
            _attach_cves_to_exploits(conn, exploits)
            return {"query": parsed, "cves": cves, "exploits": exploits}

        if parsed["edb_id"]:
            rows = conn.execute(
                """
                SELECT edb_id, title, platform, type, date_pub, author, codes, verified, kind
                FROM exploits WHERE edb_id = ?
                """,
                (int(parsed["edb_id"]),),
            ).fetchall()
            exploits = [dict(r) for r in rows]
            for e in exploits:
                e["match_reason"] = "exact EDB id"
            _attach_cves_to_exploits(conn, exploits)
            # Also surface the linked CVE records as primary CVE hits
            cves: list[dict[str, Any]] = []
            seen_cve: set[str] = set()
            for e in exploits:
                for c in e.get("cves") or []:
                    if c["cve_id"] in seen_cve:
                        continue
                    d = dict(c)
                    d["match_reason"] = f"linked from EDB-{e['edb_id']}"
                    cves.append(d)
                    seen_cve.add(c["cve_id"])
            _attach_edb_to_cves(conn, cves)
            return {"query": parsed, "cves": cves, "exploits": exploits}

        product = parsed["product"]
        version = parsed["version"]
        prod_like = f"%{product}%"
        cves = []
        exploits: list[dict[str, Any]] = []

        if version:
            vprefs = _version_prefixes(version)
            product_rows = conn.execute(
                """
                SELECT DISTINCT c.cve_id, c.state, substr(c.description,1,320) AS description,
                       c.cvss_score, c.severity, c.date_updated,
                       cp.vendor, cp.product, cp.version AS matched_version
                FROM cve_products cp
                JOIN cves c ON c.cve_id = cp.cve_id
                WHERE (cp.product LIKE ? COLLATE NOCASE OR cp.vendor LIKE ? COLLATE NOCASE)
                  AND cp.version LIKE ? COLLATE NOCASE
                ORDER BY COALESCE(c.cvss_score, 0) DESC, c.cve_id DESC
                LIMIT ?
                """,
                (prod_like, prod_like, f"%{version}%", limit),
            ).fetchall()
            seen = set()
            for r in product_rows:
                d = dict(r)
                d["match_reason"] = f"product version {d.get('matched_version') or version}"
                cves.append(d)
                seen.add(d["cve_id"])

            for pref in vprefs[:5]:
                if len(seen) >= limit:
                    break
                rows = conn.execute(
                    """
                    SELECT cve_id, state, substr(description,1,320) AS description,
                           cvss_score, severity, date_updated
                    FROM cves
                    WHERE description LIKE ? COLLATE NOCASE
                      AND description LIKE ? COLLATE NOCASE
                      AND (state IS NULL OR state != 'REJECTED')
                    ORDER BY COALESCE(cvss_score, 0) DESC, cve_id DESC
                    LIMIT ?
                    """,
                    (prod_like, f"%{pref}%", limit),
                ).fetchall()
                for r in rows:
                    d = dict(r)
                    if d["cve_id"] in seen:
                        continue
                    d["match_reason"] = f"description mentions {product} {pref}"
                    d["matched_version"] = pref
                    cves.append(d)
                    seen.add(d["cve_id"])
                    if len(seen) >= limit:
                        break

            ex_rows = conn.execute(
                """
                SELECT edb_id, title, platform, type, date_pub, author, codes, verified, kind
                FROM exploits
                WHERE title LIKE ? COLLATE NOCASE
                  AND title LIKE ? COLLATE NOCASE
                ORDER BY edb_id DESC
                LIMIT ?
                """,
                (prod_like, f"%{version}%", limit),
            ).fetchall()
            for r in ex_rows:
                d = dict(r)
                d["match_reason"] = f"title mentions {product} {version}"
                d["matched_version"] = version
                exploits.append(d)
        else:
            product_rows = conn.execute(
                """
                SELECT DISTINCT c.cve_id, c.state, substr(c.description,1,320) AS description,
                       c.cvss_score, c.severity, c.date_updated,
                       cp.vendor, cp.product, cp.version AS matched_version
                FROM cve_products cp
                JOIN cves c ON c.cve_id = cp.cve_id
                WHERE cp.product LIKE ? COLLATE NOCASE OR cp.vendor LIKE ? COLLATE NOCASE
                ORDER BY COALESCE(c.cvss_score, 0) DESC, c.cve_id DESC
                LIMIT ?
                """,
                (prod_like, prod_like, limit),
            ).fetchall()
            seen = set()
            for r in product_rows:
                d = dict(r)
                d["match_reason"] = f"affected product {d.get('product') or product}"
                cves.append(d)
                seen.add(d["cve_id"])

            if len(seen) < limit:
                rows = conn.execute(
                    """
                    SELECT cve_id, state, substr(description,1,320) AS description,
                           cvss_score, severity, date_updated
                    FROM cves
                    WHERE cve_id LIKE ? OR description LIKE ?
                    ORDER BY COALESCE(cvss_score, 0) DESC, cve_id DESC
                    LIMIT ?
                    """,
                    (prod_like, prod_like, limit - len(seen)),
                ).fetchall()
                for r in rows:
                    d = dict(r)
                    if d["cve_id"] in seen:
                        continue
                    d["match_reason"] = "text match"
                    cves.append(d)

            exploits = [
                dict(r)
                for r in conn.execute(
                    """
                    SELECT edb_id, title, platform, type, date_pub, author, codes, verified, kind
                    FROM exploits
                    WHERE title LIKE ? OR codes LIKE ? OR platform LIKE ?
                    ORDER BY edb_id DESC
                    LIMIT ?
                    """,
                    (prod_like, prod_like, prod_like, limit),
                ).fetchall()
            ]
            for d in exploits:
                d["match_reason"] = "title/platform match"

        cves = cves[:limit]
        _attach_edb_to_cves(conn, cves)
        exploits = _merge_linked_exploits(exploits, cves, limit=limit)
        exploits = exploits[:limit]
        _attach_cves_to_exploits(conn, exploits)

    return {
        "query": parsed,
        "cves": cves,
        "exploits": exploits,
    }
