"""NSE correlation API — CPE/product matching with NVD version ranges (Vulners-like)."""

from __future__ import annotations

import re
from typing import Any

from .db import db_session
from .version_range import (
    cpe_update_matches_detected as _cpe_update_matches_detected,
    match_applies_to_version,
    norm_ver as _norm_ver,
    version_matches as _version_matches_strict,
)

_NOISE = {
    "httpd",
    "smtpd",
    "ftpd",
    "daemon",
    "server",
    "service",
    "protocol",
    "open",
    "the",
    "and",
}
_MAX = 50
_WILDCARD_VER = frozenset({"", "*", "-", "n/a", "na", "any", "unspecified", "unknown"})

# Banner side-products: "Werkzeug httpd 3.1.6 (Python 3.14.0)"
_PAREN_PRODUCT_RE = re.compile(
    r"\(\s*([A-Za-z][\w.+-]*)\s+(v?\d[\w.+-]*)\s*\)",
    re.IGNORECASE,
)
_NAMED_PRODUCT_RE = re.compile(
    r"\b(Python|OpenJDK|OpenSSL|OpenSSH|Node\.js|nodejs|PHP|Ruby|Perl|Java|Go|nginx|Apache)\s+(v?\d[\w.+-]*)\b",
    re.IGNORECASE,
)


def _is_suppressed_fingerprint(product: str, version: str) -> bool:
    p = (product or "").lower()
    v = (version or "").lower().strip()
    if "httpapi" in p and ("microsoft" in p or "httpd" in p):
        if not v or v == "2.0" or v.startswith("2.0"):
            return True
    return False


def _tokenize_product(prod: str) -> list[str]:
    cleaned = re.sub(r"[^\w.\-+_]+", " ", (prod or "").lower())
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    out: list[str] = []
    for token in cleaned.split():
        if len(token) >= 3 and token not in _NOISE:
            out.append(token)
    return out


def _version_matches(detected: str, dbver: str, *, allow_wildcard: bool = False) -> bool:
    """Align concrete versions. Bare CPE '*' / '-' never match when allow_wildcard is False."""
    d = _norm_ver(detected)
    b = _norm_ver(dbver)
    if not d:
        return False
    if b in _WILDCARD_VER:
        return bool(allow_wildcard)
    return _version_matches_strict(d, b)


def _version_sql_needles(ver: str) -> list[str]:
    """CPE URI fragments that can align with a detected version (full + major.minor)."""
    v = _norm_ver(ver)
    if not v:
        return []
    out = [f":{v}:"]
    parts = [p for p in v.split(".") if p]
    if len(parts) >= 2:
        mm = ".".join(parts[:2])
        if f":{mm}:" not in out:
            out.append(f":{mm}:")
    return out


def _synth_cpe(product: str, version: str) -> str:
    raw = (product or "").lower().strip()
    raw = re.sub(r"\bhttpd\b", "", raw)
    raw = re.sub(r"[^\w.+-]+", " ", raw).strip()
    prod = raw.split()[0] if raw else "unknown"
    vendor = prod
    aliases = {
        "python": ("python", "python"),
        "cpython": ("python", "python"),
        "openssl": ("openssl", "openssl"),
        "openssh": ("openbsd", "openssh"),
        "nginx": ("f5", "nginx"),
        "apache": ("apache", "http_server"),
        "httpd": ("apache", "http_server"),
        "postgresql": ("postgresql", "postgresql"),
        "postgres": ("postgresql", "postgresql"),
        "redis": ("redis", "redis"),
        "nodejs": ("nodejs", "node.js"),
        "node.js": ("nodejs", "node.js"),
        "node": ("nodejs", "node.js"),
        "php": ("php", "php"),
        "java": ("oracle", "jdk"),
        "openjdk": ("oracle", "openjdk"),
        "werkzeug": ("palletsprojects", "werkzeug"),
    }
    if prod in aliases:
        vendor, prod = aliases[prod]
    ver = _norm_ver(version) or "*"
    return f"cpe:/a:{vendor}:{prod}:{ver}"


def _parse_cpe23(cpe: str) -> dict[str, str]:
    raw = (cpe or "").strip().lower()
    if not raw:
        return {}
    if raw.startswith("cpe:/"):
        body = raw[5:]
        parts = body.split(":")
        if len(parts) < 3:
            return {}
        ver = parts[3] if len(parts) > 3 else ""
        update = parts[4] if len(parts) > 4 else ""
        uri = f"cpe:/{parts[0]}:{parts[1]}:{parts[2]}"
        if ver and ver not in _WILDCARD_VER:
            uri += f":{ver}"
        return {
            "part": parts[0],
            "vendor": parts[1],
            "product": parts[2],
            "version": ver,
            "update": update,
            "soft": f"cpe:2.3:{parts[0]}:{parts[1]}:{parts[2]}",
            "uri": uri,
        }
    raw = raw.replace("cpe:/", "cpe:2.3:")
    parts = raw.split(":")
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":
        return {}
    ver = parts[5] if len(parts) > 5 else ""
    update = parts[6] if len(parts) > 6 else ""
    uri = f"cpe:/{parts[2]}:{parts[3]}:{parts[4]}"
    if ver and ver not in _WILDCARD_VER:
        uri += f":{ver}"
    return {
        "part": parts[2],
        "vendor": parts[3],
        "product": parts[4],
        "version": ver,
        "update": update,
        "soft": f"cpe:2.3:{parts[2]}:{parts[3]}:{parts[4]}",
        "uri": uri,
    }


def _cve_link(cve_id: str) -> str:
    return f"https://www.cve.org/CVERecord?id={cve_id}"


def _nvd_link(cve_id: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def _product_hit_has_ga_cpe(
    conn, *, cve_id: str, vendor: str, product: str, detected_ver: str
) -> bool:
    """If CPE/match rows exist, require a GA concrete or in-range hit."""
    soft = f"cpe:2.3:a:{(vendor or '').lower()}:{(product or '').lower()}"
    try:
        rows = conn.execute(
            """
            SELECT cpe, version, update_token, ver_start_incl, ver_start_excl,
                   ver_end_incl, ver_end_excl, vulnerable
            FROM cve_cpe_matches
            WHERE cve_id = ? AND (soft = ? OR instr(lower(cpe), ?) > 0)
            LIMIT 300
            """,
            (cve_id, soft, soft),
        ).fetchall()
    except Exception:
        rows = []
    if rows:
        for r in rows:
            if not int(r["vulnerable"] if r["vulnerable"] is not None else 1):
                continue
            ok, _ = match_applies_to_version(
                detected_ver,
                cpe_version=r["version"] or "",
                cpe_update=r["update_token"] or "",
                ver_start_incl=r["ver_start_incl"] or "",
                ver_start_excl=r["ver_start_excl"] or "",
                ver_end_incl=r["ver_end_incl"] or "",
                ver_end_excl=r["ver_end_excl"] or "",
            )
            if ok:
                return True
        return False
    # Fallback: legacy cve_cpes concrete GA check.
    rows = conn.execute(
        """
        SELECT cpe FROM cve_cpes
        WHERE cve_id = ? AND instr(lower(cpe), ?) > 0
        LIMIT 200
        """,
        (cve_id, soft),
    ).fetchall()
    if not rows:
        return True
    saw_concrete = False
    for r in rows:
        parsed = _parse_cpe23(r["cpe"] or "")
        db_ver = parsed.get("version") or ""
        if db_ver in _WILDCARD_VER:
            continue
        saw_concrete = True
        if not _version_matches(detected_ver, db_ver):
            continue
        if _cpe_update_matches_detected(detected_ver, parsed.get("update") or ""):
            return True
    return not saw_concrete


def _push(bucket: dict[str, dict[str, Any]], key: str, rec: dict[str, Any]) -> None:
    prev = bucket.get(key)
    if prev and (prev.get("score") or 0) >= (rec.get("score") or 0):
        return
    bucket[key] = rec


def _sorted(bucket: dict[str, dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    rows = list(bucket.values())
    rows.sort(key=lambda r: (-(float(r.get("score") or 0)), str(r.get("id") or "")))
    return rows[:limit]


def _product_name_matches(tokens: list[str], vendor: str, product: str) -> bool:
    if not tokens or not product:
        return False
    prod = product.lower()
    vend = (vendor or "").lower()
    primary = max(tokens, key=len)
    if primary not in prod and prod not in primary and primary not in vend:
        blob = f"{vend} {prod}"
        if not all(t in blob for t in tokens[:3]):
            return False
    else:
        if not any(t in prod or prod == t for t in tokens):
            return False
    return True


def _cpe_belongs_to_product(cpe: str, product: str) -> bool:
    """True if a CPE URI is for the same product family as the Nmap product name."""
    parsed = _parse_cpe23(cpe)
    cpe_prod = (parsed.get("product") or "").lower().replace("_", " ")
    cpe_vend = (parsed.get("vendor") or "").lower()
    if not cpe_prod:
        return False
    tokens = _tokenize_product(product)
    if not tokens:
        return False
    aliases = {
        "python": {"python", "cpython"},
        "cpython": {"python", "cpython"},
        "werkzeug": {"werkzeug"},
        "httpd": {"http_server", "httpd", "apache"},
        "apache": {"http_server", "httpd", "apache"},
        "openssl": {"openssl"},
        "openssh": {"openssh"},
        "nginx": {"nginx"},
    }
    primary = max(tokens, key=len)
    family = aliases.get(primary, {primary})
    if cpe_prod in family or any(t == cpe_prod or t in cpe_prod for t in tokens):
        return True
    blob = f"{cpe_vend} {cpe_prod}"
    return any(t in blob for t in tokens)


def _soft_belongs_to_product(soft: str, product: str) -> bool:
    parts = (soft or "").lower().split(":")
    if len(parts) >= 5 and parts[0] == "cpe":
        probe = f"cpe:2.3:{parts[2]}:{parts[3]}:{parts[4]}:*"
        return _cpe_belongs_to_product(probe, product)
    return False


def discover_targets(
    *,
    product: str = "",
    version: str = "",
    cpes: list[str] | None = None,
    extrainfo: str = "",
) -> list[dict[str, Any]]:
    """Build primary + banner/CPE side targets (e.g. Python from Werkzeug banner)."""
    product = (product or "").strip()
    version = (version or "").strip()
    extrainfo = (extrainfo or "").strip()
    cpes = [c for c in (cpes or []) if c]
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(prod: str, ver: str, extra_cpes: list[str] | None = None) -> None:
        prod = (prod or "").strip()
        ver = (ver or "").strip()
        if not prod or not ver:
            return
        key = (prod.lower(), _norm_ver(ver))
        if key in seen:
            return
        seen.add(key)
        # Never attach another product's CPE to this target (e.g. python CPE on
        # Werkzeug 3.1.6 caused mass false positives via version 3.1 vs 3.1.6).
        cpe_list = [c for c in (extra_cpes or []) if _cpe_belongs_to_product(c, prod)]
        synth = _synth_cpe(prod, ver)
        if synth not in cpe_list:
            cpe_list.insert(0, synth)
        out.append({"product": prod, "version": ver, "cpes": cpe_list})

    add(product, version, cpes)

    blob = f"{product} {extrainfo}"
    for m in _PAREN_PRODUCT_RE.finditer(blob):
        add(m.group(1), m.group(2), [])
    for m in _NAMED_PRODUCT_RE.finditer(blob):
        add(m.group(1), m.group(2), [])

    for cpe in cpes:
        parsed = _parse_cpe23(cpe)
        p = parsed.get("product") or ""
        v = parsed.get("version") or ""
        if p and v and _norm_ver(v) not in _WILDCARD_VER:
            add(p, v, [cpe])

    return out


def _match_target(
    conn,
    *,
    product: str,
    version: str,
    cpes: list[str],
    limit: int,
) -> tuple[dict[str, dict[str, Any]], str]:
    """Return (hits_by_cve, display_cpe_uri) using NVD ranges + concrete versions."""
    hits: dict[str, dict[str, Any]] = {}
    display_cpe = ""
    detected_ver = version
    softs: list[str] = []

    for cpe in cpes:
        parsed = _parse_cpe23(cpe)
        soft = parsed.get("soft") or ""
        cpe_own_ver = parsed.get("version") or ""
        use_ver = (
            cpe_own_ver
            if cpe_own_ver and _norm_ver(cpe_own_ver) not in _WILDCARD_VER
            else detected_ver
        )
        if not soft:
            needle = cpe.lower().replace("cpe:/", "cpe:2.3:")
            soft_m = re.match(r"^(cpe:2\.3:[aho]:[^:]+:[^:]+)", needle)
            soft = soft_m.group(1) if soft_m else needle
        if soft and soft not in softs:
            if not _soft_belongs_to_product(soft, product):
                continue
            softs.append(soft)
        if not display_cpe:
            display_cpe = parsed.get("uri") or _synth_cpe(product, use_ver)

    if not softs:
        softs.append(_parse_cpe23(_synth_cpe(product, detected_ver)).get("soft") or "")

    # Vendor/product aliases used by NVD (python vs cpython, nginx vs f5).
    extra_softs: list[str] = []
    for soft in softs:
        replacements = (
            (":python:python", ":python:cpython"),
            (":python:cpython", ":python:python"),
            (":nginx:nginx", ":f5:nginx"),
            (":f5:nginx", ":nginx:nginx"),
            (":apache:httpd", ":apache:http_server"),
            (":apache:http_server", ":apache:httpd"),
            (":nodejs:nodejs", ":nodejs:node.js"),
            (":nodejs:node.js", ":nodejs:nodejs"),
        )
        for a, b in replacements:
            if a in soft:
                alt = soft.replace(a, b, 1)
                if alt not in softs and alt not in extra_softs:
                    extra_softs.append(alt)
    softs.extend(extra_softs)

    # Prefer NVD cpeMatch rows (with versionStart/End) — Vulners-like.
    # No row LIMIT: soft-exact queries are selective; LIMIT 2500 previously
    # truncated OpenSSL/PostgreSQL and dropped real in-range CVEs.
    has_match_table = True
    for soft in softs:
        if not soft:
            continue
        try:
            rows = conn.execute(
                """
                SELECT m.cpe, m.cve_id, m.version, m.update_token,
                       m.ver_start_incl, m.ver_start_excl,
                       m.ver_end_incl, m.ver_end_excl, m.vulnerable,
                       COALESCE(c.cvss_score, 0) AS score,
                       COALESCE(c.description, '') AS title
                FROM cve_cpe_matches m
                JOIN cves c ON c.cve_id = m.cve_id
                WHERE lower(m.soft) = ?
                  AND (
                    COALESCE(m.ver_start_incl, '') != ''
                    OR COALESCE(m.ver_start_excl, '') != ''
                    OR COALESCE(m.ver_end_incl, '') != ''
                    OR COALESCE(m.ver_end_excl, '') != ''
                    OR trim(COALESCE(m.version, '')) NOT IN ('', '*', '-', 'n/a', 'any')
                  )
                """,
                (soft.lower(),),
            ).fetchall()
        except Exception:
            has_match_table = False
            rows = []

        for r in rows:
            if not int(r["vulnerable"] if r["vulnerable"] is not None else 1):
                continue
            cid = str(r["cve_id"] or "")
            if not cid:
                continue
            ok, matched_ver = match_applies_to_version(
                detected_ver,
                cpe_version=r["version"] or "",
                cpe_update=r["update_token"] or "",
                ver_start_incl=r["ver_start_incl"] or "",
                ver_start_excl=r["ver_start_excl"] or "",
                ver_end_incl=r["ver_end_incl"] or "",
                ver_end_excl=r["ver_end_excl"] or "",
            )
            if not ok:
                continue
            how = "cpe_range" if (
                (r["ver_start_incl"] or r["ver_start_excl"] or r["ver_end_incl"] or r["ver_end_excl"])
            ) else "cpe"
            title = str(r["title"] or "").replace("\n", " ").strip()[:240]
            _push(
                hits,
                cid,
                {
                    "id": cid,
                    "score": float(r["score"] or 0),
                    "title": title,
                    "how": how,
                    "matched_version": matched_ver,
                    "link": _cve_link(cid),
                    "nvd": _nvd_link(cid),
                    "cpe": display_cpe or _synth_cpe(product, detected_ver),
                },
            )

    # Legacy concrete CPE fallback when range table is empty/unavailable.
    if not has_match_table or not hits:
        needles = _version_sql_needles(detected_ver)
        for soft in softs:
            if not soft or not needles:
                continue
            ver_clause = " OR ".join(["instr(lower(cc.cpe), ?) > 0"] * len(needles))
            rows = conn.execute(
                f"""
                SELECT cc.cpe, cc.cve_id, COALESCE(c.cvss_score, 0) AS score,
                       COALESCE(c.description, '') AS title
                FROM cve_cpes cc
                JOIN cves c ON c.cve_id = cc.cve_id
                WHERE instr(lower(cc.cpe), ?) > 0
                  AND ({ver_clause})
                LIMIT 800
                """,
                (soft.lower(), *needles),
            ).fetchall()
            for r in rows:
                cid = str(r["cve_id"] or "")
                if not cid:
                    continue
                parsed_db = _parse_cpe23(r["cpe"] or "")
                db_ver = parsed_db.get("version") or ""
                if not _version_matches(detected_ver, db_ver):
                    continue
                if not _cpe_update_matches_detected(
                    detected_ver, parsed_db.get("update") or ""
                ):
                    continue
                title = str(r["title"] or "").replace("\n", " ").strip()[:240]
                _push(
                    hits,
                    cid,
                    {
                        "id": cid,
                        "score": float(r["score"] or 0),
                        "title": title,
                        "how": "cpe",
                        "matched_version": db_ver,
                        "link": _cve_link(cid),
                        "nvd": _nvd_link(cid),
                        "cpe": display_cpe or _synth_cpe(product, detected_ver),
                    },
                )

    tokens = _tokenize_product(product)
    if tokens:
        tokens_sorted = sorted(tokens, key=len, reverse=True)
        primary = tokens_sorted[0]
        ver_norm = _norm_ver(detected_ver)
        rows = conn.execute(
            """
            SELECT cp.vendor, cp.product, cp.version, cp.cve_id,
                   COALESCE(c.cvss_score, 0) AS score,
                   COALESCE(c.description, '') AS title
            FROM cve_products cp
            JOIN cves c ON c.cve_id = cp.cve_id
            WHERE instr(lower(cp.product), ?) > 0
              AND trim(COALESCE(cp.version,'')) NOT IN ('', '*', '-', 'n/a', 'any')
              AND (
                lower(COALESCE(cp.version,'')) = ?
                OR instr(lower(COALESCE(cp.version,'')), ?) = 1
              )
            LIMIT 800
            """,
            (primary, ver_norm, ver_norm),
        ).fetchall()
        for r in rows:
            vendor = r["vendor"] or ""
            prod = r["product"] or ""
            ver = r["version"] or ""
            cid = r["cve_id"]
            if not cid or not prod:
                continue
            if not _product_name_matches(tokens, vendor, prod):
                continue
            if not _version_matches(detected_ver, ver):
                continue
            if not _product_hit_has_ga_cpe(
                conn,
                cve_id=str(cid),
                vendor=vendor,
                product=prod,
                detected_ver=detected_ver,
            ):
                continue
            if not display_cpe:
                display_cpe = _synth_cpe(product, detected_ver)
            title = (r["title"] or "").replace("\n", " ").strip()[:240]
            _push(
                hits,
                cid,
                {
                    "id": cid,
                    "score": float(r["score"] or 0),
                    "title": title,
                    "how": "product",
                    "matched_version": ver,
                    "link": _cve_link(cid),
                    "nvd": _nvd_link(cid),
                    "cpe": display_cpe,
                },
            )

    return hits, display_cpe or _synth_cpe(product, version)


def correlate(
    *,
    product: str = "",
    version: str = "",
    cpes: list[str] | None = None,
    extrainfo: str = "",
    limit: int = _MAX,
) -> dict[str, Any]:
    """
    Correlate Nmap -sV product/version/CPE to local CVE rows.

    Discovers side products from banners (e.g. Python inside Werkzeug) and
    matches CPE wildcards (*) like vulners for the detected version.
    """
    product = (product or "").strip()
    version = (version or "").strip()
    extrainfo = (extrainfo or "").strip()
    cpes = [c for c in (cpes or []) if c]
    limit = max(1, min(int(limit or _MAX), 100))

    empty = {
        "source": "api",
        "product": product,
        "version": version,
        "extrainfo": extrainfo,
        "cpes": cpes,
        "cpe": [],
        "product_match": [],
        "by_cpe": [],
        "keyword": [],
        "exploitdb": [],
        "match_mode": "cpe_nvd_ranges",
    }

    if not version and not extrainfo and not cpes:
        empty["source"] = "skipped"
        empty["reason"] = "no version detected"
        return empty

    if version and _is_suppressed_fingerprint(product, version):
        empty["source"] = "suppressed"
        empty["suppressed"] = True
        empty["reason"] = "noisy fingerprint (Microsoft HTTPAPI httpd 2.0)"
        return empty

    targets = discover_targets(
        product=product, version=version, cpes=cpes, extrainfo=extrainfo
    )
    if not targets and version:
        targets = [{"product": product, "version": version, "cpes": cpes}]

    all_hits: dict[str, dict[str, Any]] = {}
    by_cpe_map: dict[str, dict[str, dict[str, Any]]] = {}

    with db_session() as conn:
        for t in targets:
            hits, display_cpe = _match_target(
                conn,
                product=t["product"],
                version=t["version"],
                cpes=t.get("cpes") or [],
                limit=limit,
            )
            if not display_cpe:
                display_cpe = _synth_cpe(t["product"], t["version"])
            bucket = by_cpe_map.setdefault(display_cpe, {})
            for cid, rec in hits.items():
                rec = dict(rec)
                rec["cpe"] = display_cpe
                _push(bucket, cid, rec)
                _push(all_hits, cid, rec)

    by_cpe = []
    for cpe_uri, bucket in by_cpe_map.items():
        rows = _sorted(bucket, limit)
        if rows:
            by_cpe.append({"cpe": cpe_uri, "cves": rows})
    by_cpe.sort(
        key=lambda g: (
            -max((float(x.get("score") or 0) for x in g["cves"]), default=0),
            g["cpe"],
        )
    )

    flat = _sorted(all_hits, limit)
    return {
        "source": "api",
        "product": product,
        "version": version,
        "extrainfo": extrainfo,
        "cpes": cpes,
        "targets": targets,
        "cpe": [r for r in flat if r.get("how") == "cpe"][:limit],
        "product_match": [r for r in flat if r.get("how") == "product"][:limit],
        "by_cpe": by_cpe,
        "keyword": [],
        "exploitdb": [],
        "match_mode": "cpe_nvd_ranges",
    }
