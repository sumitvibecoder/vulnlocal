"""Threat / vulnerability category taxonomy for overview + CVE detail."""

from __future__ import annotations

import re
from typing import Any

# Ordered: first match wins (more specific before generic).
CATEGORY_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("SQL Injection", ("sql injection", "sqli", "cwe-89")),
    ("Command Injection", ("command injection", "os command", "shell injection", "cwe-78", "cwe-77")),
    ("Code Injection", ("code injection", "cwe-94", "eval injection")),
    ("Remote Code Execution", ("remote code execution", "execute arbitrary code", "arbitrary code execution", " rce ")),
    ("Local Privilege Escalation", ("local privilege", "elevation of privilege", "privilege escalation", "gain privileges", "cwe-269")),
    ("Authentication Bypass", ("authentication bypass", "bypass authentication", "auth bypass", "cwe-287")),
    ("Authorization Bypass", ("authorization bypass", "broken access control", "privilege bypass", "cwe-285", "cwe-639")),
    ("Cross-Site Scripting", ("cross-site scripting", " xss", "stored xss", "reflected xss", "cwe-79")),
    ("Cross-Site Request Forgery", ("cross-site request forgery", " csrf", "cwe-352")),
    ("Server-Side Request Forgery", ("server-side request forgery", " ssrf", "cwe-918")),
    ("XML External Entity", ("xml external entity", " xxe", "cwe-611")),
    ("Deserialization", ("deserialization", "unserialize", "insecure deserialization", "cwe-502")),
    ("Path Traversal", ("path traversal", "directory traversal", "lfi", "local file inclusion", "cwe-22")),
    ("Remote File Inclusion", ("remote file inclusion", " rfi ")),
    ("Buffer Overflow", ("buffer overflow", "heap overflow", "stack overflow", "heap-based buffer", "stack-based buffer", "cwe-119", "cwe-120", "cwe-122")),
    ("Use After Free", ("use after free", "use-after-free", "cwe-416")),
    ("Integer Overflow", ("integer overflow", "integer underflow", "cwe-190")),
    ("Memory Corruption", ("memory corruption", "out-of-bounds", "out of bounds", "cwe-125", "cwe-787")),
    ("Denial of Service", ("denial of service", "resource exhaustion", "cpu consumption", "infinite loop", "crash", "cwe-400")),
    ("Information Disclosure", ("information disclosure", "information leak", "sensitive information", "cleartext", "cwe-200")),
    ("Cryptographic Weakness", ("weak encryption", "weak cipher", "cryptographic", "hardcoded key", "insufficient entropy", "cwe-327", "cwe-330")),
    ("Insecure Configuration", ("misconfiguration", "insecure default", "default credentials", "hardcoded password", "cwe-16")),
    ("Supply Chain", ("supply chain", "dependency confusion", "typosquat", "malicious package")),
    ("Race Condition", ("race condition", "toctou", "time-of-check", "cwe-362")),
    ("Open Redirect", ("open redirect", "url redirection", "cwe-601")),
    ("Clickjacking", ("clickjacking", "ui redress", "cwe-1021")),
    ("Man-in-the-Middle", ("man-in-the-middle", "mitm", "cwe-300")),
    ("Session Fixation", ("session fixation", "session hijack", "cwe-384")),
    ("CSRF Token Bypass", ("csrf token", "missing csrf")),
    ("HTTP Request Smuggling", ("request smuggling", "http smuggling", "cwe-444")),
    ("Prototype Pollution", ("prototype pollution",)),
    ("LDAP Injection", ("ldap injection", "cwe-90")),
    ("XPath Injection", ("xpath injection", "cwe-643")),
    ("Template Injection", ("template injection", "ssti")),
    ("File Upload Abuse", ("unrestricted upload", "arbitrary file upload", "cwe-434")),
    ("DNS Rebinding", ("dns rebinding",)),
    ("Side-Channel", ("side-channel", "timing attack", "spectre", "meltdown")),
    ("Firmware / Hardware", ("firmware", "bootrom", "uefi", "bios vulnerability")),
    ("Container Escape", ("container escape", "docker escape", "kubernetes escape")),
    ("Cloud / IAM Abuse", ("iam policy", "overly permissive", "cloud metadata", "instance metadata")),
]

# Friendly labels for Exploit-DB type buckets shown on the home page.
EDB_TYPE_LABELS = {
    "remote": "Remote exploits",
    "local": "Local exploits",
    "webapps": "Web application",
    "dos": "Denial of Service",
    "shellcode": "Shellcode",
    "papers": "Papers / research",
    "hardware": "Hardware",
}


def guess_category(description: str, problem_types: list | None = None) -> str:
    """Pick a single primary threat category for a CVE."""
    blobs: list[str] = []
    for pt in problem_types or []:
        if isinstance(pt, dict):
            blobs.append(str(pt.get("description") or ""))
            blobs.append(str(pt.get("cwe_id") or ""))
        else:
            blobs.append(str(pt or ""))
    blobs.append(description or "")
    text = " ".join(blobs).lower()
    # Pad so short tokens like " xss" match
    padded = f" {text} "

    for label, needles in CATEGORY_RULES:
        for n in needles:
            if n.startswith("cwe-"):
                if n in text:
                    return label
            elif n in padded or n in text:
                return label
    return "Uncategorized"


def category_labels() -> list[str]:
    return [label for label, _ in CATEGORY_RULES] + ["Uncategorized"]


def overview_category_counts_sql(*, table: str = "cves", sample_limit: int | None = None) -> str:
    """
    Build a single-pass SQL that buckets CVEs into exclusive threat categories.
    Used to refresh home-page overview stats.

    sample_limit: when set, only the newest `sample_limit` rows (by date) are
    classified — full-table CASE over 300k+ descriptions is too slow for Sync.
    """
    if table not in {"cves", "nvd_cves"}:
        table = "cves"
    date_col = "date_published" if table == "cves" else "published"
    whens: list[str] = []
    for label, needles in CATEGORY_RULES:
        parts: list[str] = []
        for n in needles:
            esc = n.replace("'", "''")
            parts.append(f"instr(lower(coalesce(description,'')), '{esc}') > 0")
        whens.append(f"WHEN ({' OR '.join(parts)}) THEN '{label.replace(chr(39), chr(39)+chr(39))}'")
    case_sql = "CASE\n          " + "\n          ".join(whens) + "\n          ELSE 'Uncategorized'\n        END"
    if sample_limit and int(sample_limit) > 0:
        lim = int(sample_limit)
        from_sql = f"""
          SELECT description FROM {table}
          WHERE description IS NOT NULL AND trim(description) != ''
          ORDER BY COALESCE({date_col}, '') DESC
          LIMIT {lim}
        """
    else:
        from_sql = f"SELECT description FROM {table}"
    return f"""
        SELECT cat AS name, COUNT(*) AS n
        FROM (
          SELECT {case_sql} AS cat
          FROM ({from_sql}) AS sample_rows
        )
        GROUP BY cat
        ORDER BY n DESC
    """


def merge_overview_categories(
    cve_cats: list[dict[str, Any]],
    edb_cats: list[dict[str, Any]],
    *,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """
    Build the full threat-category list for the home page.

    Always includes every label from ``category_labels()`` (40 taxonomy +
    Uncategorized = 41). CVE/EDB counts fill matching buckets; missing ones
    stay at 0 so the UI can show the complete set.
    """
    # Map Exploit-DB friendly labels onto the CVE taxonomy where they overlap.
    edb_into_taxonomy = {
        "Denial of Service": "Denial of Service",
        "Hardware": "Firmware / Hardware",
    }

    merged: dict[str, int] = {name: 0 for name in category_labels()}
    for row in cve_cats:
        name = (row.get("name") or "").strip()
        if not name:
            continue
        if name not in merged:
            # Keep unexpected labels only when caller asks for an unbounded list.
            if limit is not None:
                continue
            merged[name] = 0
        merged[name] = merged.get(name, 0) + int(row.get("count") or row.get("n") or 0)

    for row in edb_cats:
        raw = (row.get("name") or "").strip().lower()
        if not raw:
            continue
        friendly = EDB_TYPE_LABELS.get(raw, raw.title())
        name = edb_into_taxonomy.get(friendly)
        if not name or name not in merged:
            continue
        # DoS already counted from CVE descriptions — skip double-count.
        if raw == "dos" and merged.get(name, 0) > 0:
            continue
        merged[name] = merged.get(name, 0) + int(row.get("count") or row.get("n") or 0)

    # Non-zero first (by count desc), then alphabetical zeros — full taxonomy kept.
    ordered = sorted(
        merged.items(),
        key=lambda x: (0 if x[1] > 0 else 1, -x[1], x[0].lower()),
    )
    if limit is not None and limit > 0:
        ordered = ordered[:limit]
    return [{"name": n, "count": c} for n, c in ordered]
