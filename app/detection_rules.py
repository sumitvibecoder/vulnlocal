"""Generate defensive YARA (EDR/file/memory) and Sigma (SIEM) detection rules.

Rules are heuristic templates derived from local CVE / Exploit-DB / Metasploit
metadata. They are starting points for blue-team tuning — not guaranteed IoCs.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .db import db_session, extract_cve_ids_from_codes


def _read_exploit_source(path: str, *, max_bytes: int = 40_000) -> dict[str, Any]:
    from .cve_detail import read_exploit_source

    return read_exploit_source(path, max_bytes=max_bytes)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.I)
_STR_RE = re.compile(r"[ -~]{10,96}")
_NOISE = {
    "copyright",
    "license",
    "http://",
    "https://",
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "function",
    "include",
    "printf",
    "return",
    "import ",
    "from ",
    "#!/usr/bin",
}


def _safe_ident(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", text)[:48].strip("_") or "rule"


def _yara_escape(s: str) -> str:
    return (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "")
        .replace("\t", "\\t")
    )


def _interesting_strings(text: str, *, limit: int = 8) -> list[str]:
    if not text:
        return []
    scored: list[tuple[int, str]] = []
    seen: set[str] = set()
    for m in _STR_RE.finditer(text):
        s = m.group(0).strip()
        low = s.lower()
        if low in seen:
            continue
        if any(n in low for n in _NOISE):
            continue
        if s.count(" ") > 12:
            continue
        # Prefer CVE / EDB / path-like / shell-ish tokens
        score = 0
        if "cve-" in low:
            score += 5
        if "edb" in low or "exploit" in low:
            score += 3
        if any(x in low for x in ("/bin/", "cmd.exe", "powershell", "wget ", "curl ")):
            score += 4
        if re.search(r"[\\/][\w.-]+\.(py|rb|pl|sh|exe|dll|ps1)", low):
            score += 3
        if score == 0 and not re.search(r"[A-Za-z]{4,}", s):
            continue
        if score == 0:
            score = 1
        seen.add(low)
        scored.append((score, s))
    scored.sort(key=lambda x: (-x[0], -len(x[1])))
    return [s for _, s in scored[:limit]]


def _load_context(cve_id: str) -> dict[str, Any]:
    cve_id = (cve_id or "").strip().upper()
    ctx: dict[str, Any] = {
        "cve_id": cve_id,
        "title": "",
        "products": [],
        "exploits": [],
        "metasploit": [],
        "ports": [],
        "strings": [],
    }
    if not _CVE_RE.match(cve_id):
        return ctx

    with db_session() as conn:
        cve = conn.execute(
            "SELECT description FROM cves WHERE cve_id = ?",
            (cve_id,),
        ).fetchone()
        if cve:
            desc = (cve["description"] or "").strip()
            ctx["title"] = desc.split(".")[0][:160] if desc else cve_id
        products = conn.execute(
            """
            SELECT DISTINCT vendor, product
            FROM cve_products
            WHERE cve_id = ?
            LIMIT 12
            """,
            (cve_id,),
        ).fetchall()
        ctx["products"] = [
            f"{r['vendor']}/{r['product']}".strip("/")
            for r in products
            if (r["product"] or "").strip()
        ]
        exploits = conn.execute(
            """
            SELECT e.edb_id, e.title, e.path, e.platform, e.type, e.port, e.codes
            FROM exploit_cves ec
            JOIN exploits e ON e.edb_id = ec.edb_id
            WHERE ec.cve_id = ?
            ORDER BY e.verified DESC, e.edb_id DESC
            LIMIT 8
            """,
            (cve_id,),
        ).fetchall()
        ctx["exploits"] = [dict(r) for r in exploits]
        for ex in ctx["exploits"]:
            port = str(ex.get("port") or "").strip()
            if port.isdigit():
                ctx["ports"].append(int(port))
        msf = conn.execute(
            """
            SELECT m.fullname, m.name, m.path, m.module_type
            FROM metasploit_module_cves mc
            JOIN metasploit_modules m ON m.fullname = mc.fullname
            WHERE mc.cve_id = ?
            LIMIT 6
            """,
            (cve_id,),
        ).fetchall()
        ctx["metasploit"] = [dict(r) for r in msf]

    # Pull distinctive strings from local EDB sources (truncated)
    for ex in ctx["exploits"][:4]:
        src = _read_exploit_source(str(ex.get("path") or ""), max_bytes=40_000)
        if src.get("available") and src.get("content"):
            ctx["strings"].extend(_interesting_strings(str(src["content"]), limit=6))
        title = str(ex.get("title") or "")
        ctx["strings"].extend(_interesting_strings(title, limit=2))

    # Always include CVE token and module paths
    ctx["strings"].insert(0, cve_id)
    for m in ctx["metasploit"][:3]:
        fullname = str(m.get("fullname") or "")
        if fullname:
            ctx["strings"].append(fullname)
            ctx["strings"].append(fullname.replace("/", "\\"))

    # Dedupe strings
    uniq: list[str] = []
    seen: set[str] = set()
    for s in ctx["strings"]:
        key = s.lower()
        if key in seen:
            continue
        seen.add(key)
        uniq.append(s)
    ctx["strings"] = uniq[:12]
    ctx["ports"] = sorted(set(ctx["ports"]))[:8]
    return ctx


def build_yara_rule(cve_id: str, *, ctx: dict[str, Any] | None = None) -> dict[str, str]:
    """YARA rule for EDR / file / memory hunting."""
    ctx = ctx or _load_context(cve_id)
    cve_id = ctx["cve_id"]
    ident = _safe_ident(cve_id)
    strings = ctx.get("strings") or [cve_id]
    # Ensure at least CVE ascii + wide
    body_lines = []
    for i, s in enumerate(strings[:10], start=1):
        esc = _yara_escape(s)
        body_lines.append(f'    $s{i} = "{esc}" ascii wide nocase')

    condition = "$s1"
    if len(strings) >= 3:
        condition = "2 of them"
    elif len(strings) == 2:
        condition = "any of them"

    products = ", ".join(ctx.get("products") or [])[:180]
    rule = f"""rule vulnlocal_{ident}
{{
  meta:
    author = "vulnlocal"
    description = "Heuristic detection aid for {cve_id}"
    cve = "{cve_id}"
    reference = "https://www.cve.org/CVERecord?id={cve_id}"
    products = "{_yara_escape(products)}"
    severity = "experimental"
    generated_by = "vulnlocal detection_rules"
  strings:
{chr(10).join(body_lines)}
  condition:
    {condition}
}}
"""
    digest = hashlib.sha1(rule.encode("utf-8"), usedforsecurity=False).hexdigest()[:12]
    return {
        "format": "yara",
        "name": f"vulnlocal_{ident}",
        "cve_id": cve_id,
        "hash": digest,
        "content": rule,
        "use": "Import into EDR / YARA scanners for file and memory hunting. Tune before production.",
    }


def build_sigma_rule(cve_id: str, *, ctx: dict[str, Any] | None = None) -> dict[str, str]:
    """Sigma rule template for SIEM correlation (process / network heuristics)."""
    ctx = ctx or _load_context(cve_id)
    cve_id = ctx["cve_id"]
    ports = ctx.get("ports") or []
    products = ctx.get("products") or ["unknown"]
    product_hint = products[0] if products else "unknown"
    title = ctx.get("title") or cve_id

    # Prefer network destination ports when EDB lists a port; else generic process hunt
    if ports:
        port_list = ", ".join(str(p) for p in ports)
        detection = f"""detection:
  selection:
    DestinationPort:
{chr(10).join(f'      - {p}' for p in ports)}
  condition: selection
"""
        logsource = """logsource:
  category: firewall
  product: any
"""
        desc = f"Heuristic SIEM alert when traffic hits ports associated with {cve_id} exploits in the local index ({port_list})."
    else:
        keywords = [cve_id] + [str(e.get("edb_id")) for e in (ctx.get("exploits") or [])[:3]]
        keywords += [str(m.get("fullname") or "") for m in (ctx.get("metasploit") or [])[:2]]
        keywords = [k for k in keywords if k]
        detection = f"""detection:
  selection:
    CommandLine|contains:
{chr(10).join(f'      - "{k}"' for k in keywords[:6])}
  condition: selection
"""
        logsource = """logsource:
  category: process_creation
  product: windows
"""
        desc = f"Heuristic SIEM alert when process command lines reference {cve_id} / related exploit identifiers."

    rule = f"""title: vulnlocal - {cve_id} heuristic
id: vulnlocal-{cve_id.lower()}
status: experimental
description: |
  {desc}
  Product hint: {product_hint}. Summary: {title}
references:
  - https://www.cve.org/CVERecord?id={cve_id}
author: vulnlocal
date: 2026/08/05
tags:
  - attack.execution
  - cve.{cve_id[4:].replace('-', '.')}
{logsource}
{detection}falsepositives:
  - Security researchers, scanners, and patch tooling mentioning the CVE ID
level: medium
"""
    return {
        "format": "sigma",
        "name": f"vulnlocal-{cve_id.lower()}",
        "cve_id": cve_id,
        "content": rule,
        "use": "Convert with sigmac / pySigma for Splunk, Elastic, Sentinel, etc. Tune before production.",
    }


def build_detection_pack(cve_id: str) -> dict[str, Any]:
    """YARA + Sigma pack for a CVE, plus per-exploit YARA variants when source exists."""
    ctx = _load_context(cve_id)
    yara = build_yara_rule(cve_id, ctx=ctx)
    sigma = build_sigma_rule(cve_id, ctx=ctx)
    exploit_rules: list[dict[str, str]] = []
    for ex in ctx.get("exploits") or []:
        edb_id = ex.get("edb_id")
        path = str(ex.get("path") or "")
        src = _read_exploit_source(path, max_bytes=40_000) if path else {}
        strings = [f"EDB-{edb_id}", cve_id, str(ex.get("title") or "")[:80]]
        if src.get("available") and src.get("content"):
            strings.extend(_interesting_strings(str(src["content"]), limit=6))
        # Build a focused mini context
        mini = {
            "cve_id": cve_id,
            "title": str(ex.get("title") or ""),
            "products": ctx.get("products") or [],
            "strings": strings,
            "exploits": [ex],
            "metasploit": [],
            "ports": [int(ex["port"])] if str(ex.get("port") or "").isdigit() else [],
        }
        rule = build_yara_rule(cve_id, ctx=mini)
        rule["name"] = f"vulnlocal_EDB_{edb_id}"
        rule["content"] = rule["content"].replace(
            f"rule vulnlocal_{_safe_ident(cve_id)}",
            f"rule vulnlocal_EDB_{edb_id}",
            1,
        )
        rule["edb_id"] = str(edb_id)
        exploit_rules.append(rule)

    return {
        "cve_id": cve_id,
        "yara": yara,
        "sigma": sigma,
        "exploit_yara": exploit_rules[:6],
        "note": (
            "Generated defensive hunting templates from local metadata/source strings. "
            "Validate and tune before deploying to EDR or SIEM."
        ),
    }


def build_detection_pack_for_edb(edb_id: int) -> dict[str, Any]:
    """YARA focused on a single Exploit-DB entry (and linked CVEs)."""
    with db_session() as conn:
        row = conn.execute(
            "SELECT edb_id, title, path, platform, type, port, codes FROM exploits WHERE edb_id = ?",
            (int(edb_id),),
        ).fetchone()
    if not row:
        return {"error": "not found", "edb_id": edb_id}
    cves = extract_cve_ids_from_codes(row["codes"])
    primary = cves[0] if cves else f"EDB-{edb_id}"
    pack = build_detection_pack(primary) if cves else None
    if pack:
        return pack
    # No CVE — still emit YARA from the exploit alone
    src = _read_exploit_source(str(row["path"] or ""), max_bytes=40_000)
    strings = [f"EDB-{edb_id}", str(row["title"] or "")[:80]]
    if src.get("available") and src.get("content"):
        strings.extend(_interesting_strings(str(src["content"]), limit=8))
    ctx = {
        "cve_id": f"EDB_{edb_id}",
        "title": row["title"],
        "products": [],
        "strings": strings,
        "exploits": [dict(row)],
        "metasploit": [],
        "ports": [int(row["port"])] if str(row["port"] or "").isdigit() else [],
    }
    yara = build_yara_rule(f"EDB_{edb_id}", ctx=ctx)
    yara["name"] = f"vulnlocal_EDB_{edb_id}"
    yara["content"] = yara["content"].replace(
        f"rule vulnlocal_{_safe_ident('EDB_'+str(edb_id))}",
        f"rule vulnlocal_EDB_{edb_id}",
        1,
    )
    return {
        "edb_id": edb_id,
        "yara": yara,
        "sigma": None,
        "exploit_yara": [yara],
        "note": "Exploit-only rule (no CVE mapping).",
    }
