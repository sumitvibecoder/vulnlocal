"""CVE detail assembly: local CVE record + Exploit-DB links/source."""

from __future__ import annotations

import json
import logging
import re
import time
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from . import config
from .db import db_session, extract_cve_ids_from_codes
from .sqlutil import in_placeholders

log = logging.getLogger("vulnlocal.cve_detail")

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.I)
_GITHUB_REPO_RE = re.compile(
    r"https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:/|$)",
    re.I,
)
_GHSA_RE = re.compile(r"/security/advisories/(GHSA-[A-Za-z0-9-]+)", re.I)
_POC_FETCH_TIMEOUT = 8
_MAX_SOURCE_BYTES = 180_000
_BINARY_EXTS = {
    ".exe",
    ".dll",
    ".bin",
    ".so",
    ".o",
    ".obj",
    ".class",
    ".jar",
    ".war",
    ".zip",
    ".gz",
    ".tgz",
    ".rar",
    ".7z",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".pdf",
}


def _guess_category(description: str, problem_types: list) -> str:
    from .threat_categories import guess_category

    # Prefer taxonomy match; fall back to cleaned CWE description when no rule hits.
    cat = guess_category(description or "", problem_types or [])
    if cat != "Uncategorized":
        return cat
    for pt in problem_types or []:
        if isinstance(pt, dict):
            text = (pt.get("description") or pt.get("cwe_id") or "").strip()
        else:
            text = str(pt or "").strip()
        if text and text.lower() not in {"n/a", "unknown", "other"}:
            return re.sub(r"^CWE-\d+\s*:?\s*", "", text, flags=re.I).strip() or text
    return "Uncategorized"


def _cwe_mitre_url(cwe_id: str) -> str:
    m = re.search(r"(\d+)", cwe_id or "")
    if not m:
        return "https://cwe.mitre.org/"
    return f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html"


def _parse_problem_types(cna: dict[str, Any]) -> list[dict[str, str]]:
    """Extract CWE entries with clickable MITRE links."""
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for block in cna.get("problemTypes") or []:
        for d in block.get("descriptions") or []:
            if not isinstance(d, dict):
                continue
            cwe_id = (d.get("cweId") or "").strip().upper()
            desc = (d.get("description") or "").strip()
            if not cwe_id:
                m = re.search(r"(CWE-\d+)", desc, re.I)
                if m:
                    cwe_id = m.group(1).upper()
            if not cwe_id and not desc:
                continue
            if desc.lower() in {"n/a", "unknown"} and not cwe_id:
                continue
            key = cwe_id or desc.lower()
            if key in seen:
                continue
            seen.add(key)
            # Clean description so it doesn't always repeat "CWE-22: ..."
            label = desc
            if cwe_id and label.upper().startswith(cwe_id):
                label = re.sub(rf"^{re.escape(cwe_id)}\s*:?\s*", "", label, flags=re.I).strip()
            label = re.sub(r"\s*\(CWE-\d+\)\s*$", "", label, flags=re.I).strip()
            out.append(
                {
                    "cwe_id": cwe_id,
                    "description": label or desc or cwe_id,
                    "url": _cwe_mitre_url(cwe_id) if cwe_id else "",
                }
            )
    return out


def _load_cve_json(source_path: str | None) -> dict[str, Any] | None:
    if not source_path:
        return None
    path = Path(source_path)
    if not path.is_file():
        # Try resolving under local tree by CVE id later
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _find_cve_json_by_id(cve_id: str) -> dict[str, Any] | None:
    """Locate CVE JSON under local cvelist tree when source_path is stale."""
    m = re.match(r"CVE-(\d{4})-(\d+)$", cve_id, re.I)
    if not m:
        return None
    year, num = m.group(1), m.group(2)
    bucket = f"{num[:-3]}xxx" if len(num) > 3 else "0xxx"
    candidates = [
        config.LOCAL_CVE_TREE / "cves" / year / bucket / f"{cve_id.upper()}.json",
        config.CVE_EXTRACT_DIR / "cvelistV5-main" / "cves" / year / bucket / f"{cve_id.upper()}.json",
    ]
    for path in candidates:
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                continue
    return None


_PATCH_TAGS = {
    "patch",
    "vendor-advisory",
    "release-notes",
    "fix",
    "mitigation",
    "official-fix",
    "x_refsource_confirm",
    "x_refsource_vendor",
}
_PATCH_URL_HINTS = (
    "/releases/tag/",
    "/releases/download/",
    "catalog.update.microsoft.com",
    "msrc.microsoft.com",
    "support.microsoft.com",
    "/security/advisories/",
    "/security/bulletin",
    "portal.msrc.microsoft.com",
    "aka.ms/",
    "/commit/",
    "errata.redhat.com",
    "access.redhat.com/errata",
    "ubuntu.com/security",
    "debian.org/security",
    "suse.com/support/update",
    "oracle.com/security-alerts",
    "cisco.com/security",
    "adobe.com/support/security",
    "helpx.adobe.com/security",
    "apple.com/support/security",
    "android.com/docs/security",
    "source.android.com/docs/security",
)
_BLOG_TAGS = {
    "third-party-advisory",
    "technical-description",
    "mailing-list",
    "exploit",
    "issue-tracking",
    "related",
    "article",
    "blog",
    "x_refsource_misc",
    "x_refsource_confirm",
}
_BLOG_URL_HINTS = (
    "medium.com/",
    "blogspot.",
    "blog.",
    "/blog/",
    "github.io/",
    "substack.com/",
    "dev.to/",
    "hashnode.",
    "seclists.org/",
    "packetstormsecurity.com/",
    "securityweek.com/",
    "thehackernews.com/",
    "bleepingcomputer.com/",
    "rapid7.com/blog",
    "unit42.paloaltonetworks.com",
    "blog.talosintelligence.com",
    "research.checkpoint.com",
    "securelist.com/",
    "mandiant.com/",
    "crowdstrike.com/blog",
    "microsoft.com/en-us/security/blog",
    "aws.amazon.com/blogs",
    "cloud.google.com/blog",
    "projectdiscovery.io/blog",
    "hackernoon.com/",
    "infosecwriteups.com/",
    "gist.github.com/",
    "vulncheck.com/advisories",
    "snyk.io/blog",
    "sonarsource.com/blog",
    "portswigger.net/",
    "exploit-db.com/",
)


def _format_version_range(ver: dict[str, Any]) -> str:
    """Human-readable affected/fixed version expression from CVE JSON version object."""
    version = str(ver.get("version") or "").strip()
    status = str(ver.get("status") or "").strip()
    parts: list[str] = []

    if version and version not in {"0", "*"}:
        parts.append(version)
    elif version == "0" and (ver.get("lessThan") or ver.get("lessThanOrEqual")):
        parts.append("0")
    elif version == "*":
        parts.append("*")

    if ver.get("lessThan"):
        parts.append(f"< {ver['lessThan']}")
    if ver.get("lessThanOrEqual"):
        parts.append(f"<= {ver['lessThanOrEqual']}")
    if ver.get("greaterThan"):
        parts.append(f"> {ver['greaterThan']}")
    if ver.get("greaterThanOrEqual"):
        parts.append(f">= {ver['greaterThanOrEqual']}")

    # changes[] often records the fixed release
    fixed_ats: list[str] = []
    for ch in ver.get("changes") or []:
        if not isinstance(ch, dict):
            continue
        at = str(ch.get("at") or "").strip()
        ch_status = str(ch.get("status") or "").lower()
        if at and ch_status in {"unaffected", "fixed"}:
            fixed_ats.append(at)

    text = " ".join(parts).strip() or version or "—"
    if fixed_ats:
        text = f"{text} (fixed in {', '.join(fixed_ats)})"
    if status and status.lower() not in {"affected", ""}:
        text = f"{text} [{status}]"
    return text


def _collect_affected_from_container(block: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for affected in block.get("affected") or []:
        vendor = (affected.get("vendor") or "").strip() or "unknown"
        product = (affected.get("product") or "").strip() or "unknown"
        package = (affected.get("packageName") or "").strip()
        platform = ", ".join(affected.get("platforms") or []) if isinstance(affected.get("platforms"), list) else ""
        versions = affected.get("versions") or [{}]
        default_status = str(affected.get("defaultStatus") or "")
        for ver in versions:
            if not isinstance(ver, dict):
                ver = {}
            status = str(ver.get("status") or default_status or "")
            version_raw = str(ver.get("version") or "")
            version_label = _format_version_range(ver)
            fixed_versions = []
            for ch in ver.get("changes") or []:
                if isinstance(ch, dict) and str(ch.get("status") or "").lower() in {"unaffected", "fixed"}:
                    at = str(ch.get("at") or "").strip()
                    if at:
                        fixed_versions.append(at)
            rows.append(
                {
                    "vendor": vendor,
                    "product": product,
                    "package": package,
                    "platform": platform,
                    "version": version_raw,
                    "version_label": version_label,
                    "status": status,
                    "less_than": str(ver.get("lessThan") or ""),
                    "less_than_or_equal": str(ver.get("lessThanOrEqual") or ""),
                    "greater_than": str(ver.get("greaterThan") or ""),
                    "greater_than_or_equal": str(ver.get("greaterThanOrEqual") or ""),
                    "fixed_versions": ", ".join(fixed_versions),
                }
            )
    return rows


def _is_patch_ref(url: str, tags: list[str]) -> bool:
    tag_set = {t.lower() for t in tags}
    if tag_set & _PATCH_TAGS:
        return True
    low = url.lower()
    return any(h in low for h in _PATCH_URL_HINTS)


def _is_blog_or_writeup_ref(url: str, tags: list[str]) -> bool:
    tag_set = {t.lower() for t in tags}
    if tag_set & _BLOG_TAGS:
        return True
    low = url.lower()
    return any(h in low for h in _BLOG_URL_HINTS)


def _patch_kind(url: str, tags: list[str]) -> str:
    low = url.lower()
    tag_set = {t.lower() for t in tags}
    if "catalog.update.microsoft.com" in low or "msrc.microsoft.com" in low or "portal.msrc" in low:
        return "Microsoft update"
    if "/releases/download/" in low:
        return "Download"
    if "/releases/tag/" in low:
        return "Release"
    if "/commit/" in low:
        return "Commit / fix"
    if "/security/advisories/" in low or "vendor-advisory" in tag_set:
        return "Vendor advisory"
    if "patch" in tag_set:
        return "Patch"
    if "fix" in tag_set or "official-fix" in tag_set:
        return "Fix"
    if "mitigation" in tag_set:
        return "Mitigation"
    return "Advisory"


def _ghsa_vendor_display_name(url: str) -> str | None:
    """
    For GitHub Security Advisory (GHSA) URLs, return a friendly label.

    Example:
      https://github.com/org/repo/security/advisories/GHSA-vh22-h7hf-www7
      -> Vendor advisory GitHub Security Advisory (GHSA-vh22-h7hf-www7)
    """
    m = _GHSA_RE.search((url or "").strip())
    if not m:
        return None
    ghsa_id = m.group(1).upper()
    return f"Vendor advisory GitHub Security Advisory ({ghsa_id})"


def _writeup_kind(url: str, tags: list[str]) -> str:
    low = url.lower()
    tag_set = {t.lower() for t in tags}
    if "gist.github.com" in low:
        return "Technical notes"
    if "third-party-advisory" in tag_set or "vulncheck.com" in low:
        return "Third-party advisory"
    if "mailing-list" in tag_set or "seclists.org" in low:
        return "Mailing list"
    if any(h in low for h in ("/blog/", "blog.", "medium.com", "substack.com", "dev.to")):
        return "Blog"
    if "exploit" in tag_set or "exploit-db.com" in low:
        return "Exploit write-up"
    return "Analysis"


def _supplemental_remediation_links(cve_id: str, existing_urls: set[str]) -> list[dict[str, str]]:
    """
    Extra remediation / write-up discovery links.

    CVE List V5 often only carries the vendor advisory; these help find blogs
    and remediation guidance without inventing fake article URLs.
    """
    q = cve_id.replace(" ", "+")
    candidates = [
        {
            "kind": "NVD",
            "name": f"NVD vulnerability detail - {cve_id}",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        },
        {
            "kind": "CVE.org",
            "name": f"CVE Program record - {cve_id}",
            "url": f"https://www.cve.org/CVERecord?id={cve_id}",
        },
        {
            "kind": "OSV",
            "name": f"OSV.dev - {cve_id}",
            "url": f"https://osv.dev/vulnerability/{cve_id}",
        },
        {
            "kind": "Remediation blogs",
            "name": f"Search remediation blogs & write-ups for {cve_id}",
            "url": (
                "https://www.google.com/search?q="
                f"{q}+(remediation+OR+mitigation+OR+patch+OR+fix)+(blog+OR+writeup+OR+analysis)"
            ),
        },
        {
            "kind": "Security blogs",
            "name": f"Search security blog coverage for {cve_id}",
            "url": (
                "https://www.google.com/search?q="
                f"{q}+site:medium.com+OR+site:seclists.org+OR+site:bleepingcomputer.com"
                "+OR+site:thehackernews.com+OR+site:rapid7.com"
            ),
        },
    ]
    out: list[dict[str, str]] = []
    for item in candidates:
        if item["url"] in existing_urls:
            continue
        out.append(item)
        existing_urls.add(item["url"])
    return out


def _pick_cvss_from_json(data: dict[str, Any]) -> dict[str, Any]:
    """Re-read CVSS from local JSON so vector/severity are complete on the detail page."""
    containers = data.get("containers") or {}
    best: dict[str, Any] | None = None

    def consider(metrics: list | None) -> None:
        nonlocal best
        if not metrics:
            return
        for metric in metrics:
            for key, version in (("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"), ("cvssV2", "2.0")):
                block = metric.get(key)
                if not block:
                    continue
                score = block.get("baseScore")
                if score is None:
                    continue
                try:
                    score_f = float(score)
                except (TypeError, ValueError):
                    continue
                candidate = {
                    "score": score_f,
                    "vector": block.get("vectorString") or "",
                    "severity": (block.get("baseSeverity") or metric.get("baseSeverity") or ""),
                    "version": version,
                }
                if best is None or score_f > float(best["score"]):
                    best = candidate

    cna = containers.get("cna") or {}
    consider(cna.get("metrics"))
    for adp in containers.get("adp") or []:
        consider(adp.get("metrics"))
    return best or {}


def _enrich_from_json(data: dict[str, Any]) -> dict[str, Any]:
    containers = data.get("containers") or {}
    cna = containers.get("cna") or {}
    meta = data.get("cveMetadata") or {}

    problem_types = _parse_problem_types(cna)

    # Collect references from CNA + ADP
    references: list[dict[str, str]] = []
    patches: list[dict[str, str]] = []
    writeups: list[dict[str, str]] = []
    seen_urls: set[str] = set()

    def add_ref(ref: dict[str, Any]) -> None:
        url = (ref.get("url") or "").strip()
        if not url or url in seen_urls:
            return
        seen_urls.add(url)
        tags = ref.get("tags") or []
        if not isinstance(tags, list):
            tags = [str(tags)]
        tag_list = [str(t) for t in tags]
        name = (ref.get("name") or url)[:220]
        item = {"url": url, "name": name, "tags": ""}  # tags hidden in UI
        references.append(item)
        if _is_patch_ref(url, tag_list):
            kind = _patch_kind(url, tag_list)
            patch_item = {**item, "kind": kind}
            if kind == "Vendor advisory":
                ghsa_name = _ghsa_vendor_display_name(url)
                if ghsa_name:
                    patch_item["name"] = ghsa_name
            patches.append(patch_item)
        elif _is_blog_or_writeup_ref(url, tag_list):
            writeups.append(
                {
                    **item,
                    "kind": _writeup_kind(url, tag_list),
                }
            )

    for ref in cna.get("references") or []:
        if isinstance(ref, dict):
            add_ref(ref)
    for adp in containers.get("adp") or []:
        for ref in adp.get("references") or []:
            if isinstance(ref, dict):
                add_ref(ref)

    cve_id = (meta.get("cveId") or "").upper()
    remediation = list(writeups)
    if cve_id:
        remediation.extend(_supplemental_remediation_links(cve_id, set(seen_urls)))

    credits: list[str] = []
    for credit in cna.get("credits") or []:
        if isinstance(credit, dict):
            val = (credit.get("value") or "").strip()
            if val:
                credits.append(val)
        elif isinstance(credit, str) and credit.strip():
            credits.append(credit.strip())
    for credit in cna.get("credit") or []:
        if isinstance(credit, dict):
            val = (credit.get("value") or "").strip()
            if val:
                credits.append(val)

    title = ""
    raw_title = cna.get("title")
    if isinstance(raw_title, str):
        title = raw_title.strip()

    affected_rows = _collect_affected_from_container(cna)
    for adp in containers.get("adp") or []:
        # Prefer CNA product rows; ADP often duplicates CPE-oriented entries
        if not affected_rows:
            affected_rows.extend(_collect_affected_from_container(adp))

    # Distinct affected versions list (status=affected primarily)
    affected_versions: list[dict[str, str]] = []
    fixed_versions: list[str] = []
    seen_ver: set[str] = set()
    for row in affected_rows:
        key = f"{row['vendor']}|{row['product']}|{row['version_label']}|{row['status']}"
        if key in seen_ver:
            continue
        seen_ver.add(key)
        if (row.get("status") or "").lower() in {"affected", "unknown", ""}:
            affected_versions.append(row)
        if row.get("fixed_versions"):
            for fv in row["fixed_versions"].split(", "):
                if fv and fv not in fixed_versions:
                    fixed_versions.append(fv)

    cvss = _pick_cvss_from_json(data)

    return {
        "problem_types": problem_types,
        "references": references[:60],
        "patches": patches[:40],
        "remediation": remediation[:40],
        "credits": credits[:20],
        "title": title,
        "date_reserved": meta.get("dateReserved") or "",
        "date_public": (cna.get("datePublic") or meta.get("datePublished") or ""),
        "affected_rows": affected_rows,
        "affected_versions": affected_versions,
        "fixed_versions": fixed_versions,
        "cvss": cvss,
    }


def _normalize_github_repo(url: str) -> tuple[str, str, str] | None:
    """Return (html_url, full_name, owner/repo) for a GitHub repo URL, else None."""
    m = _GITHUB_REPO_RE.match((url or "").strip())
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    # Skip non-repo paths
    if owner.lower() in {"topics", "search", "orgs", "settings", "marketplace", "sponsors"}:
        return None
    if repo.lower() in {"releases", "issues", "pulls", "actions", "security", "commit", "commits", "blob", "tree"}:
        return None
    full_name = f"{owner}/{repo}"
    return f"https://github.com/{full_name}", full_name, full_name


def _github_pocs_from_references(references: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ref in references:
        url = (ref.get("url") or "").strip()
        norm = _normalize_github_repo(url)
        if not norm:
            continue
        html_url, full_name, _ = norm
        if html_url.lower() in seen:
            continue
        seen.add(html_url.lower())
        out.append(
            {
                "html_url": html_url,
                "full_name": full_name,
                "description": ref.get("name") if ref.get("name") != url else "",
                "source": "cve-reference",
                "stargazers_count": None,
            }
        )
    return out


def _poc_cache_path(cve_id: str) -> Path:
    year = cve_id.split("-")[1] if "-" in cve_id else "unknown"
    return config.DOWNLOAD_DIR / "poc_github_cache" / year / f"{cve_id}.json"


def _exploit_type_label(source: str, raw_type: str = "", url: str = "") -> str:
    """XDB-style exploit type label (Git Repository PoC, Remote, Webapps, …)."""
    src = (source or "").lower()
    t = (raw_type or "").strip().lower()
    low = (url or "").lower()

    edb_map = {
        "remote": "Remote",
        "local": "Local",
        "webapps": "Web application",
        "dos": "Denial of Service",
        "shellcode": "Shellcode",
        "papers": "Paper / research",
        "hardware": "Hardware",
    }
    if t in edb_map:
        return edb_map[t]

    if "virustotal.com" in low or src == "virustotal":
        return "Malware / sample hash"
    if "vulncheck.com/xdb" in low or src in {"vulncheck xdb", "xdb"}:
        return "Git Repository PoC"
    if "vulncheck.com" in low:
        return "Third-party advisory"
    if "rapid7.com/db/vulnerabilities" in low:
        return "Vulnerability advisory"
    if "rapid7.com/db/modules" in low or "metasploit" in src or "metasploit" in low:
        return "Metasploit module"
    if "exploit-db.com" in low or src in {"exploit-db", "edb"}:
        return edb_map.get(t, "Public exploit")
    if "github.com" in low or "github" in src or "poc" in src:
        return "Git Repository PoC"
    if "packetstorm" in low:
        return "Public exploit"
    if "search" in src:
        return "Discovery search"
    return (raw_type or source or "Exploit").strip() or "Exploit"


def _collect_exploit_links(
    cve_id: str,
    references: list[dict[str, Any]],
    github_pocs: list[dict[str, Any]],
    exploits: list[dict[str, Any]],
    *,
    metasploit_modules: list[dict[str, Any]] | None = None,
) -> list[dict[str, str]]:
    """
    Aggregate public exploit / PoC links (URLs only).

    Keeps Rapid7 vulnerability advisories, real Exploit-DB entries, GitHub PoC
    repos, and mapped Metasploit modules. Omits VulnCheck XDB and discovery searches.
    """
    out: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(kind: str, name: str, url: str, *, exploit_type: str = "", raw_type: str = "") -> None:
        u = (url or "").strip()
        if not u:
            return
        key = u.lower().rstrip("/")
        if key in seen:
            return
        # Drop VulnCheck XDB and generic discovery/search pages
        if "vulncheck.com/xdb" in key:
            return
        if "exploit-db.com/search" in key:
            return
        if "github.com/search" in key:
            return
        if "rapid7.com/db/?q=" in key and "type=metasploit" in key:
            return
        seen.add(key)
        et = exploit_type or _exploit_type_label(kind, raw_type, u)
        out.append({"kind": kind, "name": name or u, "url": u, "exploit_type": et})

    # Rapid7 vulnerability advisory only (no Metasploit / XDB / discovery searches)
    cve_lower = cve_id.lower()
    add(
        "Rapid7",
        f"Rapid7 vulnerability — {cve_id}",
        f"https://www.rapid7.com/db/vulnerabilities/{cve_lower}/",
        exploit_type="Vulnerability advisory",
    )

    for poc in github_pocs:
        add(
            "GitHub PoC",
            poc.get("full_name") or poc.get("html_url") or "GitHub",
            poc.get("html_url") or "",
            exploit_type="Git Repository PoC",
        )

    for ref in references or []:
        url = (ref.get("url") or "").strip()
        if not url:
            continue
        low = url.lower()
        name = (ref.get("name") or url).strip()
        if "vulncheck.com/xdb" in low:
            continue
        if "rapid7.com/db/modules" in low or "github.com/rapid7/metasploit-framework" in low:
            add("Metasploit", name, url, exploit_type="Metasploit module")
        elif "rapid7.com/db/vulnerabilities" in low:
            add("Rapid7", name, url, exploit_type="Vulnerability advisory")
        elif "exploit-db.com/exploits/" in low or "exploit-db.com/shellcodes/" in low:
            add("Exploit-DB", name, url)
        elif "packetstorm" in low:
            add("Packet Storm", name, url, exploit_type="Public exploit")
        elif "github.com/" in low and ("poc" in low or "exploit" in low or "cve-" in low):
            add("GitHub", name, url, exploit_type="Git Repository PoC")

    for ex in exploits or []:
        edb_id = ex.get("edb_id")
        if edb_id:
            raw = str(ex.get("type") or "")
            kind_label = str(ex.get("kind") or "exploit").lower()
            if kind_label == "paper":
                page_url = f"https://www.exploit-db.com/papers/{edb_id}"
                et = "Paper / research"
            elif kind_label == "shellcode":
                page_url = f"https://www.exploit-db.com/shellcodes/{edb_id}"
                et = _exploit_type_label("Exploit-DB", raw) or "Shellcode"
            else:
                page_url = f"https://www.exploit-db.com/exploits/{edb_id}"
                et = _exploit_type_label("Exploit-DB", raw)
            add(
                "Exploit-DB",
                ex.get("title") or f"EDB-{edb_id}",
                page_url,
                raw_type=raw,
                exploit_type=et,
            )
            app_url = str(ex.get("application_url") or "").strip()
            if app_url:
                add(
                    "Vulnerable app",
                    f"App download - EDB-{edb_id}",
                    app_url,
                    exploit_type="Vulnerable application",
                )
            src_url = str(ex.get("source_url") or "").strip()
            if src_url:
                add(
                    "Article",
                    f"Article / source - EDB-{edb_id}",
                    src_url,
                    exploit_type="Article / advisory",
                )
            shot_url = str(ex.get("screenshot_url") or "").strip()
            if shot_url:
                add(
                    "Screenshot",
                    f"Screenshot - EDB-{edb_id}",
                    shot_url,
                    exploit_type="Screenshot",
                )

    for mod in metasploit_modules or []:
        add(
            "Metasploit",
            mod.get("name") or mod.get("fullname") or "Metasploit module",
            mod.get("detail_url") or "",
            exploit_type="Metasploit module",
        )
    return out


def _merge_all_references(
    *,
    cve_id: str,
    base_refs: list[dict[str, Any]] | None,
    patches: list[dict[str, Any]] | None = None,
    remediation: list[dict[str, Any]] | None = None,
    github_pocs: list[dict[str, Any]] | None = None,
    exploit_links: list[dict[str, Any]] | None = None,
    attack: list[dict[str, Any]] | None = None,
    apt_actors: list[dict[str, Any]] | None = None,
    nuclei_templates: list[dict[str, Any]] | None = None,
    metasploit_modules: list[dict[str, Any]] | None = None,
    nessus_plugins: list[dict[str, Any]] | None = None,
    msrc: dict[str, Any] | None = None,
    nvd: dict[str, Any] | None = None,
    cisa_kev: dict[str, Any] | None = None,
    unlock_resources: list[dict[str, Any]] | None = None,
) -> list[dict[str, str]]:
    """Single deduped References list for the CVE page (all section URLs land here)."""
    out: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(url: str, *, name: str = "", kind: str = "Reference") -> None:
        u = (url or "").strip()
        if not u or not u.startswith(("http://", "https://")):
            return
        key = u.lower().rstrip("/")
        if key in seen or "vulncheck.com/xdb" in key:
            return
        seen.add(key)
        out.append({"url": u, "name": (name or u).strip(), "kind": kind})

    add(f"https://www.cve.org/CVERecord?id={cve_id}", name=f"CVE Record — {cve_id}", kind="CVE")
    add(f"https://nvd.nist.gov/vuln/detail/{cve_id}", name=f"NVD — {cve_id}", kind="NVD")
    if nvd and nvd.get("detail_url"):
        add(str(nvd["detail_url"]), name="NVD detail", kind="NVD")
    for ref in (nvd or {}).get("references") or []:
        if isinstance(ref, dict):
            add(str(ref.get("url") or ""), name=str(ref.get("url") or ""), kind="NVD reference")
    if cisa_kev:
        add(
            str(cisa_kev.get("detail_url") or ""),
            name="CISA KEV catalog",
            kind="CISA KEV",
        )

    for ref in base_refs or []:
        add(str(ref.get("url") or ""), name=str(ref.get("name") or ""), kind="CVE reference")
    for patch in patches or []:
        add(str(patch.get("url") or ""), name=str(patch.get("name") or ""), kind=str(patch.get("kind") or "Patch"))
    for item in remediation or []:
        add(str(item.get("url") or ""), name=str(item.get("name") or ""), kind=str(item.get("kind") or "Remediation"))
    for poc in github_pocs or []:
        add(str(poc.get("html_url") or ""), name=str(poc.get("full_name") or ""), kind="GitHub PoC")
    for link in exploit_links or []:
        add(str(link.get("url") or ""), name=str(link.get("name") or ""), kind=str(link.get("kind") or "Exploit"))
    for tech in attack or []:
        add(str(tech.get("url") or ""), name=f"{tech.get('id') or ''} {tech.get('name') or ''}".strip(), kind="ATT&CK")
    for actor in apt_actors or []:
        add(str(actor.get("url") or ""), name=str(actor.get("name") or ""), kind="APT / threat actor")
    for t in nuclei_templates or []:
        add(str(t.get("detail_url") or ""), name=str(t.get("template_id") or t.get("name") or ""), kind="Nuclei")
    for m in metasploit_modules or []:
        add(str(m.get("detail_url") or ""), name=str(m.get("fullname") or m.get("name") or ""), kind="Metasploit")
    for p in nessus_plugins or []:
        add(str(p.get("detail_url") or ""), name=f"Nessus #{p.get('plugin_id')} {p.get('name') or ''}".strip(), kind="Nessus")
        for link in p.get("see_also") or []:
            add(str(link), name=str(link), kind="Nessus see also")
    if msrc:
        add(str(msrc.get("detail_url") or ""), name=f"MSRC — {cve_id}", kind="MSRC")
        for rem in msrc.get("remediations") or []:
            add(
                str(rem.get("url") or ""),
                name=str(rem.get("kb") or rem.get("url") or ""),
                kind="MSRC KB",
            )
    for r in unlock_resources or []:
        add(str(r.get("url") or ""), name=str(r.get("name") or ""), kind="Resource")

    add(
        f"https://www.rapid7.com/db/vulnerabilities/{cve_id.lower()}/",
        name=f"Rapid7 — {cve_id}",
        kind="Rapid7",
    )
    return out


def _parse_cvss_exploitability(vector: str) -> dict[str, str]:
    """Extract human-readable exploitability factors from a CVSS vector string."""
    raw = (vector or "").strip()
    parts = {}
    for token in raw.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "").replace("CVSS:2.0/", "").split("/"):
        if ":" in token:
            k, v = token.split(":", 1)
            parts[k.upper()] = v.upper()

    av = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}.get(parts.get("AV", ""), parts.get("AV", "—"))
    ac = {"L": "Low", "H": "High", "M": "Medium"}.get(parts.get("AC", ""), parts.get("AC", "—"))
    pr = {"N": "None", "L": "Low", "H": "High"}.get(parts.get("PR", ""), parts.get("PR", "—"))
    ui = {"N": "None", "R": "Required"}.get(parts.get("UI", ""), parts.get("UI", "—"))

    # Rough qualitative label
    label = "Unknown"
    if parts.get("AV") == "N" and parts.get("AC") in {"L", None} and parts.get("UI") in {"N", None}:
        label = "Easily reachable (network, low complexity)"
    elif parts.get("AV") == "N":
        label = "Network reachable"
    elif parts.get("AV") in {"L", "P"}:
        label = "Requires local / physical access"
    elif vector:
        label = "See CVSS vector"

    return {
        "label": label,
        "attack_vector": av,
        "attack_complexity": ac,
        "privileges_required": pr,
        "user_interaction": ui,
    }


def _publicly_disclosed(cve: dict[str, Any], enrich: dict[str, Any]) -> dict[str, Any]:
    state = (cve.get("state") or "").upper()
    published = (cve.get("date_published") or enrich.get("date_public") or "").strip()
    reserved = (enrich.get("date_reserved") or "").strip()
    if state == "REJECTED":
        status = "Rejected (record exists)"
    elif published:
        status = "Yes"
    elif reserved and not published:
        status = "Reserved / not fully public"
    else:
        status = "Unknown"
    return {
        "disclosed": bool(published),
        "status": status,
        "date_public": published[:10] if published else "",
        "date_reserved": reserved[:10] if reserved else "",
        "state": state or "—",
    }


def fetch_github_pocs(cve_id: str, *, references: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """
    Collect GitHub PoC / research repo links for a CVE.

    Sources:
    1) GitHub repos listed in the local CVE references
    2) nomi-sec/PoC-in-GitHub index (cached under downloads/poc_github_cache)

    Returns repo metadata/URLs only — does not download or display PoC code.
    """
    cve_id = (cve_id or "").strip().upper()
    if not _CVE_RE.match(cve_id):
        return []

    collected: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(item: dict[str, Any]) -> None:
        url = (item.get("html_url") or "").rstrip("/")
        if not url:
            return
        key = url.lower()
        if key in seen:
            return
        seen.add(key)
        collected.append(item)

    for item in _github_pocs_from_references(references or []):
        add(item)

    # Local / remote PoC-in-GitHub index
    cache = _poc_cache_path(cve_id)
    payload: Any = None
    if cache.is_file():
        try:
            payload = json.loads(cache.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = None

    if payload is None:
        year = cve_id.split("-")[1]
        from .settings_store import get_url

        url = get_url("poc_in_github_index", config.POC_IN_GITHUB_INDEX_URL).format(
            year=year, cve_id=cve_id
        )
        try:
            # Short timeout so CVE pages stay responsive when offline / slow
            resp = session_get_poc(url)
            if resp is not None and resp.status_code == 200:
                payload = resp.json()
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text(json.dumps(payload), encoding="utf-8")
            elif resp is not None and resp.status_code == 404:
                # Cache empty result so we don't re-hit every page load
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text("[]", encoding="utf-8")
                payload = []
        except Exception as exc:  # noqa: BLE001
            log.debug("PoC-in-GitHub lookup failed for %s: %s", cve_id, exc)
            payload = None

    if isinstance(payload, dict):
        payload = [payload]
    if isinstance(payload, list):
        for row in payload:
            if not isinstance(row, dict):
                continue
            html_url = (row.get("html_url") or "").strip()
            full_name = (row.get("full_name") or "").strip()
            if not html_url and full_name:
                html_url = f"https://github.com/{full_name}"
            if not html_url:
                continue
            # Prefer canonical repo root URL
            norm = _normalize_github_repo(html_url)
            if norm:
                html_url, full_name, _ = norm
            add(
                {
                    "html_url": html_url,
                    "full_name": full_name or row.get("name") or html_url,
                    "description": (row.get("description") or "")[:240],
                    "stargazers_count": row.get("stargazers_count"),
                    "source": "poc-in-github",
                }
            )

    # Stars desc when available
    collected.sort(
        key=lambda x: (
            -(x.get("stargazers_count") or 0),
            (x.get("full_name") or "").lower(),
        )
    )
    return collected[:40]


def session_get_poc(url: str):
    """Lightweight GET for PoC index (separate short timeout)."""
    import requests

    from .httputil import session

    try:
        return session().get(url, timeout=_POC_FETCH_TIMEOUT, allow_redirects=True)
    except requests.RequestException as exc:
        log.debug("PoC GET failed: %s", exc)
        return None


def _edb_zip_path() -> Path | None:
    path = config.DOWNLOAD_DIR / "exploitdb-main.zip"
    return path if path.is_file() else None


def _edb_papers_zip_path() -> Path | None:
    path = config.DOWNLOAD_DIR / "exploitdb-papers-main.zip"
    return path if path.is_file() else None


def _safe_edb_member(rel_path: str) -> str | None:
    """Normalize Exploit-DB relative path; reject traversal / odd prefixes."""
    raw = (rel_path or "").replace("\\", "/").lstrip("/")
    if not raw or ".." in raw.split("/"):
        return None
    allowed_roots = ("exploits/", "shellcodes/", "papers/")
    if not raw.startswith(allowed_roots):
        return None
    return raw


def _read_member_from_zip(zpath: Path, safe: str) -> tuple[bytes, int] | None:
    prefixes = (
        "exploitdb-main/",
        "exploitdb-master/",
        "exploitdb-papers-main/",
        "exploitdb-papers-master/",
        "",
    )
    candidates = [f"{p}{safe}" for p in prefixes]
    with zipfile.ZipFile(zpath, "r") as zf:
        names = set(zf.namelist())
        member = next((c for c in candidates if c in names), None)
        if member is None:
            lower_map = {n.lower(): n for n in names}
            for c in candidates:
                if c.lower() in lower_map:
                    member = lower_map[c.lower()]
                    break
        if member is None:
            return None
        info = zf.getinfo(member)
        return zf.read(member), int(info.file_size)


def read_exploit_source(rel_path: str, *, max_bytes: int = _MAX_SOURCE_BYTES) -> dict[str, Any]:
    """
    Read Exploit-DB source from the local official archive zip(s).

    Returns metadata + text when the file is text-like; never invents code.
    """
    safe = _safe_edb_member(rel_path)
    out: dict[str, Any] = {
        "path": rel_path or "",
        "available": False,
        "truncated": False,
        "binary": False,
        "size": 0,
        "content": "",
        "error": "",
    }
    if not safe:
        out["error"] = "invalid path"
        return out

    ext = Path(safe).suffix.lower()
    if ext in _BINARY_EXTS:
        out["binary"] = True
        out["error"] = "binary file not shown"
        return out

    archives: list[Path] = []
    if safe.startswith("papers/"):
        papers = _edb_papers_zip_path()
        if papers:
            archives.append(papers)
    main = _edb_zip_path()
    if main:
        archives.append(main)
    if not archives:
        out["error"] = "Exploit-DB archive not downloaded yet"
        return out

    raw: bytes | None = None
    size = 0
    try:
        for zpath in archives:
            found = _read_member_from_zip(zpath, safe)
            if found is not None:
                raw, size = found
                break
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        out["error"] = str(exc)
        return out

    if raw is None:
        out["error"] = "file not found in local archive"
        return out

    out["size"] = size

    if b"\x00" in raw[:4096]:
        out["binary"] = True
        out["error"] = "binary file not shown"
        return out

    truncated = False
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
        truncated = True

    text = raw.decode("utf-8", errors="replace")
    out.update(
        {
            "available": True,
            "truncated": truncated,
            "content": text,
            "error": "",
        }
    )
    return out


def get_cve_detail(cve_id: str, *, include_source: bool = True) -> dict[str, Any] | None:
    cve_id = (cve_id or "").strip().upper()
    if not _CVE_RE.match(cve_id):
        return None

    with db_session() as conn:
        row = conn.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,)).fetchone()
        if not row:
            return None
        cve = dict(row)
        products = [
            dict(r)
            for r in conn.execute(
                """
                SELECT vendor, product, version, status
                FROM cve_products WHERE cve_id = ?
                ORDER BY vendor, product, version
                """,
                (cve_id,),
            ).fetchall()
        ]
        cpes = [
            r["cpe"]
            for r in conn.execute(
                "SELECT cpe FROM cve_cpes WHERE cve_id = ? ORDER BY cpe LIMIT 80",
                (cve_id,),
            ).fetchall()
        ]
        exploits = [
            dict(r)
            for r in conn.execute(
                """
                SELECT e.edb_id, e.path, e.title, e.platform, e.type, e.date_pub,
                       e.author, e.codes, e.verified, e.kind, e.tags,
                       e.aliases, e.application_url, e.source_url, e.screenshot_url,
                       e.date_added, e.date_updated
                FROM exploit_cves ec
                JOIN exploits e ON e.edb_id = ec.edb_id
                WHERE ec.cve_id = ?
                ORDER BY e.verified DESC, e.edb_id DESC
                """,
                (cve_id,),
            ).fetchall()
        ]

        def _safe_one(sql: str):
            try:
                row = conn.execute(sql, (cve_id,)).fetchone()
                return dict(row) if row else None
            except Exception:
                return None

        def _safe_many(sql: str) -> list[dict[str, Any]]:
            try:
                return [dict(r) for r in conn.execute(sql, (cve_id,)).fetchall()]
            except Exception:
                return []

        debian = _safe_one("SELECT * FROM debian_cves WHERE cve_id = ?")
        ubuntu = _safe_one("SELECT * FROM ubuntu_cves WHERE cve_id = ?")
        ghsa_rows = _safe_many(
            """
            SELECT ghsa_id, summary, severity, published_at, html_url, packages_json
            FROM ghsa_advisories WHERE cve_id = ?
            ORDER BY published_at DESC LIMIT 20
            """
        )
        osv_rows = _safe_many(
            """
            SELECT v.osv_id, v.summary, v.severity, v.published, v.detail_url, v.packages_json
            FROM osv_cves oc
            JOIN osv_vulns v ON v.osv_id = oc.osv_id
            WHERE oc.cve_id = ?
            ORDER BY v.modified DESC LIMIT 30
            """
        )
        poc_db_rows = _safe_many(
            """
            SELECT html_url, full_name, description, stargazers, language
            FROM poc_github WHERE cve_id = ?
            ORDER BY COALESCE(stargazers,0) DESC LIMIT 40
            """
        )

    # Enrich from local CVE JSON when available
    raw_json = _load_cve_json(cve.get("source_path")) or _find_cve_json_by_id(cve_id)
    enrich = (
        _enrich_from_json(raw_json)
        if raw_json
        else {
            "problem_types": [],
            "references": [],
            "patches": [],
            "remediation": [],
            "credits": [],
            "title": "",
            "date_reserved": "",
            "date_public": "",
            "affected_rows": [],
            "affected_versions": [],
            "fixed_versions": [],
            "cvss": {},
        }
    )

    category = _guess_category(cve.get("description") or "", enrich["problem_types"])
    exploit_status = "Has Exploit-DB" if exploits else "No Exploit-DB"

    # Prefer richer CVSS from local JSON when DB vector/score is thin
    json_cvss = enrich.get("cvss") or {}
    score = cve.get("cvss_score")
    if score is None and json_cvss.get("score") is not None:
        score = json_cvss.get("score")
    vector = (cve.get("cvss_vector") or "") or str(json_cvss.get("vector") or "")
    severity = (cve.get("severity") or "").upper() or str(json_cvss.get("severity") or "").upper()
    if not severity and score is not None:
        if score >= 9:
            severity = "CRITICAL"
        elif score >= 7:
            severity = "HIGH"
        elif score >= 4:
            severity = "MEDIUM"
        elif score > 0:
            severity = "LOW"

    # Prefer structured affected rows from JSON; fall back to SQLite products
    affected_versions = list(enrich.get("affected_versions") or [])
    if not affected_versions and products:
        for p in products:
            if (p.get("product") or "").lower() in {"n/a", "unknown", ""} and (
                p.get("version") or ""
            ).lower() in {"n/a", "unknown", ""}:
                continue
            affected_versions.append(
                {
                    "vendor": p.get("vendor") or "unknown",
                    "product": p.get("product") or "",
                    "package": "",
                    "platform": "",
                    "version": p.get("version") or "",
                    "version_label": p.get("version") or "—",
                    "status": p.get("status") or "",
                    "less_than": "",
                    "less_than_or_equal": "",
                    "greater_than": "",
                    "greater_than_or_equal": "",
                    "fixed_versions": "",
                }
            )

    # Group products by vendor for PatchaPalooza-like sections
    by_vendor: dict[str, list[dict[str, str]]] = defaultdict(list)
    source_rows = enrich.get("affected_rows") or affected_versions
    for p in source_rows:
        vendor = (p.get("vendor") or "unknown").strip() or "unknown"
        product = (p.get("product") or "").strip()
        version_label = p.get("version_label") or p.get("version") or ""
        if product.lower() in {"n/a", "unknown", ""} and version_label.lower() in {
            "n/a",
            "unknown",
            "",
            "—",
        }:
            continue
        by_vendor[vendor].append(
            {
                "product": product,
                "version": version_label,
                "status": p.get("status") or "",
                "package": p.get("package") or "",
                "platform": p.get("platform") or "",
                "fixed_versions": p.get("fixed_versions") or "",
            }
        )

    for edb in exploits:
        edb["cve_ids"] = extract_cve_ids_from_codes(edb.get("codes"))
        kind_label = str(edb.get("kind") or "exploit").lower()
        if kind_label == "paper":
            edb["exploit_type"] = "Paper / research"
        elif kind_label == "shellcode":
            edb["exploit_type"] = _exploit_type_label("Exploit-DB", str(edb.get("type") or "")) or "Shellcode"
        else:
            edb["exploit_type"] = _exploit_type_label("Exploit-DB", str(edb.get("type") or ""))
        # Expose attachment metadata for the CVE page (URLs live in References)
        edb["has_application"] = bool(str(edb.get("application_url") or "").strip())
        edb["has_article"] = bool(str(edb.get("source_url") or "").strip())
        edb["has_screenshot"] = bool(str(edb.get("screenshot_url") or "").strip())
        if include_source:
            src = read_exploit_source(edb.get("path") or "")
            edb["source"] = src
        else:
            edb["source"] = {"available": False, "path": edb.get("path") or ""}

    title = enrich.get("title") or ""
    if not title:
        desc = (cve.get("description") or "").strip()
        title = desc.split(".")[0][:140] if desc else cve_id

    github_pocs = fetch_github_pocs(cve_id, references=enrich.get("references") or [])
    for poc in github_pocs:
        poc["exploit_type"] = "Git Repository PoC"
    # Merge offline PoC-in-GitHub sync rows
    seen_poc = {(p.get("html_url") or "").lower() for p in github_pocs}
    for row in poc_db_rows or []:
        url = (row.get("html_url") or "").strip()
        if not url or url.lower() in seen_poc:
            continue
        seen_poc.add(url.lower())
        github_pocs.append(
            {
                "html_url": url,
                "full_name": row.get("full_name") or "",
                "description": row.get("description") or "",
                "stargazers_count": row.get("stargazers") or 0,
                "language": row.get("language") or "",
                "exploit_type": "Git Repository PoC",
                "source": "poc-in-github",
            }
        )

    # CAPEC via CWE problem types
    cwe_ids: list[str] = []
    for pt in enrich.get("problem_types") or []:
        raw = str(pt.get("cwe_id") or pt.get("description") or "")
        m = re.search(r"CWE-(\d+)", raw, re.I)
        if m:
            cwe_ids.append(f"CWE-{m.group(1)}")
    capec_rows: list[dict[str, Any]] = []
    if cwe_ids:
        with db_session() as conn:
            try:
                placeholders = ",".join("?" * len(cwe_ids))
                capec_rows = [
                    dict(r)
                    for r in conn.execute(
                        f"""
                        SELECT DISTINCT c.capec_id, c.name, c.severity, c.likelihood,
                               c.description, c.detail_url, cc.cwe_id
                        FROM capec_cwes cc
                        JOIN capec c ON c.capec_id = cc.capec_id
                        WHERE cc.cwe_id IN ({placeholders})
                        ORDER BY c.capec_id
                        LIMIT 40
                        """,  # nosec B608
                        cwe_ids,
                    ).fetchall()
                ]
            except Exception:
                capec_rows = []

    from .epss import fetch_epss
    from .ingest.nvd import get_nvd_detail
    from .ingest.cisa_kev import get_cisa_kev
    from .ingest.nuclei import get_nuclei_for_cve
    from .ingest.metasploit import get_metasploit_for_cve
    from .ingest.nessus_plugins import get_nessus_for_cve
    from .ingest.msrc import get_msrc_for_cve
    from .threat_intel import threat_intel_bundle

    epss = fetch_epss(cve_id)
    exploitability = _parse_cvss_exploitability(vector)
    public = _publicly_disclosed(cve, enrich)
    exploit_text_bits = []
    for ex in exploits[:8]:
        src = (ex.get("source") or {}) if isinstance(ex.get("source"), dict) else {}
        if src.get("content"):
            exploit_text_bits.append(str(src.get("content"))[:4000])
        if ex.get("title"):
            exploit_text_bits.append(str(ex.get("title")))
    nvd = get_nvd_detail(cve_id)
    cisa_kev = get_cisa_kev(cve_id)
    nuclei_templates = get_nuclei_for_cve(cve_id)
    metasploit_modules = get_metasploit_for_cve(cve_id)
    nessus_plugins = get_nessus_for_cve(cve_id)
    msrc = get_msrc_for_cve(cve_id)
    from .detection_rules import build_detection_pack

    detection = build_detection_pack(cve_id)
    for m in metasploit_modules[:10]:
        if m.get("description"):
            exploit_text_bits.append(str(m.get("description")))
        if m.get("name"):
            exploit_text_bits.append(str(m.get("name")))
    if cisa_kev:
        exploit_text_bits.append(str(cisa_kev.get("notes") or ""))
        exploit_text_bits.append(str(cisa_kev.get("short_description") or ""))

    intel = threat_intel_bundle(
        cve_id=cve_id,
        category=category,
        description=cve.get("description") or "",
        references=enrich.get("references") or [],
        extra_text="\n".join(exploit_text_bits),
    )

    exploit_links = _collect_exploit_links(
        cve_id,
        enrich.get("references") or [],
        github_pocs,
        exploits,
        metasploit_modules=metasploit_modules,
    )

    status_bits = [exploit_status]
    if cisa_kev:
        status_bits.append("CISA KEV")
    if nuclei_templates:
        status_bits.append(f"Nuclei×{len(nuclei_templates)}")
    if metasploit_modules:
        status_bits.append(f"MSF×{len(metasploit_modules)}")
    if nessus_plugins:
        status_bits.append(f"Nessus×{len(nessus_plugins)}")
    exploit_status = " · ".join(status_bits)
    # Only attach VirusTotal when concrete hashes exist in local text
    vt_links = intel.get("virustotal") or []
    seen_urls = {((x.get("url") or "").lower().rstrip("/")) for x in exploit_links}
    for vt in vt_links:
        u = (vt.get("url") or "").strip()
        key = u.lower().rstrip("/")
        if not u or key in seen_urls:
            continue
        seen_urls.add(key)
        exploit_links.append(
            {
                "kind": vt.get("kind") or "VirusTotal",
                "name": vt.get("name") or u,
                "url": u,
                "exploit_type": vt.get("exploit_type") or "Malware / sample hash",
            }
        )

    merged_refs = _merge_all_references(
        cve_id=cve_id,
        base_refs=enrich.get("references") or [],
        patches=enrich.get("patches") or [],
        remediation=enrich.get("remediation") or [],
        github_pocs=github_pocs,
        exploit_links=exploit_links,
        attack=intel.get("attack") or [],
        apt_actors=(intel.get("apt") or {}).get("actors") or [],
        nuclei_templates=nuclei_templates,
        metasploit_modules=metasploit_modules,
        nessus_plugins=nessus_plugins,
        msrc=msrc,
        nvd=nvd,
        cisa_kev=cisa_kev,
        unlock_resources=(intel.get("unlock") or {}).get("resources") or [],
    )

    # Distinct product names (without version noise)
    product_names: list[str] = []
    seen_names: set[str] = set()
    for p in source_rows:
        name = f"{p.get('vendor') or ''}/{p.get('product') or ''}".strip("/")
        if not name or name.lower() in {"unknown/unknown", "n/a/n/a"}:
            continue
        key = name.lower()
        if key in seen_names:
            continue
        seen_names.add(key)
        product_names.append(name)

    # Primary exploit types present for this CVE (unique, ordered)
    exploit_types: list[str] = []
    for link in exploit_links:
        et = (link.get("exploit_type") or "").strip()
        if et and et not in exploit_types and et != "Discovery search":
            exploit_types.append(et)
    for ex in exploits:
        et = (ex.get("exploit_type") or "").strip()
        if et and et not in exploit_types:
            exploit_types.append(et)

    return {
        "cve_id": cve_id,
        "title": title,
        "state": cve.get("state") or "",
        "description": cve.get("description") or "",
        "date_published": cve.get("date_published") or enrich.get("date_public") or "",
        "date_updated": cve.get("date_updated") or "",
        "date_reserved": enrich.get("date_reserved") or "",
        "cvss_score": score,
        "cvss_vector": vector,
        "cvss_version": json_cvss.get("version") or "",
        "severity": severity,
        "assigner": cve.get("assigner") or "",
        "category": category,
        "problem_types": enrich.get("problem_types") or [],
        "exploit_status": exploit_status,
        "exploit_count": len(exploits),
        "exploit_types": exploit_types,
        "epss": epss,
        "publicly_disclosed": public,
        "exploitability": exploitability,
        "attack": intel.get("attack") or [],
        "apt": intel.get("apt") or {},
        "unlock": intel.get("unlock") or {},
        "virustotal": vt_links,
        "nvd": nvd,
        "cisa_kev": cisa_kev,
        "nuclei_templates": nuclei_templates,
        "metasploit_modules": metasploit_modules,
        "nessus_plugins": nessus_plugins,
        "msrc": msrc,
        "detection": detection,
        "exploit_links": exploit_links,
        "products": products,
        "product_names": product_names,
        "products_by_vendor": [
            {"vendor": v, "products": items, "count": len(items)}
            for v, items in sorted(by_vendor.items(), key=lambda x: (-len(x[1]), x[0].lower()))
        ],
        "product_count": sum(len(items) for items in by_vendor.values()),
        "affected_versions": affected_versions,
        "fixed_versions": enrich.get("fixed_versions") or [],
        "patches": enrich.get("patches") or [],
        "remediation": enrich.get("remediation") or [],
        "github_pocs": github_pocs,
        "capec": capec_rows,
        "debian": debian,
        "ubuntu": ubuntu,
        "ghsa": ghsa_rows,
        "osv": osv_rows,
        "cpes": cpes,
        "references": merged_refs,
        "credits": enrich.get("credits") or [],
        "exploits": exploits,
        "links": {
            "cve_org": f"https://www.cve.org/CVERecord?id={cve_id}",
            "nvd": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        },
    }


def home_brief(limit_critical: int = 8, limit_exploited: int = 8) -> dict[str, Any]:
    """Compact home lists inspired by PatchaPalooza brief overviews."""
    with db_session() as conn:
        critical = [
            dict(r)
            for r in conn.execute(
                """
                SELECT c.cve_id, c.severity, c.cvss_score,
                       substr(c.description, 1, 160) AS description,
                       c.date_published,
                       (SELECT COUNT(*) FROM exploit_cves ec WHERE ec.cve_id = c.cve_id) AS edb_count
                FROM cves c
                WHERE upper(c.severity) = 'CRITICAL'
                   OR (c.cvss_score IS NOT NULL AND c.cvss_score >= 9)
                ORDER BY COALESCE(c.cvss_score, 0) DESC, c.date_published DESC
                LIMIT ?
                """,
                (limit_critical,),
            ).fetchall()
        ]
        with_edb = [
            dict(r)
            for r in conn.execute(
                """
                SELECT c.cve_id, c.severity, c.cvss_score,
                       substr(c.description, 1, 160) AS description,
                       COUNT(ec.edb_id) AS edb_count
                FROM exploit_cves ec
                JOIN cves c ON c.cve_id = ec.cve_id
                GROUP BY c.cve_id
                ORDER BY edb_count DESC, COALESCE(c.cvss_score, 0) DESC
                LIMIT ?
                """,
                (limit_exploited,),
            ).fetchall()
        ]
        mapped = conn.execute("SELECT COUNT(DISTINCT cve_id) AS n FROM exploit_cves").fetchone()["n"]
    return {
        "critical": critical,
        "with_exploits": with_edb,
        "cves_with_edb": int(mapped),
    }


def _diversify_latest(
    rows: list[dict[str, Any]],
    *,
    bucket_key: str,
    limit: int,
    max_per_bucket: int = 2,
    prefer_buckets: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    """
    Pick recent rows while spreading across vendors/platforms.

    Pure date order often floods the home tables with one vendor (e.g. Apache)
    and hides Microsoft / Windows even when they published a day or two earlier.
    """
    if limit <= 0 or not rows:
        return []

    def _norm(value: Any) -> str:
        text = str(value or "").strip().lower()
        return text or "other"

    preferred = {_norm(x) for x in prefer_buckets if str(x or "").strip()}
    selected: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    leftovers: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _row_id(row: dict[str, Any]) -> str:
        if row.get("cve_id"):
            return f"cve:{row['cve_id']}"
        return f"edb:{row.get('edb_id')}"

    for row in rows:
        rid = _row_id(row)
        if rid in seen:
            continue
        key = _norm(row.get(bucket_key))
        if key not in preferred:
            leftovers.append(row)
            continue
        if counts.get(key, 0) >= max_per_bucket:
            leftovers.append(row)
            continue
        selected.append(row)
        seen.add(rid)
        counts[key] = counts.get(key, 0) + 1
        if len(selected) >= limit:
            break

    deferred: list[dict[str, Any]] = []
    for row in leftovers:
        if len(selected) >= limit:
            break
        rid = _row_id(row)
        if rid in seen:
            continue
        key = _norm(row.get(bucket_key))
        if counts.get(key, 0) >= max_per_bucket:
            deferred.append(row)
            continue
        selected.append(row)
        seen.add(rid)
        counts[key] = counts.get(key, 0) + 1

    for row in deferred:
        if len(selected) >= limit:
            break
        rid = _row_id(row)
        if rid in seen:
            continue
        selected.append(row)
        seen.add(rid)

    selected.sort(
        key=lambda r: (
            str(r.get("date_published") or r.get("date_pub") or ""),
            str(r.get("cve_id") or r.get("edb_id") or ""),
        ),
        reverse=True,
    )
    return selected[:limit]


def _enrich_latest_cves(conn: Any, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach products/versions/edb_count in one batch (no per-row correlated SQL)."""
    if not rows:
        return []
    ids = [str(r["cve_id"]) for r in rows if r.get("cve_id")]
    if not ids:
        return rows
    placeholders = in_placeholders(len(ids))
    products: dict[str, list[str]] = defaultdict(list)
    versions: dict[str, list[str]] = defaultdict(list)
    primary_vendor: dict[str, str] = {}
    seen_prod: dict[str, set[str]] = defaultdict(set)
    seen_ver: dict[str, set[str]] = defaultdict(set)

    for r in conn.execute(
        # placeholders are only '?' repeated from len(ids); values are bound.
        "SELECT cve_id, vendor, product, version FROM cve_products "
        f"WHERE cve_id IN ({placeholders})",  # nosec B608
        ids,
    ):
        cid = r["cve_id"]
        vendor = (r["vendor"] or "").strip()
        product = (r["product"] or "").strip()
        if cid not in primary_vendor and vendor:
            primary_vendor[cid] = vendor.lower()
        label = "/".join(p for p in (vendor, product) if p)
        if label and label not in seen_prod[cid] and len(products[cid]) < 4:
            seen_prod[cid].add(label)
            products[cid].append(label)
        ver = (r["version"] or "").strip()
        if ver and ver not in seen_ver[cid] and len(versions[cid]) < 6:
            seen_ver[cid].add(ver)
            versions[cid].append(ver)

    edb_counts = {
        r["cve_id"]: int(r["n"])
        for r in conn.execute(
            "SELECT cve_id, COUNT(*) AS n FROM exploit_cves "
            f"WHERE cve_id IN ({placeholders}) GROUP BY cve_id",  # nosec B608
            ids,
        )
    }

    out: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        cid = item.get("cve_id")
        item["primary_vendor"] = primary_vendor.get(cid, "")
        item["products"] = ", ".join(products.get(cid, []))
        item["versions"] = ", ".join(versions.get(cid, []))
        item["edb_count"] = edb_counts.get(cid, 0)
        out.append(item)
    return out


def _enrich_latest_exploits(conn: Any, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not rows:
        return []
    ids = [int(r["edb_id"]) for r in rows if r.get("edb_id") is not None]
    if not ids:
        return rows
    placeholders = in_placeholders(len(ids))
    cves_by_edb: dict[int, list[str]] = defaultdict(list)
    for r in conn.execute(
        "SELECT edb_id, cve_id FROM exploit_cves "
        f"WHERE edb_id IN ({placeholders}) ORDER BY cve_id",  # nosec B608
        ids,
    ):
        bucket = cves_by_edb[int(r["edb_id"])]
        if len(bucket) < 4:
            bucket.append(r["cve_id"])

    out: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        edb_id = int(item["edb_id"])
        item["primary_platform"] = str(item.get("platform") or "").strip().lower()
        item["cves"] = ", ".join(cves_by_edb.get(edb_id, []))
        out.append(item)
    return out


_LATEST_CACHE: dict[str, Any] = {"ts": 0.0, "limit": 0, "payload": None}
_LATEST_CACHE_TTL_SEC = 60.0


def invalidate_latest_releases_cache() -> None:
    _LATEST_CACHE["payload"] = None
    _LATEST_CACHE["ts"] = 0.0


def latest_releases(limit: int = 10) -> dict[str, Any]:
    """Latest published CVEs (with vendor/product/version) and Exploit-DB entries."""
    limit = max(1, min(int(limit or 10), 50))
    now = time.monotonic()
    cached = _LATEST_CACHE.get("payload")
    if (
        cached is not None
        and int(_LATEST_CACHE.get("limit") or 0) == limit
        and (now - float(_LATEST_CACHE.get("ts") or 0.0)) < _LATEST_CACHE_TTL_SEC
    ):
        return cached

    # Keep candidate sets small — correlated subqueries per row were multi-second on large DBs.
    recent_limit = min(48, max(limit * 4, 24))
    prefer_limit = max(6, min(limit, 10))

    with db_session() as conn:
        recent_cves = [
            dict(r)
            for r in conn.execute(
                """
                SELECT cve_id, severity, cvss_score, date_published,
                       substr(description, 1, 120) AS description
                FROM cves
                WHERE date_published IS NOT NULL AND trim(date_published) != ''
                ORDER BY date_published DESC, cve_id DESC
                LIMIT ?
                """,
                (recent_limit,),
            ).fetchall()
        ]

        # Prefer MSRC-linked Microsoft CVEs (indexed) over scanning all cve_products.
        ms_cves = [
            dict(r)
            for r in conn.execute(
                """
                SELECT DISTINCT c.cve_id, c.severity, c.cvss_score, c.date_published,
                       substr(c.description, 1, 120) AS description
                FROM msrc_cves mc
                JOIN cves c ON c.cve_id = mc.cve_id
                WHERE c.date_published IS NOT NULL AND trim(c.date_published) != ''
                ORDER BY c.date_published DESC, c.cve_id DESC
                LIMIT ?
                """,
                (prefer_limit,),
            ).fetchall()
        ]
        if not ms_cves:
            ms_cves = [
                dict(r)
                for r in conn.execute(
                    """
                    SELECT c.cve_id, c.severity, c.cvss_score, c.date_published,
                           substr(c.description, 1, 120) AS description
                    FROM cves c
                    WHERE c.date_published IS NOT NULL AND trim(c.date_published) != ''
                      AND EXISTS (
                        SELECT 1 FROM cve_products cp
                        WHERE cp.cve_id = c.cve_id
                          AND cp.vendor = 'Microsoft' COLLATE NOCASE
                      )
                    ORDER BY c.date_published DESC, c.cve_id DESC
                    LIMIT ?
                    """,
                    (prefer_limit,),
                ).fetchall()
            ]

        cve_by_id: dict[str, dict[str, Any]] = {}
        for row in ms_cves + recent_cves:
            cid = row.get("cve_id")
            if cid and cid not in cve_by_id:
                cve_by_id[cid] = row
        cve_rows = _enrich_latest_cves(conn, list(cve_by_id.values()))

        recent_ex = [
            dict(r)
            for r in conn.execute(
                """
                SELECT edb_id, title, date_pub, platform, type, verified
                FROM exploits
                WHERE date_pub IS NOT NULL AND trim(date_pub) != ''
                ORDER BY date_pub DESC, edb_id DESC
                LIMIT ?
                """,
                (recent_limit,),
            ).fetchall()
        ]
        win_ex = [
            dict(r)
            for r in conn.execute(
                """
                SELECT edb_id, title, date_pub, platform, type, verified
                FROM exploits
                WHERE date_pub IS NOT NULL AND trim(date_pub) != ''
                  AND (
                    platform = 'windows' COLLATE NOCASE
                    OR title LIKE '%Microsoft%'
                  )
                ORDER BY date_pub DESC, edb_id DESC
                LIMIT ?
                """,
                (prefer_limit,),
            ).fetchall()
        ]
        ex_by_id: dict[int, dict[str, Any]] = {}
        for row in win_ex + recent_ex:
            edb_id = int(row["edb_id"])
            if edb_id not in ex_by_id:
                ex_by_id[edb_id] = row
        exploit_rows = _enrich_latest_exploits(conn, list(ex_by_id.values()))

    payload = {
        "cves": _diversify_latest(
            cve_rows,
            bucket_key="primary_vendor",
            limit=limit,
            max_per_bucket=2,
            prefer_buckets=("microsoft",),
        ),
        "exploits": _diversify_latest(
            exploit_rows,
            bucket_key="primary_platform",
            limit=limit,
            max_per_bucket=2,
            prefer_buckets=("windows",),
        ),
    }
    _LATEST_CACHE["ts"] = now
    _LATEST_CACHE["limit"] = limit
    _LATEST_CACHE["payload"] = payload
    return payload
