"""Threat intel enrichment: ATT&CK, APT mentions, VirusTotal, public key hints."""

from __future__ import annotations

import re
from typing import Any

# Heuristic category → ATT&CK technique mappings (defensive correlation aid).
_ATTACK_BY_CATEGORY: dict[str, list[dict[str, str]]] = {
    "sql injection": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "url": "https://attack.mitre.org/techniques/T1190/"},
        {"id": "T1505", "name": "Server Software Component", "url": "https://attack.mitre.org/techniques/T1505/"},
    ],
    "command injection": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "url": "https://attack.mitre.org/techniques/T1190/"},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "url": "https://attack.mitre.org/techniques/T1059/"},
    ],
    "code injection": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "url": "https://attack.mitre.org/techniques/T1059/"},
        {"id": "T1203", "name": "Exploitation for Client Execution", "url": "https://attack.mitre.org/techniques/T1203/"},
    ],
    "remote code execution": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "url": "https://attack.mitre.org/techniques/T1190/"},
        {"id": "T1203", "name": "Exploitation for Client Execution", "url": "https://attack.mitre.org/techniques/T1203/"},
        {"id": "T1210", "name": "Exploitation of Remote Services", "url": "https://attack.mitre.org/techniques/T1210/"},
    ],
    "local privilege escalation": [
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "url": "https://attack.mitre.org/techniques/T1068/"},
        {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "url": "https://attack.mitre.org/techniques/T1548/"},
    ],
    "authentication bypass": [
        {"id": "T1078", "name": "Valid Accounts", "url": "https://attack.mitre.org/techniques/T1078/"},
        {"id": "T1550", "name": "Use Alternate Authentication Material", "url": "https://attack.mitre.org/techniques/T1550/"},
    ],
    "authorization bypass": [
        {"id": "T1078", "name": "Valid Accounts", "url": "https://attack.mitre.org/techniques/T1078/"},
        {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "url": "https://attack.mitre.org/techniques/T1548/"},
    ],
    "cross-site scripting": [
        {"id": "T1189", "name": "Drive-by Compromise", "url": "https://attack.mitre.org/techniques/T1189/"},
        {"id": "T1059.007", "name": "JavaScript", "url": "https://attack.mitre.org/techniques/T1059/007/"},
    ],
    "cross-site request forgery": [
        {"id": "T1189", "name": "Drive-by Compromise", "url": "https://attack.mitre.org/techniques/T1189/"},
    ],
    "server-side request forgery": [
        {"id": "T1090", "name": "Proxy", "url": "https://attack.mitre.org/techniques/T1090/"},
        {"id": "T1552", "name": "Unsecured Credentials", "url": "https://attack.mitre.org/techniques/T1552/"},
    ],
    "path traversal": [
        {"id": "T1083", "name": "File and Directory Discovery", "url": "https://attack.mitre.org/techniques/T1083/"},
        {"id": "T1005", "name": "Data from Local System", "url": "https://attack.mitre.org/techniques/T1005/"},
    ],
    "deserialization": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "url": "https://attack.mitre.org/techniques/T1190/"},
        {"id": "T1203", "name": "Exploitation for Client Execution", "url": "https://attack.mitre.org/techniques/T1203/"},
    ],
    "buffer overflow": [
        {"id": "T1203", "name": "Exploitation for Client Execution", "url": "https://attack.mitre.org/techniques/T1203/"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "url": "https://attack.mitre.org/techniques/T1068/"},
    ],
    "memory corruption": [
        {"id": "T1203", "name": "Exploitation for Client Execution", "url": "https://attack.mitre.org/techniques/T1203/"},
    ],
    "use after free": [
        {"id": "T1203", "name": "Exploitation for Client Execution", "url": "https://attack.mitre.org/techniques/T1203/"},
    ],
    "denial of service": [
        {"id": "T1499", "name": "Endpoint Denial of Service", "url": "https://attack.mitre.org/techniques/T1499/"},
        {"id": "T1498", "name": "Network Denial of Service", "url": "https://attack.mitre.org/techniques/T1498/"},
    ],
    "information disclosure": [
        {"id": "T1005", "name": "Data from Local System", "url": "https://attack.mitre.org/techniques/T1005/"},
        {"id": "T1552", "name": "Unsecured Credentials", "url": "https://attack.mitre.org/techniques/T1552/"},
    ],
    "cryptographic weakness": [
        {"id": "T1552", "name": "Unsecured Credentials", "url": "https://attack.mitre.org/techniques/T1552/"},
        {"id": "T1600", "name": "Weaken Encryption", "url": "https://attack.mitre.org/techniques/T1600/"},
    ],
    "supply chain": [
        {"id": "T1195", "name": "Supply Chain Compromise", "url": "https://attack.mitre.org/techniques/T1195/"},
    ],
    "man-in-the-middle": [
        {"id": "T1557", "name": "Adversary-in-the-Middle", "url": "https://attack.mitre.org/techniques/T1557/"},
    ],
    "file upload abuse": [
        {"id": "T1505.003", "name": "Web Shell", "url": "https://attack.mitre.org/techniques/T1505/003/"},
        {"id": "T1105", "name": "Ingress Tool Transfer", "url": "https://attack.mitre.org/techniques/T1105/"},
    ],
}

_DEFAULT_ATTACK = [
    {"id": "T1190", "name": "Exploit Public-Facing Application", "url": "https://attack.mitre.org/techniques/T1190/"},
    {"id": "T1210", "name": "Exploitation of Remote Services", "url": "https://attack.mitre.org/techniques/T1210/"},
]

# Well-known APT / actor name patterns (match in text; do not invent attribution).
_APT_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\bAPT\s*[- ]?\s*(\d+)\b", re.I), "APT{0}", "https://attack.mitre.org/groups/"),
    (re.compile(r"\b(Lazarus|Lazarus Group)\b", re.I), "Lazarus Group", "https://attack.mitre.org/groups/G0032/"),
    (re.compile(r"\b(Sandworm|Sandworm Team)\b", re.I), "Sandworm Team", "https://attack.mitre.org/groups/G0034/"),
    (re.compile(r"\b(FIN\d+)\b", re.I), "{0}", "https://attack.mitre.org/groups/"),
    (re.compile(r"\b(Cozy Bear|APT29|Midnight Blizzard)\b", re.I), "APT29 / Midnight Blizzard", "https://attack.mitre.org/groups/G0016/"),
    (re.compile(r"\b(Fancy Bear|APT28|Forest Blizzard)\b", re.I), "APT28 / Forest Blizzard", "https://attack.mitre.org/groups/G0007/"),
    (re.compile(r"\b(Equation Group)\b", re.I), "Equation Group", "https://attack.mitre.org/groups/G0020/"),
    (re.compile(r"\b(Turla)\b", re.I), "Turla", "https://attack.mitre.org/groups/G0010/"),
    (re.compile(r"\b(Kimsuky)\b", re.I), "Kimsuky", "https://attack.mitre.org/groups/G0094/"),
    (re.compile(r"\b(Mustang Panda)\b", re.I), "Mustang Panda", "https://attack.mitre.org/groups/G0129/"),
    (re.compile(r"\b(Volt Typhoon)\b", re.I), "Volt Typhoon", "https://attack.mitre.org/groups/G1017/"),
    (re.compile(r"\b(Hafnium)\b", re.I), "HAFNIUM", "https://attack.mitre.org/groups/G0125/"),
    (re.compile(r"\b(OilRig|APT34)\b", re.I), "OilRig / APT34", "https://attack.mitre.org/groups/G0049/"),
    (re.compile(r"\b(Emotet)\b", re.I), "Emotet (malware)", "https://attack.mitre.org/software/S0367/"),
    (re.compile(r"\b(LockBit)\b", re.I), "LockBit (ransomware)", "https://attack.mitre.org/software/S0446/"),
    (re.compile(r"\b(Conti)\b", re.I), "Conti (ransomware)", "https://attack.mitre.org/software/S0575/"),
]

_HASH_RE = re.compile(r"\b([A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b")
_DEFAULT_CREDS_RE = re.compile(
    r"(?i)(?:default|hardcoded|built[- ]in|static)\s+(?:password|passwd|credential|username|user|key|secret|token)\s*[:=]?\s*['\"]?([^\s'\",;]{2,64})"
)
_MASTER_KEY_RE = re.compile(
    r"(?i)(?:master\s*key|decryption\s*key|private\s*key|api[_ ]?key|secret[_ ]?key)\s*[:=]?\s*['\"]?([A-Za-z0-9+/=_\-]{8,128})"
)


def attack_techniques(category: str) -> list[dict[str, str]]:
    cat = (category or "").lower()
    for key, techs in _ATTACK_BY_CATEGORY.items():
        if key in cat:
            return list(techs)
    return list(_DEFAULT_ATTACK)


# Curated CVE → APT / threat groups publicly reported to use the exploit
# (defensive correlation only — verify with primary CTI).
_CVE_APT_USAGE: dict[str, list[dict[str, str]]] = {
    "CVE-2017-0144": [
        {"name": "Lazarus Group", "url": "https://attack.mitre.org/groups/G0032/", "source": "known to use EternalBlue / MS17-010"},
        {"name": "Equation Group", "url": "https://attack.mitre.org/groups/G0020/", "source": "origin / tooling association (EternalBlue)"},
    ],
    "CVE-2017-0143": [
        {"name": "Lazarus Group", "url": "https://attack.mitre.org/groups/G0032/", "source": "known to use EternalBlue family"},
    ],
    "CVE-2021-44228": [
        {"name": "Multiple ransomware / APT campaigns", "url": "https://attack.mitre.org/groups/", "source": "Log4Shell widely exploited in the wild"},
    ],
    "CVE-2021-26855": [
        {"name": "HAFNIUM", "url": "https://attack.mitre.org/groups/G0125/", "source": "ProxyLogon campaign"},
    ],
    "CVE-2021-27065": [
        {"name": "HAFNIUM", "url": "https://attack.mitre.org/groups/G0125/", "source": "ProxyLogon campaign"},
    ],
    "CVE-2021-34527": [
        {"name": "Multiple threat actors", "url": "https://attack.mitre.org/groups/", "source": "PrintNightmare exploited in the wild"},
    ],
    "CVE-2020-1472": [
        {"name": "Multiple threat actors", "url": "https://attack.mitre.org/groups/", "source": "Zerologon exploited in the wild"},
    ],
    "CVE-2019-0708": [
        {"name": "Multiple threat actors", "url": "https://attack.mitre.org/groups/", "source": "BlueKeep exploited / weaponized"},
    ],
    "CVE-2023-34362": [
        {"name": "Clop (ransomware)", "url": "https://attack.mitre.org/software/S0611/", "source": "MOVEit Transfer mass exploitation"},
    ],
    "CVE-2021-34473": [
        {"name": "HAFNIUM", "url": "https://attack.mitre.org/groups/G0125/", "source": "ProxyShell campaign"},
    ],
}


def extract_apt_mentions(
    *,
    description: str,
    references: list[dict[str, Any]] | None = None,
    cve_id: str = "",
    extra_text: str = "",
) -> dict[str, Any]:
    """
    APT / threat groups associated with this CVE or named in local text / exploit sources.
    """
    blobs = [description or "", extra_text or ""]
    for ref in references or []:
        blobs.append(str(ref.get("name") or ""))
        blobs.append(str(ref.get("url") or ""))
    text = "\n".join(blobs)

    found: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(name: str, url: str, source: str) -> None:
        key = name.lower()
        if not name or key in seen:
            return
        seen.add(key)
        found.append({"name": name, "source": source, "url": url})

    cid = (cve_id or "").strip().upper()
    for item in _CVE_APT_USAGE.get(cid, []):
        add(item["name"], item["url"], item.get("source") or "known exploit usage")

    for pat, label_fmt, url in _APT_PATTERNS:
        for m in pat.finditer(text):
            try:
                label = label_fmt.format(*m.groups()) if m.groups() else label_fmt
            except (IndexError, KeyError):
                label = m.group(0)
            link = url
            if url.rstrip("/").endswith("/groups") and m.groups():
                link = f"https://attack.mitre.org/groups/?search={m.group(0)}"
            add(label, link, "mentioned in local CVE / exploit text")

    return {
        "actors": found,
        "has_attribution": bool(found),
        "note": (
            "APT / threat groups listed when publicly associated with this CVE or named in "
            "local advisory / exploit text. Absence does not mean unused by threat actors — "
            "verify with primary CTI."
            if not found
            else "Groups known to use this exploit or named in local text — verify with primary CTI."
        ),
        "searches": [],
    }


def virustotal_links(cve_id: str, description: str = "", references: list[dict[str, Any]] | None = None) -> list[dict[str, str]]:
    """
    VirusTotal links only when concrete file hashes appear in local advisory text.

    Generic CVE search stubs are omitted — if nothing is on VT from our data, show nothing.
    """
    links: list[dict[str, str]] = []
    blobs = [description or ""]
    for ref in references or []:
        blobs.append(str(ref.get("url") or ""))
        blobs.append(str(ref.get("name") or ""))
    text = "\n".join(blobs)
    seen: set[str] = set()
    for m in _HASH_RE.finditer(text):
        h = m.group(1).lower()
        if h in seen:
            continue
        # Skip very short / likely non-hash tokens that match 32-hex by chance in words
        if len(h) not in {32, 40, 64}:
            continue
        seen.add(h)
        links.append(
            {
                "kind": "VirusTotal",
                "name": f"VT file — {h[:16]}…",
                "url": f"https://www.virustotal.com/gui/file/{h}",
                "exploit_type": "Malware / sample hash",
            }
        )
        if len(links) >= 6:
            break
    return links


def public_unlock_material(description: str, references: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """
    Surface publicly disclosed default credentials / keys only when present in advisory text.

    Does not invent keys. Ransomware decryptors: point to No More Ransom / CISA — never generate keys.
    """
    blobs = [description or ""]
    for ref in references or []:
        blobs.append(str(ref.get("name") or ""))
    text = "\n".join(blobs)

    findings: list[dict[str, str]] = []
    for m in _DEFAULT_CREDS_RE.finditer(text):
        val = m.group(1).strip().rstrip(".,;)")
        if len(val) < 2:
            continue
        findings.append(
            {
                "kind": "Default / hardcoded credential (from advisory text)",
                "value": val[:80],
                "context": m.group(0)[:120],
            }
        )
    for m in _MASTER_KEY_RE.finditer(text):
        val = m.group(1).strip().rstrip(".,;)")
        findings.append(
            {
                "kind": "Key material mentioned in advisory text",
                "value": val[:80],
                "context": m.group(0)[:120],
            }
        )

    # Deduplicate
    seen: set[str] = set()
    uniq: list[dict[str, str]] = []
    for f in findings:
        key = f"{f['kind']}|{f['value']}".lower()
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)

    return {
        "available": bool(uniq),
        "entries": uniq[:10],
        "note": (
            "Only values explicitly present in the local CVE/advisory text are shown. "
            "No keys are generated. For ransomware decryptors, use official programs such as "
            "No More Ransom — never pay or trust unofficial unlockers."
        ),
        "resources": [
            {
                "name": "No More Ransom — decryption tools",
                "url": "https://www.nomoreransom.org/",
            },
            {
                "name": "CISA Stop Ransomware",
                "url": "https://www.cisa.gov/stopransomware",
            },
        ],
    }


def threat_intel_bundle(
    *,
    cve_id: str,
    category: str,
    description: str,
    references: list[dict[str, Any]] | None = None,
    extra_text: str = "",
) -> dict[str, Any]:
    return {
        "attack": attack_techniques(category),
        "apt": extract_apt_mentions(
            description=description,
            references=references,
            cve_id=cve_id,
            extra_text=extra_text,
        ),
        "virustotal": virustotal_links(cve_id, description, references),
        "unlock": public_unlock_material(description, references),
    }
