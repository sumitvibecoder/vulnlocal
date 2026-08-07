"""NVD-style CPE version range comparison (Vulners-like)."""

from __future__ import annotations

import re
from typing import Any

_WILDCARD = frozenset({"", "*", "-", "n/a", "na", "any", "unspecified", "unknown"})
_PRE_RE = re.compile(
    r"^(?P<head>.*?)(?P<tag>a|b|alpha|beta|rc|preview|pre|dev)(?P<num>\d*)$",
    re.IGNORECASE,
)
_PRE_UPDATE_RE = re.compile(
    r"^(alpha|beta|rc|preview|pre|dev|snapshot)([.\-_]?\d+)?$",
    re.IGNORECASE,
)


def norm_ver(ver: str) -> str:
    v = (ver or "").strip().lower()
    if len(v) > 1 and v[0] == "v" and v[1].isdigit():
        v = v[1:]
    return v


def ver_key(ver: str) -> tuple[Any, ...]:
    """Sortable version key for NVD python/cpe ranges."""
    v = norm_ver(ver)
    if not v or v in _WILDCARD:
        return ()
    v = v.replace("_", ".").replace("-", ".")
    parts = [p for p in v.split(".") if p != ""]
    key: list[Any] = []
    for part in parts:
        m = _PRE_RE.match(part)
        if m and m.group("head") == "":
            tag = m.group("tag").lower()
            rank = {
                "a": 1,
                "alpha": 1,
                "b": 2,
                "beta": 2,
                "pre": 3,
                "preview": 3,
                "rc": 4,
                "dev": 0,
            }.get(tag, 5)
            num = int(m.group("num") or 0)
            key.append((-1, rank, num))
            continue
        if m and m.group("head"):
            head = m.group("head")
            if head.isdigit():
                key.append((0, int(head)))
            else:
                key.append((1, head))
            tag = m.group("tag").lower()
            rank = {
                "a": 1,
                "alpha": 1,
                "b": 2,
                "beta": 2,
                "pre": 3,
                "preview": 3,
                "rc": 4,
                "dev": 0,
            }.get(tag, 5)
            num = int(m.group("num") or 0)
            key.append((-1, rank, num))
            continue
        if part.isdigit():
            key.append((0, int(part)))
        else:
            key.append((1, part))
    return tuple(key)


def version_matches(detected: str, dbver: str) -> bool:
    """Concrete version alignment (no bare '*' / '-')."""
    d = norm_ver(detected)
    b = norm_ver(dbver)
    if not d or b in _WILDCARD:
        return False
    if d == b:
        return True

    def boundary_prefix(longer: str, shorter: str) -> bool:
        if not longer.startswith(shorter):
            return False
        if len(longer) == len(shorter):
            return True
        nxt = longer[len(shorter)]
        return not nxt.isdigit()

    # Require at least major.minor worth of digits on both sides when using prefix.
    # Avoid treating "3" as matching "3.14.0".
    if "." not in b and b.isdigit() and len(b) <= 2:
        return False
    return boundary_prefix(d, b) or boundary_prefix(b, d)


def cpe_update_matches_detected(detected: str, update: str) -> bool:
    """Reject pre-release CPE updates (e.g. 3.14.0:alpha1) for GA detections."""
    u = norm_ver(update)
    if u in _WILDCARD:
        return True
    d = norm_ver(detected)
    if u and u in d:
        return True
    if _PRE_UPDATE_RE.match(u):
        return False
    return True


def has_range_bounds(
    *,
    ver_start_incl: str = "",
    ver_start_excl: str = "",
    ver_end_incl: str = "",
    ver_end_excl: str = "",
) -> bool:
    return any(
        norm_ver(x) and norm_ver(x) not in _WILDCARD
        for x in (ver_start_incl, ver_start_excl, ver_end_incl, ver_end_excl)
    )


def version_in_nvd_range(
    detected: str,
    *,
    ver_start_incl: str = "",
    ver_start_excl: str = "",
    ver_end_incl: str = "",
    ver_end_excl: str = "",
) -> bool:
    """Return True if detected version falls inside NVD cpeMatch range fields."""
    d = ver_key(detected)
    if not d:
        return False

    si = norm_ver(ver_start_incl)
    sx = norm_ver(ver_start_excl)
    ei = norm_ver(ver_end_incl)
    ex = norm_ver(ver_end_excl)

    if si and si not in _WILDCARD and d < ver_key(si):
        return False
    if sx and sx not in _WILDCARD and d <= ver_key(sx):
        return False
    if ei and ei not in _WILDCARD and d > ver_key(ei):
        return False
    if ex and ex not in _WILDCARD and d >= ver_key(ex):
        return False
    return True


def match_applies_to_version(
    detected: str,
    *,
    cpe_version: str = "",
    cpe_update: str = "",
    ver_start_incl: str = "",
    ver_start_excl: str = "",
    ver_end_incl: str = "",
    ver_end_excl: str = "",
    allow_bare_wildcard: bool = False,
) -> tuple[bool, str]:
    """
    Decide if an NVD cpeMatch applies to a concrete detected version.

    Priority (Vulners-like):
      1. If range bounds exist → evaluate them.
      2. Else if criteria has a concrete version → exact/prefix + GA update.
      3. Else bare * → reject unless allow_bare_wildcard.
    """
    d = norm_ver(detected)
    if not d:
        return False, ""

    ranged = has_range_bounds(
        ver_start_incl=ver_start_incl,
        ver_start_excl=ver_start_excl,
        ver_end_incl=ver_end_incl,
        ver_end_excl=ver_end_excl,
    )
    cver = norm_ver(cpe_version)

    if ranged:
        if not version_in_nvd_range(
            d,
            ver_start_incl=ver_start_incl,
            ver_start_excl=ver_start_excl,
            ver_end_incl=ver_end_incl,
            ver_end_excl=ver_end_excl,
        ):
            return False, ""
        if cver and cver not in _WILDCARD and not version_matches(d, cver):
            return False, ""
        if not cpe_update_matches_detected(d, cpe_update):
            return False, ""
        label = cver if cver and cver not in _WILDCARD else d
        return True, label

    if cver and cver not in _WILDCARD:
        if not version_matches(d, cver):
            return False, ""
        if not cpe_update_matches_detected(d, cpe_update):
            return False, ""
        return True, cver

    if allow_bare_wildcard and cver in _WILDCARD:
        return True, "*"
    return False, ""
