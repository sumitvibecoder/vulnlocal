"""Request / URL hardening helpers for the local Manage/Settings surface."""

from __future__ import annotations

from urllib.parse import urlparse

from flask import Request, jsonify


_ALLOWED_URL_SCHEMES = frozenset({"http", "https"})


def sanitize_feed_url(url: str, *, field: str = "url") -> str:
    """Allow only http(s) absolute URLs for sync feed settings (blocks file:// etc.)."""
    raw = (url or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_URL_SCHEMES:
        raise ValueError(f"{field}: only http/https URLs are allowed")
    if not parsed.netloc:
        raise ValueError(f"{field}: URL must include a host")
    # Reject obvious credentials-in-URL surprises for non-proxy fields
    if parsed.username or parsed.password:
        raise ValueError(f"{field}: embed credentials in Settings proxy, not feed URLs")
    return raw


def sanitize_settings_urls(urls: dict) -> dict:
    """Validate every non-empty URL value in the settings urls map."""
    out: dict = {}
    path_keys = {"nessus_plugins_path", "osv_ecosystems"}  # local path / csv list, not URLs
    multi_url_keys = {"ubuntu_uct_zips"}  # comma-separated http(s) URLs
    for key, val in (urls or {}).items():
        s = "" if val is None else str(val).strip()
        if key in path_keys or not s:
            out[key] = s
            continue
        if key in multi_url_keys:
            parts = [p.strip() for p in s.split(",") if p.strip()]
            out[key] = ",".join(sanitize_feed_url(p, field=key) for p in parts)
            continue
        # Templates like https://…/{ecosystem}/all.zip are fine
        out[key] = sanitize_feed_url(s, field=key)
    return out


def reject_cross_origin_mutation(request: Request):
    """
    Block cross-site POSTs/DELETEs to Manage APIs (localhost CSRF).

    Same-origin browser fetch sends Origin matching Host. Cross-site
    pages send a foreign Origin and are rejected. CLI tools without
    Origin/Referer are still allowed for local automation.
    """
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return None
    host = _norm_host(request.host or "")
    if not host:
        return None

    origin = (request.headers.get("Origin") or "").strip()
    if origin:
        netloc = _norm_host(urlparse(origin).netloc or "")
        if netloc and netloc != host:
            return jsonify({"error": "cross-origin request blocked"}), 403
        return None

    referer = (request.headers.get("Referer") or "").strip()
    if referer:
        netloc = _norm_host(urlparse(referer).netloc or "")
        if netloc and netloc != host:
            return jsonify({"error": "cross-origin request blocked"}), 403
    return None


def _norm_host(value: str) -> str:
    """Normalize Host / Origin netloc for Windows + Linux (case, IPv6 brackets)."""
    h = (value or "").strip().lower()
    if h.startswith("[") and "]" in h:
        # [::<something>]:port → keep brackets form comparable
        return h
    return h
