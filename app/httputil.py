"""Polite bulk-download helpers for official archives/CDNs (no HTML crawling)."""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path

import requests

from . import config
from .progress import check_cancelled, set_progress

log = logging.getLogger("vulnlocal.http")

_SESSION: requests.Session | None = None


def reset_session() -> None:
    global _SESSION
    _SESSION = None


def session() -> requests.Session:
    global _SESSION
    if _SESSION is None:
        s = requests.Session()
        s.headers.update(
            {
                "User-Agent": config.HTTP_USER_AGENT,
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                # Makes intent explicit to operators reviewing logs: bulk mirror, not a crawler
                "X-Purpose": "local-offline-mirror",
            }
        )
        try:
            from .settings_store import proxy_dict

            proxies = proxy_dict()
            if proxies:
                s.proxies.update(proxies)
                log.info("HTTP session using proxy %s", next(iter(proxies.values())).split("@")[-1])
        except Exception as exc:
            log.warning("Proxy config not applied: %s", exc)
        _SESSION = s
    return _SESSION


def http_get(
    url: str,
    *,
    stream: bool = False,
    etag: str | None = None,
    extra_headers: dict | None = None,
) -> requests.Response:
    headers = {}
    if etag:
        headers["If-None-Match"] = etag
    if extra_headers:
        headers.update(extra_headers)
    # Prefer archive/CDN hosts; never used against HTML search pages.
    resp = session().get(
        url,
        headers=headers or None,
        timeout=config.HTTP_TIMEOUT,
        stream=stream,
        allow_redirects=True,
    )
    return resp


def download_file(
    url: str,
    dest: Path,
    *,
    etag_path: Path | None = None,
    label: str = "",
) -> dict:
    """
    Download a single bulk file with conditional GET (ETag / Last-Modified)
    and large chunks.

    Returns dict with keys: path, bytes, skipped (bool), etag, url
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    etag = None
    last_mod = None
    lm_path = etag_path.with_suffix(etag_path.suffix + ".lastmod") if etag_path else None
    if etag_path and etag_path.is_file() and dest.is_file():
        etag = etag_path.read_text(encoding="utf-8").strip() or None
    if lm_path and lm_path.is_file() and dest.is_file():
        last_mod = lm_path.read_text(encoding="utf-8").strip() or None

    started = time.monotonic()
    headers: dict[str, str] = {}
    if etag:
        headers["If-None-Match"] = etag
    if last_mod:
        headers["If-Modified-Since"] = last_mod
    resp = session().get(
        url,
        headers=headers or None,
        timeout=config.HTTP_TIMEOUT,
        stream=True,
        allow_redirects=True,
    )
    if resp.status_code == 304 and dest.is_file():
        log.info("Unchanged (304): %s", label or dest.name)
        return {
            "path": str(dest),
            "bytes": dest.stat().st_size,
            "skipped": True,
            "etag": etag,
            "url": url,
        }
    resp.raise_for_status()

    tmp = dest.with_suffix(dest.suffix + ".part")
    total = 0
    hasher = hashlib.sha256()
    content_len = resp.headers.get("Content-Length")
    expected = int(content_len) if content_len and content_len.isdigit() else 0
    last_progress = 0
    with tmp.open("wb") as fh:
        for chunk in resp.iter_content(chunk_size=config.HTTP_CHUNK_SIZE):
            check_cancelled()
            if not chunk:
                continue
            fh.write(chunk)
            hasher.update(chunk)
            total += len(chunk)
            if total - last_progress >= 8 * 1024 * 1024 or (expected and total >= expected):
                last_progress = total
                set_progress(
                    phase="download",
                    label=f"Downloading {label or dest.name}",
                    current=total,
                    total=expected,
                    unit="bytes",
                    detail=url.split("/")[2],
                )
    tmp.replace(dest)

    new_etag = resp.headers.get("ETag")
    if etag_path is not None and new_etag:
        etag_path.write_text(new_etag, encoding="utf-8")
    new_lm = resp.headers.get("Last-Modified")
    if lm_path is not None and new_lm:
        lm_path.write_text(new_lm, encoding="utf-8")

    elapsed = max(0.001, time.monotonic() - started)
    mbps = (total / (1024 * 1024)) / elapsed
    log.info(
        "Downloaded %s (%.1f MB in %.1fs, %.1f MB/s) from %s",
        label or dest.name,
        total / (1024 * 1024),
        elapsed,
        mbps,
        url.split("/")[2],
    )
    return {
        "path": str(dest),
        "bytes": total,
        "skipped": False,
        "etag": new_etag,
        "sha256": hasher.hexdigest(),
        "url": url,
    }


def download_first_ok(urls: list[str], dest: Path, label: str = "") -> dict:
    """Try official mirrors in order until one succeeds."""
    last_error: Exception | None = None
    etag_path = dest.with_suffix(dest.suffix + ".etag")
    for url in urls:
        try:
            return download_file(url, dest, etag_path=etag_path, label=label or dest.name)
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            log.warning("Mirror failed (%s): %s", url.split("/")[2], exc)
    raise RuntimeError(f"All download URLs failed for {dest.name}: {urls}") from last_error
