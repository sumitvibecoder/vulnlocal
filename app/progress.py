"""Shared live progress reporting and cooperative job cancellation."""

from __future__ import annotations

import threading
import time
from typing import Any


class JobCancelled(Exception):
    """Raised when a background job is asked to stop."""


_lock = threading.Lock()
_cancel = threading.Event()
_progress: dict[str, Any] = {
    "phase": None,
    "label": None,
    "current": 0,
    "total": 0,
    "unit": "",
    "percent": None,
    "detail": "",
    "updated_at": None,
    "cancel_requested": False,
}


def clear_progress() -> None:
    with _lock:
        _progress.update(
            {
                "phase": None,
                "label": None,
                "current": 0,
                "total": 0,
                "unit": "",
                "percent": None,
                "detail": "",
                "updated_at": None,
                "cancel_requested": False,
            }
        )


def reset_cancel() -> None:
    _cancel.clear()
    with _lock:
        _progress["cancel_requested"] = False


def request_cancel() -> bool:
    """Signal the running job to stop. Returns False if nothing is cancellable yet."""
    _cancel.set()
    with _lock:
        _progress["cancel_requested"] = True
        if _progress.get("label"):
            _progress["detail"] = "stop requested…"
            _progress["updated_at"] = time.time()
    return True


def cancel_requested() -> bool:
    return _cancel.is_set()


def check_cancelled() -> None:
    if _cancel.is_set():
        raise JobCancelled("Job stopped by user")


def set_progress(
    *,
    phase: str,
    label: str,
    current: int = 0,
    total: int = 0,
    unit: str = "",
    detail: str = "",
) -> None:
    check_cancelled()
    percent = None
    if total and total > 0:
        percent = round(min(100.0, (current / total) * 100.0), 1)
    with _lock:
        _progress.update(
            {
                "phase": phase,
                "label": label,
                "current": int(current),
                "total": int(total) if total else 0,
                "unit": unit,
                "percent": percent,
                "detail": detail,
                "updated_at": time.time(),
                "cancel_requested": _cancel.is_set(),
            }
        )


def get_progress() -> dict[str, Any]:
    with _lock:
        data = dict(_progress)
    data["cancel_requested"] = _cancel.is_set()
    return data
