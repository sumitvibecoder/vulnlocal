"""User-configurable Sync DB scheduler (stdlib threading).

Schedule is stored in settings.json under ``schedule``:
  enabled, frequency (hourly|daily|weekly|monthly|yearly|once),
  start_at / next_run_at / last_run_at (local-time ISO without timezone).
"""

from __future__ import annotations

import calendar
import logging
import threading
from datetime import datetime, timedelta
from typing import Any, Callable

from ..settings_store import load_settings, save_settings

log = logging.getLogger("vulnlocal.sync")

FREQUENCIES = ("hourly", "daily", "weekly", "monthly", "yearly", "once")

_stop = threading.Event()
_wake = threading.Event()
_threads: list[threading.Thread] = []
_trigger_sync: Callable[[], tuple[dict, int]] | None = None
_tick_lock = threading.Lock()


def register_sync_trigger(fn: Callable[[], tuple[dict, int]]) -> None:
    """Register the app's background-job runner: ``() -> (body, http_code)``."""
    global _trigger_sync
    _trigger_sync = fn


def reload_schedule() -> None:
    """Wake the scheduler after settings change."""
    _wake.set()


def parse_local_dt(value: str | None) -> datetime | None:
    raw = (value or "").strip()
    if not raw:
        return None
    raw = raw.replace("Z", "").replace("z", "")
    if " " in raw and "T" not in raw:
        raw = raw.replace(" ", "T", 1)
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                return datetime.strptime(raw[:19], fmt)
            except ValueError:
                continue
    return None


def format_local_dt(dt: datetime | None) -> str:
    if not dt:
        return ""
    return dt.replace(microsecond=0).isoformat(timespec="minutes")


def add_frequency(dt: datetime, frequency: str) -> datetime:
    freq = (frequency or "daily").lower()
    if freq == "hourly":
        return dt + timedelta(hours=1)
    if freq == "daily":
        return dt + timedelta(days=1)
    if freq == "weekly":
        return dt + timedelta(weeks=1)
    if freq == "monthly":
        y, m = dt.year, dt.month + 1
        if m > 12:
            y, m = y + 1, 1
        day = min(dt.day, calendar.monthrange(y, m)[1])
        return dt.replace(year=y, month=m, day=day)
    if freq == "yearly":
        y = dt.year + 1
        day = min(dt.day, calendar.monthrange(y, dt.month)[1])
        return dt.replace(year=y, day=day)
    # once — unused for advance
    return dt + timedelta(days=1)


def compute_next_run(
    *,
    enabled: bool,
    frequency: str,
    start_at: datetime | None,
    last_run_at: datetime | None,
    now: datetime | None = None,
) -> datetime | None:
    """Next run instant in local time, or None if nothing scheduled.

    A next_run_at in the past means the job is due (tick will fire).
    """
    if not enabled:
        return None
    now = now or datetime.now()
    freq = (frequency or "daily").lower()
    if freq not in FREQUENCIES:
        freq = "daily"
    anchor = start_at or now.replace(second=0, microsecond=0)

    if freq == "once":
        return None if last_run_at else anchor

    cursor = anchor
    if last_run_at:
        safety = 0
        while cursor <= last_run_at and safety < 100000:
            cursor = add_frequency(cursor, freq)
            safety += 1
    return cursor


def normalize_schedule(raw: dict[str, Any] | None) -> dict[str, Any]:
    data = dict(raw or {})
    enabled = bool(data.get("enabled"))
    freq = str(data.get("frequency") or "daily").lower().strip()
    if freq not in FREQUENCIES:
        freq = "daily"
    start = parse_local_dt(str(data.get("start_at") or ""))
    last = parse_local_dt(str(data.get("last_run_at") or ""))
    if not start and enabled:
        start = datetime.now().replace(second=0, microsecond=0)
    next_run = compute_next_run(
        enabled=enabled,
        frequency=freq,
        start_at=start,
        last_run_at=last,
    )
    return {
        "enabled": enabled,
        "frequency": freq,
        "start_at": format_local_dt(start),
        "next_run_at": format_local_dt(next_run),
        "last_run_at": format_local_dt(last),
    }


def get_schedule() -> dict[str, Any]:
    sch = load_settings().get("schedule") or {}
    return normalize_schedule(sch if isinstance(sch, dict) else {})


def save_schedule(payload: dict[str, Any]) -> dict[str, Any]:
    """Persist schedule from Manage UI and recompute next_run_at."""
    current = load_settings().get("schedule") or {}
    merged = dict(current) if isinstance(current, dict) else {}
    if "enabled" in payload:
        merged["enabled"] = bool(payload.get("enabled"))
    if "frequency" in payload:
        freq = str(payload.get("frequency") or "daily").lower().strip()
        merged["frequency"] = freq if freq in FREQUENCIES else "daily"
    if "start_at" in payload:
        start = parse_local_dt(str(payload.get("start_at") or ""))
        merged["start_at"] = format_local_dt(start) if start else ""
        # Changing start clears once-run latch unless last_run kept explicitly
        if str(payload.get("reset_last") or "").lower() in {"1", "true", "yes"}:
            merged["last_run_at"] = ""
    normalized = normalize_schedule(merged)
    save_settings({"schedule": normalized})
    reload_schedule()
    return normalized


def mark_schedule_ran(when: datetime | None = None) -> dict[str, Any]:
    when = when or datetime.now()
    sch = get_schedule()
    sch["last_run_at"] = format_local_dt(when)
    if sch.get("frequency") == "once":
        sch["enabled"] = False
        sch["next_run_at"] = ""
    else:
        start = parse_local_dt(sch.get("start_at"))
        sch["next_run_at"] = format_local_dt(
            compute_next_run(
                enabled=True,
                frequency=str(sch.get("frequency") or "daily"),
                start_at=start,
                last_run_at=when,
                now=when,
            )
        )
    save_settings({"schedule": sch})
    reload_schedule()
    return sch


def schedule_status() -> dict[str, Any]:
    sch = get_schedule()
    next_run = parse_local_dt(sch.get("next_run_at"))
    now = datetime.now()
    due = bool(sch.get("enabled") and next_run and next_run <= now)
    return {
        **sch,
        "due": due,
        "server_now": format_local_dt(now),
    }


def _tick() -> None:
    if not _tick_lock.acquire(blocking=False):
        return
    try:
        sch = get_schedule()
        if not sch.get("enabled"):
            return
        next_run = parse_local_dt(sch.get("next_run_at"))
        if not next_run:
            # Recompute if missing
            sch = normalize_schedule(sch)
            save_settings({"schedule": sch})
            next_run = parse_local_dt(sch.get("next_run_at"))
        if not next_run or next_run > datetime.now():
            return
        if not _trigger_sync:
            log.warning("Scheduled sync due but no trigger registered")
            return
        log.info("Starting scheduled Sync DB (frequency=%s)", sch.get("frequency"))
        body, code = _trigger_sync()
        if code == 409:
            log.info("Scheduled sync deferred — another job is running")
            return
        if code >= 400:
            log.error("Scheduled sync failed to start: %s", body)
            return
        mark_schedule_ran()
        log.info("Scheduled Sync DB started successfully")
    except Exception:
        log.exception("Scheduled sync tick failed")
    finally:
        _tick_lock.release()


def _schedule_loop() -> None:
    # Short initial delay so the app finishes booting
    if _stop.wait(5.0):
        return
    while not _stop.is_set():
        try:
            _tick()
        except Exception:
            log.exception("Schedule loop error")
        _wake.clear()
        # Sleep up to 30s, or wake early on settings change
        _wake.wait(30.0)
        if _stop.is_set():
            break


def start_scheduler() -> None:
    if _threads:
        return
    _stop.clear()
    t = threading.Thread(
        target=_schedule_loop,
        name="vulnlocal-schedule",
        daemon=True,
    )
    t.start()
    _threads.append(t)
    sch = get_schedule()
    log.info(
        "Scheduler started (enabled=%s frequency=%s next=%s)",
        sch.get("enabled"),
        sch.get("frequency"),
        sch.get("next_run_at") or "—",
    )


def stop_scheduler() -> None:
    _stop.set()
    _wake.set()
