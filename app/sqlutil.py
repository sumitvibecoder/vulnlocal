"""Small SQL helpers that keep dynamic fragments non-injectable."""

from __future__ import annotations


def in_placeholders(count: int, *, max_items: int = 5000) -> str:
    """Return '?,?,?' for a bound IN (...) clause. Never interpolates user text."""
    n = int(count)
    if n < 1 or n > max_items:
        raise ValueError("invalid IN clause size")
    return ",".join("?" * n)
