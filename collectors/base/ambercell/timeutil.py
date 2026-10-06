"""UTC RFC3339 timestamps with nanosecond-precision fields when available."""

from __future__ import annotations

import time
from datetime import datetime, timezone


def utc_now_rfc3339_nano() -> str:
    # stdlib datetime has no timespec='nanoseconds'; pad microseconds to 9 digits.
    now = datetime.now(timezone.utc)
    base = now.strftime("%Y-%m-%dT%H:%M:%S")
    # Prefer time.time_ns for sub-microsecond when the clock supports it.
    nanos = time.time_ns() % 1_000_000_000
    return f"{base}.{nanos:09d}Z"


def epoch_to_rfc3339_nano(ts: float) -> str:
    sec = int(ts)
    frac = ts - sec
    dt = datetime.fromtimestamp(sec, tz=timezone.utc)
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    nanos = int(round(frac * 1_000_000_000))
    if nanos >= 1_000_000_000:
        nanos = 999_999_999
    return f"{base}.{nanos:09d}Z"
