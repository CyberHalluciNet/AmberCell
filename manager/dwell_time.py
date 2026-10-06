"""Dwell-time / continue-engagement stub (~5 min idle) for rebuild recommendations."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

IDLE_SECONDS = int(os.environ.get("AMBER_DWELL_IDLE_SECONDS", "300"))


def _parse_ts(ts: str) -> datetime | None:
    try:
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def last_event_age_seconds(events_path: Path) -> float | None:
    if not events_path.is_file():
        return None
    last: datetime | None = None
    with events_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = rec.get("ts")
            if isinstance(ts, str):
                parsed = _parse_ts(ts)
                if parsed is not None:
                    last = parsed
    if last is None:
        return None
    now = datetime.now(timezone.utc)
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return max(0.0, (now - last).total_seconds())


def should_defer_rebuild(root: Path, svc: str) -> tuple[bool, str]:
    """True when recent interactive activity suggests delaying non-critical rebuild."""
    if os.environ.get("AMBER_FORCE_REBUILD") == "1":
        return False, ""
    age = last_event_age_seconds(root / "jsonl" / svc / "events.jsonl")
    if age is None:
        return False, ""
    if age < IDLE_SECONDS:
        return True, f"last activity {int(age)}s ago (< {IDLE_SECONDS}s idle threshold)"
    return False, ""
