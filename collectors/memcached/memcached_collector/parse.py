"""Parse memcached text-protocol lines from tcpdump -A payload (tcp/11211)."""

from __future__ import annotations

import re

from ambercell.timeutil import utc_now_rfc3339_nano

_CMDS = (
    "get|gets|set|add|replace|append|prepend|cas|delete|incr|decr|touch|gat|"
    "stats|flush_all|version|verbosity|quit|watch"
)
_CMD = re.compile(rf"^({_CMDS})\b[ \t]*(.*)$", re.IGNORECASE)


def parse_memcached_line(line: str) -> dict | None:
    text = line.rstrip("\r").lstrip()
    if not text:
        return None
    m = _CMD.match(text)
    if m is None:
        return None
    cmd = m.group(1).lower()
    args = (m.group(2) or "").strip()
    rec = {
        "ts": utc_now_rfc3339_nano(),
        "raw": text,
        "event": f"memcached.{cmd}",
        "command": cmd,
        "argument": args[:120],
    }
    if cmd in ("get", "gets"):
        rec["keys"] = [k for k in re.split(r"\s+", args) if k][:8]
    elif cmd == "set" or cmd in ("add", "replace", "append", "prepend"):
        parts = re.split(r"\s+", args)
        if parts:
            rec["key"] = parts[0][:120]
    return rec
