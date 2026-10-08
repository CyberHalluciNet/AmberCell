"""Parse VNC banner from tcpdump -A payload (tcp/5900)."""

from __future__ import annotations

import re

from ambercell.timeutil import utc_now_rfc3339_nano

_RFB = re.compile(r"^RFB[ ]?(\d{3}\.\d{3})")


def parse_vnc_line(line: str) -> dict | None:
    text = line.rstrip("\r").lstrip()
    m = _RFB.match(text)
    if m is None:
        return None
    return {
        "ts": utc_now_rfc3339_nano(),
        "raw": text[:64],
        "event": "vnc.banner",
        "protocol_version": m.group(1),
    }
