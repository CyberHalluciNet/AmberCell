"""Parse RFC3164/5424 syslog messages from tcpdump -A payload lines."""

from __future__ import annotations

import re

from ambercell.timeutil import utc_now_rfc3339_nano

_PRI = re.compile(r"^<(\d{1,3})>(?:(\d) )?")
_HOST_APP = re.compile(r"^(?:(\S+)\s)?(\S+?)(?:\[(\d+)\])?:\s?(.*)$")


def parse_syslog_message(line: str) -> dict | None:
    # tcpdump -A payload lines may be indented after the packet header.
    text = line.rstrip("\r").lstrip()
    if not text.startswith("<"):
        return None
    pm = _PRI.match(text)
    if pm is None:
        return None
    pri = int(pm.group(1))
    rest = text[pm.end():]
    hostname, app, procid, body = "", "", "", rest
    ha = _HOST_APP.match(rest)
    if ha is not None:
        hostname, app, procid, body = ha.group(1) or "", ha.group(2), ha.group(3) or "", ha.group(4)
    if not 0 <= pri <= 191:
        return None
    return {
        "ts": utc_now_rfc3339_nano(),
        "raw": text,
        "facility": pri // 8,
        "severity": pri % 8,
        "hostname": hostname,
        "app": app,
        "procid": procid,
        "body": body,
        "transport": "udp",
    }
