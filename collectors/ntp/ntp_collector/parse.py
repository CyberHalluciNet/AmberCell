"""Parse tcpdump NTP decode (udp/123)."""

from __future__ import annotations

import re

_LINE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}\.\d+) "
    r"(?:(?P<iface>\S+)\s+(?P<dir>In|Out)\s+)?"
    r"IP (?P<src>[\d.]+)\.(?P<src_port>\d+) > (?P<dst>[\d.]+)\.(?P<dst_port>\d+): "
    r"(?P<rest>.*)$"
)
_NTP = re.compile(r"NTPv(\d+),? length (\d+)")


def parse_ntp_line(line: str) -> dict | None:
    m = _LINE.match(line)
    if m is None:
        return None
    frac = (m.group("time").split(".", 1)[1] + "000000000")[:9]
    rec = {
        "ts": f"{m.group('date')}T{m.group('time').split('.')[0]}.{frac}Z",
        "src_ip": m.group("src"),
        "src_port": int(m.group("src_port")),
        "dst_ip": m.group("dst"),
        "dst_port": int(m.group("dst_port")),
        "length": 0,
        "kind": "undecoded",
        "version": 0,
    }
    nm = _NTP.search(m.group("rest"))
    if nm is not None:
        rec.update(kind="ntp", version=int(nm.group(1)), length=int(nm.group(2)))
    return rec
