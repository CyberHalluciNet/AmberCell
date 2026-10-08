"""Parse tcpdump TFTP decode (udp/69): RRQ/WRQ/ERROR summary lines."""

from __future__ import annotations

import re

_LINE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}\.\d+) "
    r"(?:(?P<iface>\S+)\s+(?P<dir>In|Out)\s+)?"
    r"IP (?P<src>[\d.]+)\.(?P<src_port>\d+) > (?P<dst>[\d.]+)\.(?P<dst_port>\d+): "
    r"(?P<rest>.*)$"
)
_OP = re.compile(r"\b(RRQ|WRQ|ERROR|OACK)\b")
_FILE = re.compile(r'(RRQ|WRQ)\s+"([^"]+)"\s+([A-Za-z0-9]+)')


def parse_ts(m: re.Match) -> str:
    frac = (m.group("time").split(".", 1)[1] + "000000000")[:9]
    return f"{m.group('date')}T{m.group('time').split('.')[0]}.{frac}Z"


def parse_tftp_line(line: str) -> dict | None:
    m = _LINE.match(line)
    if m is None:
        return None
    rec = {
        "ts": parse_ts(m),
        "src_ip": m.group("src"),
        "src_port": int(m.group("src_port")),
        "dst_ip": m.group("dst"),
        "dst_port": int(m.group("dst_port")),
        "length": 0,
        "kind": "undecoded",
        "filename": "",
        "mode": "",
    }
    rest = m.group("rest")
    fm = _FILE.search(rest)
    if fm is not None:
        rec.update(kind="query", op=fm.group(1), filename=fm.group(2), mode=fm.group(3))
        return rec
    if _OP.search(rest):
        rec.update(kind="op", op=_OP.search(rest).group(1))
        return rec
    return rec
