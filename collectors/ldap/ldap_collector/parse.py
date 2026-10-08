"""Parse tcpdump -v LDAP decode (tcp/389)."""

from __future__ import annotations

import re

_LINE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}\.\d+) "
    r"(?:(?P<iface>\S+)\s+(?P<dir>In|Out)\s+)?"
    r"IP (?P<src>[\d.]+)\.(?P<src_port>\d+) > (?P<dst>[\d.]+)\.(?P<dst_port>\d+): "
    r"(?P<rest>.*)$"
)
_LDAP = re.compile(
    r"LDAP\s+(bind|unbind|search|searchResEntry|searchResDone|add|modify|del|compare|abandon|extended|result)",
    re.I,
)
_FLAGS = re.compile(r"Flags \[")


_CONT = re.compile(
    r"^\s+(?P<src>[\d.]+)\.(?P<src_port>\d+) > (?P<dst>[\d.]+)\.(?P<dst_port>\d+): (?P<rest>.*)$"
)


def parse_ldap_line(line: str) -> dict | None:
    m = _LINE.match(line)
    if m is not None:
        frac = (m.group("time").split(".", 1)[1] + "000000000")[:9]
        ts = f"{m.group('date')}T{m.group('time').split('.')[0]}.{frac}Z"
    else:
        m = _CONT.match(line)
        if m is None:
            return None
        from ambercell.timeutil import utc_now_rfc3339_nano

        ts = utc_now_rfc3339_nano()
    rec = {
        "ts": ts,
        "src_ip": m.group("src"),
        "src_port": int(m.group("src_port")),
        "dst_ip": m.group("dst"),
        "dst_port": int(m.group("dst_port")),
        "length": 0,
        "kind": "undecoded",
        "op": "",
        "detail": "",
    }
    rest = m.group("rest")
    if _FLAGS.search(rest):
        # TCP handshake/teardown lines carry no LDAP decode.
        return rec
    lm = _LDAP.search(rest)
    if lm is not None:
        rec.update(kind="ldap", op=lm.group(1).lower(), detail=rest)
    return rec
