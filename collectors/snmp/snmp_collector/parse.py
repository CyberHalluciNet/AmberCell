"""Parse tcpdump -v SNMP decode (udp/tcp 161): PDU op, reqid, OIDs."""

from __future__ import annotations

import re

from ambercell.timeutil import utc_now_rfc3339_nano

_LINE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}\.\d+) "
    r"(?:(?P<iface>\S+)\s+(?P<dir>In|Out)\s+)?"
    r"IP6? (?P<src>[\d.]+)\.(?P<src_port>\d+) > (?P<dst>[\d.]+)\.(?P<dst_port>\d+): "
    r"(?P<rest>.*)$"
)
_VERS = re.compile(r"SNMPv(\d)([cu]?)")
_OPS = re.compile(
    r"(GetRequest|GetNextRequest|GetBulkRequest|SetRequest|GetResponse|Report|Trapv1|Trap)"
)
_REQID = re.compile(r"R=(\d+)")
_OID = re.compile(r"\.1(?:\.\d+)+")

OP_EVENTS = {
    "GetRequest": "snmp.get",
    "GetNextRequest": "snmp.getnext",
    "GetBulkRequest": "snmp.getbulk",
    "SetRequest": "snmp.set",
    "GetResponse": "snmp.response",
    "Report": "snmp.report",
    "Trapv1": "snmp.trap",
    "Trap": "snmp.trap",
}


_CONT = re.compile(
    r"^\s+(?P<src>[\d.]+)\.(?P<src_port>\d+) > (?P<dst>[\d.]+)\.(?P<dst_port>\d+): (?P<rest>.*)$"
)


def parse_ts(m: re.Match) -> str:
    frac = (m.group("time").split(".", 1)[1] + "000000000")[:9]
    return f"{m.group('date')}T{m.group('time').split('.')[0]}.{frac}Z"


def parse_snmp_line(line: str, transport: str) -> dict | None:
    m = _LINE.match(line)
    if m is not None:
        ts = parse_ts(m)
    else:
        # tcpdump -v puts addresses+decode on an indented continuation line.
        m = _CONT.match(line)
        if m is None:
            return None
        ts = utc_now_rfc3339_nano()
    rec = {
        "ts": ts,
        "src_ip": m.group("src"),
        "src_port": int(m.group("src_port")),
        "dst_ip": m.group("dst"),
        "dst_port": int(m.group("dst_port")),
        "transport": transport,
        "kind": "undecoded",
        "version": "",
        "oids": [],
        "reqid": 0,
        "op": "",
    }
    rest = m.group("rest")
    vm = _VERS.search(rest)
    om = _OPS.search(rest)
    if vm is None and om is None:
        return rec
    if vm is not None:
        rec["version"] = f"v{vm.group(1)}{vm.group(2) or ''}"
    if om is None:
        return rec
    rec["op"] = om.group(1)
    rec["kind"] = "snmp"
    rm = _REQID.search(rest)
    if rm is not None:
        rec["reqid"] = int(rm.group(1))
    oids = _OID.findall(rest)
    rec["oids"] = [o.lstrip(".") for o in oids[:8]]
    return rec
