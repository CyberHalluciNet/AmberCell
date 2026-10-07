"""Parse tcpdump summary-line DNS decode (udp/tcp 53) into structured exchanges.

tcpdump decodes DNS natively; we parse its summary lines instead of raw payload
bytes (no -A). Query lines carry a ``?``-suffixed qtype token; response lines
carry ``an/ns/ar`` counters and an optional rcode token (tcpdump's historic
"RefUsed" spelling included).
"""

from __future__ import annotations

import re

# Same packet prefix as ambercell.flow_tracker but without the Flags tail
# (udp/tcp 53 lines carry the DNS decode after the colon).
_PREFIX = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}\.\d+) "
    r"(?:(?P<iface>\S+)\s+(?P<dir>In|Out)\s+)?"
    r"IP (?P<src>[\d.]+)\.(?P<src_port>\d+) > (?P<dst>[\d.]+)\.(?P<dst_port>\d+): "
    r"(?P<rest>.*)$"
)

_QID = re.compile(r"^(?P<qid>\d{1,5})(?P<flags>[\*\+\-\|\$%]*)(?P<body>.*)$")
_EDNS = re.compile(r"\[\d+au\]")
_QUERY = re.compile(
    r"(?P<qtype>[A-Za-z][A-Za-z0-9]*)\?\s(?P<qname>\S+?)(?:\.)?(?:\s+\((?P<len>\d+)\))?\s*$"
)
_COUNTS = re.compile(r"(?P<an>\d+)/(?P<ns>\d+)/(?P<ar>\d+)")
_RCODE = re.compile(
    r"\b(NXDomain|ServFail|FormErr|NotImp|RefUsed|Refused|BadVers|BadName|BadAlg|BadTrunc|BadKey)\b"
)
_LEN = re.compile(r"\((?P<len>\d+)\)\s*$")
RCODE_MAP = {"RefUsed": "Refused"}

AXFR_TYPES = ("AXFR", "IXFR")


def parse_ts(m: re.Match) -> str:
    frac = m.group("time").split(".", 1)[1]
    frac = (frac + "000000000")[:9]
    return f"{m.group('date')}T{m.group('time').split('.')[0]}.{frac}Z"


def parse_dns_line(line: str) -> dict | None:
    """Parse one tcpdump summary line carrying a DNS decode.

    Returns None for non-matching lines (TCP handshake lines, daemon logs, ...).
    The caller tags transport (udp/tcp) based on which tcpdump stream produced
    the line.
    """
    m = _PREFIX.match(line)
    if m is None:
        return None
    rec = {
        "ts": parse_ts(m),
        "src_ip": m.group("src"),
        "src_port": int(m.group("src_port")),
        "dst_ip": m.group("dst"),
        "dst_port": int(m.group("dst_port")),
        "truncated": False,
        "update": False,
        "edns": False,
        "length": 0,
    }
    rest = m.group("rest")
    qm = _QID.match(rest)
    if qm is None:
        # Packet on port 53 without a DNS decode (or TCP header line). The
        # caller decides whether this is a port-53 packet worth a raw flow.
        rec["kind"] = "undecoded"
        rec["rest"] = rest
        return rec
    rec["qid"] = int(qm.group("qid"))
    rec["dns_flags"] = qm.group("flags")
    body = qm.group("body")
    if _EDNS.search(body):
        rec["edns"] = True
        body = _EDNS.sub("", body).strip()
    if "[|dns]" in body:
        rec["truncated"] = True
        body = body.replace("[|dns]", "").strip()
    lm = _LEN.search(body)
    if lm:
        rec["length"] = int(lm.group("len"))
        body = _LEN.sub("", body).strip()

    if body.startswith("update"):
        rec.update(kind="query", update=True, qtype="", qname="", rcode="")
        return rec

    qmatch = _QUERY.search(body)
    if qmatch is not None:
        rec.update(
            kind="query",
            qtype=qmatch.group("qtype"),
            qname=qmatch.group("qname").rstrip("."),
            rcode="",
        )
        return rec

    cm = _COUNTS.search(body)
    if cm is not None:
        rcode = "NOERROR"
        rm = _RCODE.search(body)
        if rm:
            rcode = RCODE_MAP.get(rm.group(1), rm.group(1))
        rec.update(
            kind="response",
            qtype="",
            qname="",
            rcode=rcode,
            ancount=int(cm.group("an")),
            nscount=int(cm.group("ns")),
            arcount=int(cm.group("ar")),
        )
        return rec

    rec["kind"] = "undecoded"
    rec["rest"] = rest
    return rec
