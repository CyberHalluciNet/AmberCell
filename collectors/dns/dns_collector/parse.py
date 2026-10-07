"""Parse tcpdump summary-line DNS decode (udp/tcp 53) into structured exchanges.

tcpdump decodes DNS natively; we parse its summary lines instead of raw payload
bytes (no -A). Query lines carry a ``?``-suffixed qtype token; non-IN classes
appear as ``TXT CH? name`` (modern tcpdump). Response lines carry ``an/ns/ar``
counters and an optional rcode token (tcpdump's historic "RefUsed" spelling
included).
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
# Modern tcpdump: "TXT CH? version.bind." — class sits between type and '?'.
# Legacy / alt: "TXT? version.bind. CH" or "TXT? version.bind. (CH)".
_QUERY = re.compile(
    r"(?P<qtype>[A-Za-z][A-Za-z0-9]*)"
    r"(?:\s+(?P<qclass>CH|HS|IN|ANY))?"
    r"\?\s(?P<qname>\S+?)"
    r"(?:\.)?"
    r"(?:\s+(?P<qclass_trail>CH|HS|IN|ANY))?"
    r"(?:\s+\((?P<len>\d+|CH|HS|IN|ANY)\))?"
    r"\s*$"
)
_COUNTS = re.compile(r"(?P<an>\d+)/(?P<ns>\d+)/(?P<ar>\d+)")
_RCODE = re.compile(
    r"\b(NXDomain|ServFail|FormErr|NotImp|RefUsed|Refused|BadVers|BadName|BadAlg|BadTrunc|BadKey)\b"
)
_LEN = re.compile(r"\((?P<len>\d+)\)\s*$")
RCODE_MAP = {"RefUsed": "Refused"}

AXFR_TYPES = ("AXFR", "IXFR")
_CHAOS_CLASSES = frozenset({"CH", "CHAOS"})
# Lab publish / host-side capture can show these as the packet destination
# instead of the cell IP. Never treat "any dst port 53" as inbound (G13).
RELAX_DST_IPS = frozenset({"127.0.0.1", "0.0.0.0"})


def toward_cell(rec: dict, *, cell_ip: str, relax: bool) -> bool:
    """Client → cell query direction (never matches cell → external resolver)."""
    if rec["dst_port"] != 53:
        return False
    if rec["dst_ip"] == cell_ip:
        return True
    return relax and rec["dst_ip"] in RELAX_DST_IPS


def from_cell(rec: dict, *, cell_ip: str, relax: bool) -> bool:
    """Cell → client (or cell → upstream) with source port 53."""
    if rec["src_port"] != 53:
        return False
    if rec["src_ip"] == cell_ip:
        return True
    return relax and rec["src_ip"] in RELAX_DST_IPS


def parse_ts(m: re.Match) -> str:
    frac = m.group("time").split(".", 1)[1]
    frac = (frac + "000000000")[:9]
    return f"{m.group('date')}T{m.group('time').split('.')[0]}.{frac}Z"


def is_chaos_probe(rec: dict) -> bool:
    """True when the query is CHAOS-class (tcpdump: ``TXT CH? …`` / ``CH``)."""
    qclass = (rec.get("qclass") or "").upper()
    qtype = (rec.get("qtype") or "").upper()
    return qclass in _CHAOS_CLASSES or qtype in _CHAOS_CLASSES


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
        "qclass": "IN",
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
        qclass = qmatch.group("qclass") or qmatch.group("qclass_trail") or "IN"
        paren = qmatch.group("len")
        length = rec["length"]
        if paren is not None:
            if paren.isdigit():
                length = int(paren)
            elif paren.upper() in ("CH", "HS", "IN", "ANY") and qmatch.group("qclass") is None:
                # "TXT? version.bind. (CH)" — class was in the paren slot.
                qclass = paren.upper()
        rec.update(
            kind="query",
            qtype=qmatch.group("qtype"),
            qname=qmatch.group("qname").rstrip("."),
            qclass=qclass.upper(),
            rcode="",
            length=length,
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
