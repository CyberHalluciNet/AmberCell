"""Parse SIP requests/responses from tcpdump -A payload lines (TCP+UDP/5060)."""

from __future__ import annotations

import re

from ambercell.timeutil import utc_now_rfc3339_nano

_REQ = re.compile(
    r"^(REGISTER|INVITE|ACK|BYE|CANCEL|OPTIONS|SUBSCRIBE|NOTIFY|MESSAGE|PUBLISH|REFER|UPDATE)\s+(\S+)\s+SIP/2\.0"
)
_RESP = re.compile(r"^SIP/2\.0\s+(\d{3})")
_HDR = re.compile(r"^(From|f|To|t|Call-ID|i|CSeq|User-Agent|Allow)\s*:\s*(.{0,120})", re.I)


def parse_sip_line(line: str) -> dict | None:
    text = line.rstrip("\r")
    ts = utc_now_rfc3339_nano()
    rm = _REQ.match(text)
    if rm is not None:
        return {"ts": ts, "raw": text, "event": "sip.request", "method": rm.group(1), "uri": rm.group(2)}
    sm = _RESP.match(text)
    if sm is not None:
        return {"ts": ts, "raw": text, "event": "sip.response", "code": int(sm.group(1))}
    hm = _HDR.match(text)
    if hm is not None:
        name = {"f": "From", "t": "To", "i": "Call-ID"}.get(hm.group(1).lower(), hm.group(1))
        return {"ts": ts, "raw": text, "event": "sip.header", "header": name, "value": hm.group(2).strip()}
    return None
