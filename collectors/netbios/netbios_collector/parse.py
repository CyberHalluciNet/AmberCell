"""Parse NBNS (NetBIOS name service, udp/137) from tcpdump -x hex dumps.

tcpdump prints the datagram payload as indented hex lines
("    0x0000:  8100 0100 ..."); we reassemble the bytes and decode the NBNS
header + first question name (netbios first-level encoding).
"""

from __future__ import annotations

import re

from ambercell.timeutil import utc_now_rfc3339_nano

_HEXLINE = re.compile(r"^\s+0x[0-9a-fA-F]+:\s+((?:[0-9a-fA-F]{2,4}\s*)+)$")

SUFFIX_NAMES = {
    0x00: "workstation",
    0x03: "messenger",
    0x20: "file server",
    0x1B: "domain master browser",
    0x1D: "master browser",
    0x1E: "browser elections",
}


def decode_netbios_name(encoded: bytes) -> tuple[str, int] | None:
    """First-level decode of a 32-byte encoded NetBIOS name + its suffix."""
    if len(encoded) < 32:
        return None
    out = bytearray()
    for i in range(0, 32, 2):
        hi = encoded[i] - ord("A")
        lo = encoded[i + 1] - ord("A")
        if not (0 <= hi <= 15 and 0 <= lo <= 15):
            return None
        out.append((hi << 4) | lo)
    name = bytes(out[:15]).decode("ascii", "replace").strip()
    suffix = out[15]
    return name, suffix


def parse_nbns_hex_lines(lines: list[str]) -> dict | None:
    """Assemble consecutive hex-dump lines into one NBNS record."""
    data = bytearray()
    for line in lines:
        m = _HEXLINE.match(line)
        if m is None:
            break
        chunk = m.group(1).split()
        for tok in chunk:
            data.extend(bytes.fromhex(tok))
    if len(data) < 12:
        return None
    tid = (data[0] << 8) | data[1]
    flags = (data[2] << 8) | data[3]
    qd = (data[4] << 8) | data[5]
    an = (data[6] << 8) | data[7]
    is_response = bool(flags & 0x8000)
    rec = {
        "ts": utc_now_rfc3339_nano(),
        "tid": tid,
        "is_response": is_response,
        "qdcount": qd,
        "ancount": an,
        "opcode": (flags >> 11) & 0xF,
        "qname": "",
        "suffix": None,
        "suffix_name": "",
    }
    # NBNS qnames are DNS-style length-prefixed labels (0x20 = 32 bytes).
    if qd > 0 and len(data) >= 12 + 35 and data[12] == 0x20:
        dec = decode_netbios_name(bytes(data[13:45]))
        if dec is not None:
            rec["qname"], rec["suffix"] = dec
            rec["suffix_name"] = SUFFIX_NAMES.get(dec[1], f"0x{dec[1]:02x}")
            qtype = (data[46] << 8) | data[47] if len(data) >= 48 else 0
            rec["qtype"] = qtype
    return rec
