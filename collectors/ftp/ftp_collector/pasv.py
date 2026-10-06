"""Parse FTP PASV/EPSV responses."""

from __future__ import annotations

import re

# 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
_PASV227 = re.compile(
    r"227[^\d]*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)",
    re.IGNORECASE,
)
# 229 Entering Extended Passive Mode (|||port|)
_EPSV229 = re.compile(r"229[^\d]*\(\|\|\|(\d+)\|\)", re.IGNORECASE)


def pasv_port_from_line(line: str) -> int | None:
    line = line.strip()
    m = _PASV227.search(line)
    if m:
        p1, p2 = int(m.group(5)), int(m.group(6))
        return p1 * 256 + p2
    m = _EPSV229.search(line)
    if m:
        return int(m.group(1))
    return None
