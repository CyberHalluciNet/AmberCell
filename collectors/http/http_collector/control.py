"""Nginx access/error log parse."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_ACCESS = re.compile(
    r'^(?P<ip>[\d.]+)\s+-\s+-\s+\[[^\]]+\]\s+"(?P<method>\w+)\s+(?P<path>[^"\s]+)[^"]*"\s+(?P<status>\d+)',
)
_POST = re.compile(r'\bPOST\b', re.I)
_UPLOAD = re.compile(r"/uploads/", re.I)
_TRAP = re.compile(r"/wp-login\.php|/phpmyadmin", re.I)


@dataclass
class HttpSession:
    session_id: str
    src_ip: str = "0.0.0.0"
    src_port: int = 0
    paths: list[str] = field(default_factory=list)


@dataclass
class ParsedEvent:
    name: str
    session: HttpSession
    details: dict


class HttpControlParser:
    def __init__(self) -> None:
        self._session = HttpSession(session_id="http-default")

    def bind(self, session: HttpSession) -> None:
        self._session = session

    def handle_line(self, line: str) -> list[ParsedEvent]:
        out: list[ParsedEvent] = []
        text = line.strip()
        if not text:
            return out
        m = _ACCESS.search(text)
        if m:
            self._session.src_ip = m.group("ip")
            path = m.group("path")
            self._session.paths.append(path)
            details = {
                "method": m.group("method"),
                "path": path,
                "status": int(m.group("status")),
                "src_ip": self._session.src_ip,
            }
            if _TRAP.search(path):
                out.append(ParsedEvent("http.trap_probe", self._session, details))
            elif _POST.search(text) or m.group("method").upper() == "POST":
                out.append(ParsedEvent("http.post", self._session, details))
            elif _UPLOAD.search(path):
                out.append(ParsedEvent("http.upload", self._session, details))
            else:
                out.append(ParsedEvent("http.request", self._session, details))
        return out
