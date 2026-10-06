"""Elasticsearch access log parse (stdout + tcpdump)."""

from __future__ import annotations

import re
from dataclasses import dataclass

_REQ = re.compile(r'"(?P<method>GET|POST|PUT|DELETE|HEAD)\s+(?P<path>/[^\s"]*)', re.I)
_BULK_DEL = re.compile(r"bulk.*delete|_delete_by_query", re.I)


@dataclass
class ElasticSession:
    session_id: str
    src_ip: str = "0.0.0.0"


@dataclass
class ParsedEvent:
    name: str
    session: ElasticSession
    details: dict


class ElasticControlParser:
    def __init__(self) -> None:
        self._session = ElasticSession(session_id="es-default")

    def bind(self, session: ElasticSession) -> None:
        self._session = session

    def handle_line(self, line: str) -> list[ParsedEvent]:
        out: list[ParsedEvent] = []
        text = line.strip()
        if not text:
            return out
        rm = _REQ.search(text)
        if rm:
            path = rm.group("path")
            details = {"method": rm.group("method"), "path": path}
            if _BULK_DEL.search(text) or "DELETE" in rm.group("method"):
                out.append(ParsedEvent("elastic.bulk_delete", self._session, {**details, "severity": "high"}))
            else:
                out.append(ParsedEvent("elastic.request", self._session, details))
        if "ransom" in text.lower() or "read_me" in text.lower():
            out.append(ParsedEvent("elastic.ransom_note", self._session, {"line": text[:200]}))
        return out
