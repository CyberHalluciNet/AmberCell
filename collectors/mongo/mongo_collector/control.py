"""MongoDB log parse."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_CONN = re.compile(r"connection accepted from (?P<ip>[\d.]+):(?P<port>\d+)", re.I)
_CMD = re.compile(r"command (?P<db>\S+).*?(dropDatabase|delete|remove|drop)", re.I)
_WIPE = re.compile(r"dropDatabase|deleteMany|drop\s+collection", re.I)


@dataclass
class MongoSession:
    session_id: str
    src_ip: str = "0.0.0.0"
    src_port: int = 0


@dataclass
class ParsedEvent:
    name: str
    session: MongoSession
    details: dict


class MongoControlParser:
    def __init__(self) -> None:
        self._session = MongoSession(session_id="mongo-default")

    def bind(self, session: MongoSession) -> None:
        self._session = session

    def handle_line(self, line: str) -> list[ParsedEvent]:
        out: list[ParsedEvent] = []
        text = line.strip()
        if not text:
            return out
        cm = _CONN.search(text)
        if cm:
            self._session.src_ip = cm.group("ip")
            self._session.src_port = int(cm.group("port"))
            out.append(
                ParsedEvent(
                    "mongo.connect",
                    self._session,
                    {"src_ip": self._session.src_ip, "src_port": self._session.src_port},
                )
            )
        if _WIPE.search(text):
            out.append(ParsedEvent("mongo.wipe", self._session, {"line": text[:300], "severity": "high"}))
        elif _CMD.search(text):
            out.append(ParsedEvent("mongo.command", self._session, {"line": text[:300]}))
        return out
