"""Parse AMBER_JSON lines from dockerapi trap FIFO."""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class TrapSession:
    session_id: str
    src_ip: str = "0.0.0.0"
    src_port: int = 0


@dataclass
class ParsedEvent:
    name: str
    session: TrapSession
    details: dict


class DockerapiControlParser:
    PREFIX = "AMBER_JSON:"

    def __init__(self) -> None:
        self._session = TrapSession(session_id="dockerapi-default")

    def bind(self, session: TrapSession) -> None:
        self._session = session

    def handle_line(self, line: str) -> list[ParsedEvent]:
        text = line.strip()
        if not text.startswith(self.PREFIX):
            return []
        try:
            payload = json.loads(text[len(self.PREFIX) :])
        except json.JSONDecodeError:
            return []
        ev = payload.pop("event", "dockerapi.request")
        src = payload.pop("src_ip", self._session.src_ip)
        if src:
            self._session.src_ip = str(src)
        return [ParsedEvent(str(ev), self._session, payload)]
