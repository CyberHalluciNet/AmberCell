"""PostgreSQL log parse."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_CONN = re.compile(r"connection (?:authorized|received).*?(?P<user>\S+).*?(?P<ip>[\d.]+)", re.I)
_STMT = re.compile(r"statement:\s+(?P<sql>.+)", re.I)
_COPY = re.compile(r"COPY\s+.+\s+FROM\s+PROGRAM|COPY\s+.+\s+TO\s+PROGRAM", re.I)


@dataclass
class PostgresSession:
    session_id: str
    src_ip: str = "0.0.0.0"
    user: str | None = None
    queries: list[str] = field(default_factory=list)


@dataclass
class ParsedEvent:
    name: str
    session: PostgresSession
    details: dict


class PostgresControlParser:
    def __init__(self) -> None:
        self._session = PostgresSession(session_id="pg-default")

    def bind(self, session: PostgresSession) -> None:
        self._session = session

    def handle_line(self, line: str) -> list[ParsedEvent]:
        out: list[ParsedEvent] = []
        text = line.strip()
        if not text:
            return out
        cm = _CONN.search(text)
        if cm:
            self._session.user = cm.group("user")
            self._session.src_ip = cm.group("ip")
            out.append(
                ParsedEvent(
                    "postgres.auth",
                    self._session,
                    {"user": self._session.user, "src_ip": self._session.src_ip},
                )
            )
        sm = _STMT.search(text)
        if sm:
            sql = sm.group("sql").strip()
            self._session.queries.append(sql[:200])
            details = {"sql": sql[:500]}
            if _COPY.search(sql):
                out.append(ParsedEvent("postgres.copy_program", self._session, {**details, "severity": "high"}))
            else:
                out.append(ParsedEvent("postgres.query", self._session, details))
        if "password authentication failed" in text.lower():
            out.append(ParsedEvent("postgres.auth_fail", self._session, {"line": text[:200]}))
        return out
