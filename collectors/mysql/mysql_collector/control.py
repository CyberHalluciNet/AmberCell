"""MariaDB general log parse."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_CONNECT = re.compile(r"Connect\s+(?P<user>\S+).*?@(?P<ip>[\d.]+)", re.I)
_QUERY = re.compile(r"Query\s+(?P<sql>.+)", re.I)
_OUTFILE = re.compile(r"INTO\s+(OUTFILE|DUMPFILE)", re.I)


@dataclass
class MysqlSession:
    session_id: str
    src_ip: str = "0.0.0.0"
    user: str | None = None
    queries: list[str] = field(default_factory=list)


@dataclass
class ParsedEvent:
    name: str
    session: MysqlSession
    details: dict


class MysqlControlParser:
    def __init__(self) -> None:
        self._session = MysqlSession(session_id="mysql-default")

    def bind(self, session: MysqlSession) -> None:
        self._session = session

    def handle_line(self, line: str) -> list[ParsedEvent]:
        out: list[ParsedEvent] = []
        text = line.strip()
        if not text:
            return out
        cm = _CONNECT.search(text)
        if cm:
            self._session.user = cm.group("user")
            self._session.src_ip = cm.group("ip")
            out.append(
                ParsedEvent(
                    "mysql.auth",
                    self._session,
                    {"user": self._session.user, "src_ip": self._session.src_ip},
                )
            )
        qm = _QUERY.search(text)
        if qm:
            sql = qm.group("sql").strip()
            self._session.queries.append(sql[:200])
            details = {"sql": sql[:500]}
            if _OUTFILE.search(sql):
                out.append(ParsedEvent("mysql.outfile", self._session, {**details, "severity": "high"}))
            else:
                out.append(ParsedEvent("mysql.query", self._session, details))
        if "Access denied" in text:
            out.append(ParsedEvent("mysql.auth_fail", self._session, {"line": text[:200]}))
        return out
