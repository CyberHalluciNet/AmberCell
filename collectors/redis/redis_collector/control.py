"""Redis command + log parse for honeypot evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_CMD = re.compile(
    r"(?P<cmd>CONFIG|AUTH|SET|GET|MODULE|SLAVEOF|REPLICAOF|SAVE|BGSAVE|FLUSHALL|FLUSHDB|DEBUG)\b",
    re.I,
)
_PERSIST = re.compile(r"\b(dir|dbfilename|save|appendonly|slaveof|replicaof)\b", re.I)
_LOG_CLIENT = re.compile(r"Accepted.*connection.*from\s+(?P<ip>[\d.]+):(?P<port>\d+)", re.I)


@dataclass
class RedisSession:
    session_id: str
    src_ip: str
    src_port: int
    commands: list[str] = field(default_factory=list)


@dataclass
class ParsedEvent:
    name: str
    session: RedisSession
    details: dict


class RedisControlParser:
    def __init__(self, cell_ip: str) -> None:
        self.cell_ip = cell_ip
        self._session = RedisSession(session_id="redis-default", src_ip="0.0.0.0", src_port=0)

    def register(self, session: RedisSession) -> None:
        self._session = session

    def handle_line(self, line: str) -> list[ParsedEvent]:
        out: list[ParsedEvent] = []
        text = line.strip()
        if not text:
            return out

        cm = _LOG_CLIENT.search(text)
        if cm:
            self._session.src_ip = cm.group("ip")
            self._session.src_port = int(cm.group("port"))
            out.append(
                ParsedEvent(
                    "connect",
                    self._session,
                    {"src_ip": self._session.src_ip, "src_port": self._session.src_port},
                )
            )

        # RESP-ish fragments from tcpdump -A and redis verbose logs.
        for m in _CMD.finditer(text):
            cmd = m.group("cmd").upper()
            self._session.commands.append(cmd)
            details: dict = {"command": cmd, "line": text[:200]}
            if cmd == "CONFIG" or _PERSIST.search(text):
                details["persistence_probe"] = True
                out.append(ParsedEvent("redis.config", self._session, details))
            elif cmd in ("SET", "GET"):
                out.append(ParsedEvent("redis.kv", self._session, details))
            else:
                out.append(ParsedEvent("redis.command", self._session, details))
        return out
