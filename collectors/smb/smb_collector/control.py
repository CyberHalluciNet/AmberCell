"""Samba log parse."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_AUTH = re.compile(r"(?P<user>\S+).*auth.*?(?P<ip>[\d.]+)", re.I)
_SHARE = re.compile(r"connecting to share (?P<share>\S+)", re.I)
_OPEN = re.compile(r"opened file (?P<path>\S+)", re.I)


@dataclass
class SmbSession:
    session_id: str
    src_ip: str = "0.0.0.0"
    user: str | None = None
    shares: list[str] = field(default_factory=list)


@dataclass
class ParsedEvent:
    name: str
    session: SmbSession
    details: dict


class SmbControlParser:
    def __init__(self) -> None:
        self._session = SmbSession(session_id="smb-default")

    def bind(self, session: SmbSession) -> None:
        self._session = session

    def handle_line(self, line: str) -> list[ParsedEvent]:
        out: list[ParsedEvent] = []
        text = line.strip()
        if not text:
            return out
        am = _AUTH.search(text)
        if am:
            self._session.user = am.group("user")
            self._session.src_ip = am.group("ip")
            out.append(
                ParsedEvent(
                    "smb.auth",
                    self._session,
                    {"user": self._session.user, "src_ip": self._session.src_ip},
                )
            )
        sm = _SHARE.search(text)
        if sm:
            share = sm.group("share")
            self._session.shares.append(share)
            out.append(ParsedEvent("smb.share_enum", self._session, {"share": share}))
        om = _OPEN.search(text)
        if om:
            path = om.group("path")
            out.append(ParsedEvent("smb.file_open", self._session, {"path": path}))
        return out
