"""POP3 command parsing from tcpdump -A and dovecot log lines."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_HDR = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) "
    r"(?:\S+\s+(?:In|Out)\s+)?"
    r"IP (?P<src>[\d.]+)\.(?P<src_port>\d+) > (?P<dst>[\d.]+)\.(?P<dst_port>\d+):"
)

_USER = re.compile(r"^USER\s+(\S+)", re.I)
_PASS = re.compile(r"^PASS\s+(\S+)", re.I)
_STAT = re.compile(r"^STAT\s*$", re.I)
_LIST = re.compile(r"^LIST(?:\s+(\d+))?\s*$", re.I)
_UIDL = re.compile(r"^UIDL(?:\s+(\d+))?\s*$", re.I)
_RETR = re.compile(r"^RETR\s+(\d+)", re.I)
_DELE = re.compile(r"^DELE\s+(\d+)", re.I)
_QUIT = re.compile(r"^QUIT\s*$", re.I)
_RCODE = re.compile(r"^([+\-])\s?(.*)")
_PAYLOAD = re.compile(r":\s*(.+)$")
_POP3_MARKERS = (
    "USER ",
    "PASS ",
    "STAT",
    "LIST",
    "UIDL",
    "RETR ",
    "DELE ",
    "QUIT",
    "+OK",
    "-ERR",
)


def _printable(text: str) -> str:
    out: list[str] = []
    for ch in text:
        o = ord(ch)
        if ch in "\r\n\t" or 32 <= o < 127:
            out.append(ch)
    return "".join(out)


def _pop3_payload_text(raw: str) -> str:
    text = _printable(raw).strip()
    if not text:
        return ""
    for marker in _POP3_MARKERS:
        idx = text.find(marker)
        if idx >= 0:
            return text[idx:].strip()
    return text


@dataclass
class Pop3Session:
    session_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    banner_seen: bool = False
    user: str | None = None
    authed: bool = False
    pending_pass: bool = False
    pending_retr: int | None = None
    awaiting_retr_body: bool = False
    retr_buffer: list[str] = field(default_factory=list)


@dataclass
class ParsedEvent:
    name: str
    session: Pop3Session
    details: dict


def client_key(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int, cell_ip: str
) -> tuple[str, int, str, int] | None:
    import os

    relax = os.environ.get("AMBER_POP3_RELAX_DST", "0") == "1"
    if dst_port == 110 and (dst_ip == cell_ip or relax):
        return (src_ip, src_port, cell_ip, 110)
    if src_port == 110 and (src_ip == cell_ip or relax):
        return (dst_ip, dst_port, cell_ip, 110)
    return None


class Pop3ControlParser:
    def __init__(self, cell_ip: str) -> None:
        self.cell_ip = cell_ip
        self._sessions: dict[tuple[str, int, str, int], Pop3Session] = {}
        self._active: tuple[str, int, str, int] | None = None

    def register(self, key: tuple[str, int, str, int], session: Pop3Session) -> None:
        self._sessions[key] = session

    def handle_line(self, line: str) -> list[ParsedEvent]:
        m = _HDR.match(line)
        if m:
            self._active = client_key(
                m.group("src"),
                int(m.group("src_port")),
                m.group("dst"),
                int(m.group("dst_port")),
                self.cell_ip,
            )
            pm = _PAYLOAD.search(line)
            if pm and self._active is not None:
                session = self._sessions.get(self._active)
                if session is not None:
                    text = _pop3_payload_text(pm.group(1))
                    if text:
                        return self._parse_payload(session, text)
            return []

        text = _pop3_payload_text(line)
        if not text or text.startswith("0x") or text.startswith("|"):
            return []
        session = None
        if self._active is not None:
            session = self._sessions.get(self._active)
        if session is None and self._sessions:
            session = next(reversed(self._sessions.values()))
        if session is None:
            return []

        return self._parse_payload(session, text)

    def _parse_payload(self, session: Pop3Session, text: str) -> list[ParsedEvent]:
        out: list[ParsedEvent] = []

        if session.awaiting_retr_body:
            if text == ".":
                body = "\r\n".join(session.retr_buffer)
                msg_num = session.pending_retr
                session.pending_retr = None
                session.awaiting_retr_body = False
                session.retr_buffer.clear()
                out.append(
                    ParsedEvent(
                        "retr",
                        session,
                        {
                            "msg_num": msg_num,
                            "user": session.user,
                            "byte_length": len(body.encode("utf-8", errors="replace")),
                            "body": body,
                        },
                    )
                )
                return out
            if not (text.startswith("+OK") and not session.retr_buffer):
                session.retr_buffer.append(text)
            return out

        rm = _RCODE.match(text)
        if rm and rm.group(1) == "+" and text.startswith("+OK Dovecot"):
            if not session.banner_seen:
                session.banner_seen = True
                out.append(ParsedEvent("session_open", session, {"banner": text[:160]}))
            return out


        um = _USER.match(text)
        if um:
            session.user = um.group(1)
            out.append(ParsedEvent("user", session, {"user": session.user}))
            return out

        pm = _PASS.match(text)
        if pm:
            session.pending_pass = True
            return out

        if _STAT.match(text):
            out.append(ParsedEvent("stat", session, {"user": session.user}))
            return out

        lm = _LIST.match(text)
        if lm:
            out.append(
                ParsedEvent("list", session, {"user": session.user, "msg_num": lm.group(1)})
            )
            return out

        uid = _UIDL.match(text)
        if uid:
            out.append(
                ParsedEvent("uidl", session, {"user": session.user, "msg_num": uid.group(1)})
            )
            return out

        retr = _RETR.match(text)
        if retr:
            session.pending_retr = int(retr.group(1))
            session.awaiting_retr_body = True
            out.append(
                ParsedEvent("retr_start", session, {"msg_num": session.pending_retr, "user": session.user})
            )
            return out

        dele = _DELE.match(text)
        if dele:
            out.append(
                ParsedEvent(
                    "dele",
                    session,
                    {"msg_num": int(dele.group(1)), "user": session.user},
                )
            )
            return out

        if _QUIT.match(text):
            out.append(ParsedEvent("quit", session, {"user": session.user}))
            return out

        if rm and rm.group(1) == "+":
            if session.pending_pass and session.user and not session.authed:
                session.pending_pass = False
                session.authed = True
                out.append(
                    ParsedEvent(
                        "auth",
                        session,
                        {"user": session.user, "ok": True, "reason": "pop3_pass", "line": text[:120]},
                    )
                )
                return out

        if rm and rm.group(1) == "-":
            if session.pending_pass and session.user and not session.authed:
                session.pending_pass = False
                out.append(
                    ParsedEvent(
                        "auth",
                        session,
                        {"user": session.user, "ok": False, "reason": "bad_password", "line": text[:120]},
                    )
                )
            return out

        return out
