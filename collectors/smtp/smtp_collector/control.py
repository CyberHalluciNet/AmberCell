"""SMTP dialogue parsing from tcpdump -A and optional daemon log lines."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_HDR = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) "
    r"(?:\S+\s+(?:In|Out)\s+)?"
    r"IP (?P<src>[\d.]+)\.(?P<src_port>\d+) > (?P<dst>[\d.]+)\.(?P<dst_port>\d+):"
)

_EHLO = re.compile(r"^(EHLO|HELO)\s+(\S+)", re.I)
_MAIL = re.compile(r"^MAIL FROM:\s*<([^>]+)>", re.I)
_RCPT = re.compile(r"^RCPT TO:\s*<([^>]+)>", re.I)
_AUTH = re.compile(r"^AUTH\s+(\S+)(?:\s+(.+))?", re.I)
_DATA = re.compile(r"^DATA\s*$", re.I)
_QUIT = re.compile(r"^QUIT\s*$", re.I)
_RCODE = re.compile(r"^(\d{3})([\s-])(.*)")
_PAYLOAD = re.compile(r":\s*(.+)$")
_SMTP_MARKERS = (
    "EHLO ",
    "HELO ",
    "MAIL FROM:",
    "RCPT TO:",
    "DATA",
    "QUIT",
    "AUTH ",
    "220 ",
    "250 ",
    "354 ",
    "554 ",
    "535 ",
)


def _printable(text: str) -> str:
    out: list[str] = []
    for ch in text:
        o = ord(ch)
        if ch in "\r\n\t" or 32 <= o < 127:
            out.append(ch)
    return "".join(out)


def _smtp_payload_text(raw: str) -> str:
    text = _printable(raw).strip()
    if not text:
        return ""
    for marker in _SMTP_MARKERS:
        idx = text.find(marker)
        if idx >= 0:
            return text[idx:].strip()
    rm = _RCODE.match(text)
    if rm:
        return text
    return text


@dataclass
class SmtpSession:
    session_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    banner_seen: bool = False
    in_data: bool = False
    data_lines: list[str] = field(default_factory=list)
    last_mail_from: str | None = None
    last_rcpt: str | None = None


@dataclass
class ParsedEvent:
    name: str
    session: SmtpSession
    details: dict


def client_key(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int, cell_ip: str
) -> tuple[str, int, str, int] | None:
    import os

    relax = os.environ.get("AMBER_SMTP_RELAX_DST", "0") == "1"
    if dst_port == 25 and (dst_ip == cell_ip or relax):
        return (src_ip, src_port, cell_ip, 25)
    if src_port == 25 and (src_ip == cell_ip or relax):
        return (dst_ip, dst_port, cell_ip, 25)
    return None


class SmtpControlParser:
    def __init__(self, cell_ip: str) -> None:
        self.cell_ip = cell_ip
        self._sessions: dict[tuple[str, int, str, int], SmtpSession] = {}
        self._active: tuple[str, int, str, int] | None = None

    def register(self, key: tuple[str, int, str, int], session: SmtpSession) -> None:
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
                    text = _smtp_payload_text(pm.group(1))
                    if text:
                        return self._parse_payload(session, text)
            return []

        text = _smtp_payload_text(line)
        if not text or text.startswith("0x") or text.startswith("|"):
            return []
        if self._active is None:
            return self._parse_log_line(text)
        session = self._sessions.get(self._active)
        if session is None:
            return self._parse_log_line(text)
        return self._parse_payload(session, text)

    def _parse_log_line(self, text: str) -> list[ParsedEvent]:
        # Postfix maillog adapter (FIFO): client= / status= / from= / to=
        out: list[ParsedEvent] = []
        if "relay=" in text and "status=" in text:
            if "relay=none" in text or "status=sent" in text:
                pass
        if "reject" in text.lower() and "relay" in text.lower():
            # No session — skip; tcpdump path emits relay_denied.
            pass
        return out

    def _parse_payload(self, session: SmtpSession, text: str) -> list[ParsedEvent]:
        out: list[ParsedEvent] = []

        if session.in_data:
            if text == ".":
                body = "\r\n".join(session.data_lines)
                session.in_data = False
                session.data_lines.clear()
                out.append(
                    ParsedEvent(
                        "data",
                        session,
                        {
                            "mail_from": session.last_mail_from,
                            "rcpt_to": session.last_rcpt,
                            "byte_length": len(body.encode("utf-8", errors="replace")),
                            "body_preview": body[:200],
                            "body": body,
                        },
                    )
                )
                return out
            session.data_lines.append(text)
            return out

        rm = _RCODE.match(text)
        if rm and not session.banner_seen and rm.group(1).startswith("220"):
            session.banner_seen = True
            out.append(ParsedEvent("session_open", session, {"banner": text[:160]}))
            return out

        if rm and rm.group(1).startswith("554") and "relay" in text.lower():
            out.append(ParsedEvent("relay_denied", session, {"line": text[:200]}))
            return out

        em = _EHLO.match(text)
        if em:
            out.append(
                ParsedEvent("ehlo", session, {"stage": em.group(1).upper(), "host": em.group(2)})
            )
            return out

        mm = _MAIL.match(text)
        if mm:
            session.last_mail_from = mm.group(1)
            out.append(ParsedEvent("mail_from", session, {"from": mm.group(1)}))
            return out

        rc = _RCPT.match(text)
        if rc:
            session.last_rcpt = rc.group(1)
            out.append(ParsedEvent("rcpt_to", session, {"to": rc.group(1)}))
            return out

        am = _AUTH.match(text)
        if am:
            out.append(
                ParsedEvent(
                    "auth",
                    session,
                    {
                        "mechanism": am.group(1),
                        "payload_present": bool(am.group(2)),
                    },
                )
            )
            return out

        if _DATA.match(text):
            session.in_data = True
            out.append(ParsedEvent("data_start", session, {}))
            return out

        if _QUIT.match(text):
            out.append(ParsedEvent("quit", session, {}))
            return out

        if rm and rm.group(1).startswith("535"):
            out.append(
                ParsedEvent("auth", session, {"ok": False, "reason": "auth_failed", "line": text[:120]})
            )
            return out

        return out
