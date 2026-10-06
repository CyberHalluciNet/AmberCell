"""Lightweight FTP control-channel parsing from tcpdump -A output."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ftp_collector.pasv import pasv_port_from_line

_HDR = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) "
    r"(?:\S+\s+(?:In|Out)\s+)?"
    r"IP (?P<src>[\d.]+)\.(?P<src_port>\d+) > (?P<dst>[\d.]+)\.(?P<dst_port>\d+):"
)
_FTP_INLINE = re.compile(r": FTP: (?P<payload>.+)$")


_CMD = re.compile(
    r"^(USER|PASS|QUIT|TYPE|SYST|PWD|CWD|LIST|RETR|STOR|PORT|EPRT)\s*(.*)",
    re.I,
)


@dataclass
class ControlSession:
    session_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    banner_seen: bool = False
    user: str | None = None
    pasv_ports: list[int] = field(default_factory=list)


@dataclass
class ParsedEvent:
    name: str
    session: ControlSession
    details: dict


def client_control_key(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int, cell_ip: str
) -> tuple[str, int, str, int] | None:
    """Normalize to client -> cell:21 for control traffic in either direction."""
    import os

    relax = os.environ.get("AMBER_FTP_RELAX_DST", "0") == "1"
    if dst_port == 21 and (dst_ip == cell_ip or relax):
        return (src_ip, src_port, cell_ip, 21)
    if src_port == 21 and (src_ip == cell_ip or relax):
        return (dst_ip, dst_port, cell_ip, 21)
    return None


class FtpControlParser:
    """Parse FTP lines from tcpdump -A, keyed by control 4-tuple."""

    def __init__(self, cell_ip: str) -> None:
        self.cell_ip = cell_ip
        self._sessions: dict[tuple[str, int, str, int], ControlSession] = {}
        self._active: tuple[str, int, str, int] | None = None

    def register(self, key: tuple[str, int, str, int], session: ControlSession) -> None:
        self._sessions[key] = session

    def handle_line(self, line: str) -> list[ParsedEvent]:
        m = _HDR.match(line)
        if m:
            self._active = client_control_key(
                m.group("src"),
                int(m.group("src_port")),
                m.group("dst"),
                int(m.group("dst_port")),
                self.cell_ip,
            )
            # tcpdump often inlines "FTP: <payload>" on the header line.
            inline = _FTP_INLINE.search(line)
            if inline and self._active is not None:
                session = self._sessions.get(self._active)
                if session is not None:
                    return self._parse_payload(session, inline.group("payload").strip())
            return []

        text = line.strip()
        if not text or text.startswith("0x") or text.startswith("|"):
            return []
        if _HDR.match(text):
            return []

        if self._active is None:
            return []
        session = self._sessions.get(self._active)
        if session is None:
            return []

        return self._parse_payload(session, text)

    def _parse_payload(self, session: ControlSession, text: str) -> list[ParsedEvent]:
        out: list[ParsedEvent] = []

        if text.startswith("220 ") or text.startswith("220-"):
            if not session.banner_seen:
                session.banner_seen = True
                out.append(
                    ParsedEvent("session_open", session, {"banner": text[:120]})
                )
            return out

        port = pasv_port_from_line(text)
        if port is not None:
            session.pasv_ports.append(port)
            out.append(
                ParsedEvent("pasv_open", session, {"pasv_port": port, "line": text[:200]})
            )
            return out

        cmd_m = _CMD.match(text)
        if cmd_m:
            cmd = cmd_m.group(1).upper()
            arg = cmd_m.group(2).strip()
            if cmd in ("PORT", "EPRT"):
                out.append(
                    ParsedEvent(
                        "port_denied",
                        session,
                        {"command": cmd, "argument": arg[:120], "reason": "active_mode_disabled"},
                    )
                )
                return out
            if cmd in ("STOR", "RETR"):
                out.append(
                    ParsedEvent(
                        cmd.lower(),
                        session,
                        {
                            "user": session.user,
                            "path": arg[:256],
                        },
                    )
                )
                return out
            if cmd == "CWD":
                out.append(
                    ParsedEvent(
                        "cwd",
                        session,
                        {"user": session.user, "path": arg[:256], "command": cmd},
                    )
                )
                return out
            if cmd == "LIST":
                out.append(
                    ParsedEvent(
                        "list",
                        session,
                        {"user": session.user, "path": arg[:256] or ".", "command": cmd},
                    )
                )
                return out
            if cmd == "USER":
                session.user = arg
                out.append(ParsedEvent("auth", session, {"user": arg, "stage": "user"}))
            elif cmd == "PASS":
                out.append(
                    ParsedEvent("auth", session, {"user": session.user, "stage": "pass"})
                )
            return out

        if text.startswith("331 "):
            out.append(
                ParsedEvent(
                    "auth", session, {"user": session.user, "stage": "pass_prompt"}
                )
            )
        elif text.startswith("530 "):
            out.append(
                ParsedEvent(
                    "auth",
                    session,
                    {"user": session.user, "ok": False, "reason": "auth_failed"},
                )
            )
        elif text.startswith("230 "):
            out.append(
                ParsedEvent(
                    "auth",
                    session,
                    {"user": session.user, "ok": True, "reason": "login_ok"},
                )
            )
        elif text.startswith("500 ") and "PORT" in text.upper():
            out.append(
                ParsedEvent(
                    "port_denied",
                    session,
                    {"command": "PORT", "reason": "server_reject", "line": text[:200]},
                )
            )
        elif text.startswith("500 ") and "EPRT" in text.upper():
            out.append(
                ParsedEvent(
                    "port_denied",
                    session,
                    {"command": "EPRT", "reason": "server_reject", "line": text[:200]},
                )
            )

        return out
