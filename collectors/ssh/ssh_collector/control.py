"""SSH session parse — sshd FIFO lines + optional cleartext hints from tcpdump."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

_ACCEPT = re.compile(r"Accepted\s+(?:password|keyboard-interactive)\s+for\s+(?P<user>\S+)", re.I)
_FAILED = re.compile(r"Failed\s+password\s+for\s+(?:invalid user\s+)?(?P<user>\S+)", re.I)
_SSH_JSON = re.compile(r"amber-ssh-json:(?P<json>\{.+)", re.I)
_EGRESS = re.compile(r"\b(?:wget|curl|scp|sftp)\b", re.I)
_HDR = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) "
    r"(?:\S+\s+(?:In|Out)\s+)?"
    r"IP (?P<src>[\d.]+)\.(?P<src_port>\d+) > (?P<dst>[\d.]+)\.(?P<dst_port>\d+):"
)


@dataclass
class SshSession:
    session_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    user: str | None = None
    transcript: list[str] = field(default_factory=list)
    opened: bool = False
    auth_emitted: bool = False


@dataclass
class ParsedEvent:
    name: str
    session: SshSession
    details: dict


class SshControlParser:
    def __init__(self, cell_ip: str) -> None:
        self.cell_ip = cell_ip
        self._by_client: dict[tuple[str, int], SshSession] = {}
        self._default: SshSession | None = None

    def register(self, session: SshSession) -> None:
        key = (session.src_ip, session.src_port)
        self._by_client[key] = session
        if self._default is None:
            self._default = session

    def _session_for_log(self) -> SshSession | None:
        if self._default is not None:
            return self._default
        if self._by_client:
            return next(iter(self._by_client.values()))
        return None

    def handle_line(self, line: str) -> list[ParsedEvent]:
        out: list[ParsedEvent] = []
        text = line.strip()
        if not text:
            return out

        m = _ACCEPT.search(text)
        if m:
            sess = self._session_for_log()
            if sess is None:
                return out
            user = m.group("user")
            sess.user = user
            sess.opened = True
            if not sess.auth_emitted:
                sess.auth_emitted = True
                out.append(
                    ParsedEvent(
                        "auth",
                        sess,
                        {"user": user, "ok": True, "reason": "password_accepted"},
                    )
                )
            return out

        m = _FAILED.search(text)
        if m:
            sess = self._session_for_log()
            if sess is None:
                return out
            user = m.group("user")
            out.append(
                ParsedEvent(
                    "auth",
                    sess,
                    {"user": user, "ok": False, "reason": "bad_password"},
                )
            )
            return out

        jm = _SSH_JSON.search(text)
        if jm:
            sess = self._session_for_log()
            if sess is None:
                return out
            try:
                payload = json.loads(jm.group("json"))
            except json.JSONDecodeError:
                return out
            ev = payload.get("event")
            if ev == "session_open":
                sess.opened = True
                out.append(ParsedEvent("session_open", sess, payload))
            elif ev == "pty_line":
                line_txt = str(payload.get("line", ""))
                sess.transcript.append(line_txt)
                if _EGRESS.search(line_txt):
                    out.append(
                        ParsedEvent(
                            "egress_staging",
                            sess,
                            {"command": line_txt, "correlate": "ssh_pty"},
                        )
                    )
                else:
                    out.append(ParsedEvent("cmd", sess, {"command": line_txt}))
            elif ev == "session_close":
                out.append(ParsedEvent("session_close", sess, payload))
            return out

        hm = _HDR.match(text)
        if hm and int(hm.group("dst_port")) == 22:
            # Banner/version hints from tcpdump (encrypted channel — metadata only).
            sess = self._session_for_log()
            if sess is not None:
                out.append(ParsedEvent("banner", sess, {"line": text[:120]}))
        return out
