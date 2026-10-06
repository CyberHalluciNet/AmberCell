"""Lightweight Telnet cleartext parsing from tcpdump payload lines."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

_HDR = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) "
    r"(?:\S+\s+(?:In|Out)\s+)?"
    r"IP (?P<src>[\d.]+)\.(?P<src_port>\d+) > (?P<dst>[\d.]+)\.(?P<dst_port>\d+):"
)
_PAYLOAD = re.compile(r":\s*(.+)$")
_LOGIN_PROMPT = re.compile(r"login\s*:", re.I)
_PASS_PROMPT = re.compile(r"password\s*:", re.I)
# Structured auth line from amber-login.sh (JSONL-friendly).
_AMBER_AUTH_JSON = re.compile(r"amber-auth-json:\s*(?P<json>\{.+\})", re.I)
_AMBER_AUTH = re.compile(r"amber-auth:\s*user=(?P<user>\S*)\s+pass=(?P<pass>.*)", re.I)
# Secondary command parse (shell prompts + common tooling).
_CMD_LINE = re.compile(
    r"^(?:ambercell[#\$]\s*|[#\$]\s*)?(?P<cmd>(?:wget|curl|nc|ncat|python|python3|perl|bash|sh|chmod|scp|ftp|tftp)\b.*)$",
    re.I,
)
_EGRESS_HINT = re.compile(
    r"\b(?:wget|curl|nc|ncat|ftp)\b.*(?:https?://|ftp://|\d{1,3}(?:\.\d{1,3}){3})",
    re.I,
)


@dataclass
class TelnetSession:
    session_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    opened: bool = False
    user: str | None = None
    transcript: list[str] = field(default_factory=list)
    auth_emitted: bool = False
    cmds: list[str] = field(default_factory=list)


@dataclass
class ParsedEvent:
    name: str
    session: TelnetSession
    details: dict


def client_key(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int, cell_ip: str
) -> tuple[str, int, str, int] | None:
    relax = os.environ.get("AMBER_TELNET_RELAX_DST", "0") == "1"
    if dst_port == 23 and (dst_ip == cell_ip or relax):
        return (src_ip, src_port, cell_ip, 23)
    if src_port == 23 and (src_ip == cell_ip or relax):
        return (dst_ip, dst_port, cell_ip, 23)
    return None


def _printable(text: str) -> str:
    out: list[str] = []
    for ch in text:
        o = ord(ch)
        if ch in "\r\n\t" or 32 <= o < 127:
            out.append(ch)
    return "".join(out)


class TelnetControlParser:
    """Parse cleartext telnet payloads keyed by client -> cell:23."""

    def __init__(self, cell_ip: str) -> None:
        self.cell_ip = cell_ip
        self._sessions: dict[tuple[str, int, str, int], TelnetSession] = {}
        self._active: tuple[str, int, str, int] | None = None
        self._awaiting: dict[tuple[str, int, str, int], str] = {}

    def register(self, key: tuple[str, int, str, int], session: TelnetSession) -> None:
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
                    return self._parse_payload(session, self._active, pm.group(1))
            return []

        text = line.strip()
        if not text or text.startswith("0x") or text.startswith("|"):
            return []
        if self._active is None:
            return []
        session = self._sessions.get(self._active)
        if session is None:
            return []
        return self._parse_payload(session, self._active, text)

    def _parse_payload(
        self,
        session: TelnetSession,
        key: tuple[str, int, str, int],
        raw: str,
    ) -> list[ParsedEvent]:
        out: list[ParsedEvent] = []
        text = _printable(raw).strip()
        if not text:
            return out

        session.transcript.append(text)

        if not session.opened:
            session.opened = True
            out.append(
                ParsedEvent(
                    "session_open",
                    session,
                    {"banner": text[:120]},
                )
            )

        auth_json = _AMBER_AUTH_JSON.search(text)
        if auth_json and not session.auth_emitted:
            user = session.user
            ok = True
            try:
                payload = json.loads(auth_json.group("json"))
                if isinstance(payload, dict):
                    user = str(payload.get("user") or user or "")
                    ok = bool(payload.get("ok", True))
            except json.JSONDecodeError:
                pass
            session.user = user
            session.auth_emitted = True
            out.append(
                ParsedEvent(
                    "auth",
                    session,
                    {
                        "user": user,
                        "ok": ok,
                        "reason": "login_ok" if ok else "auth_failed",
                        "stage": "complete",
                        "auth_format": "json",
                    },
                )
            )
            return out

        auth_m = _AMBER_AUTH.search(text)
        if auth_m and not session.auth_emitted:
            user = auth_m.group("user") or session.user
            session.user = user
            session.auth_emitted = True
            out.append(
                ParsedEvent(
                    "auth",
                    session,
                    {
                        "user": user,
                        "ok": True,
                        "reason": "login_ok",
                        "stage": "complete",
                        "auth_format": "kv",
                    },
                )
            )
            return out

        if _LOGIN_PROMPT.search(text):
            self._awaiting[key] = "user"
            return out

        if _PASS_PROMPT.search(text):
            self._awaiting[key] = "pass"
            return out

        stage = self._awaiting.get(key)
        if stage == "user" and text and not _LOGIN_PROMPT.search(text):
            session.user = text.split()[0][:64]
            out.append(
                ParsedEvent(
                    "auth",
                    session,
                    {"user": session.user, "stage": "user"},
                )
            )
            self._awaiting[key] = "pass_pending"
            return out

        if stage in ("pass", "pass_pending") and text and not _PASS_PROMPT.search(text):
            if not session.auth_emitted:
                session.auth_emitted = True
                out.append(
                    ParsedEvent(
                        "auth",
                        session,
                        {
                            "user": session.user,
                            "stage": "pass",
                            "ok": True,
                            "reason": "login_ok",
                        },
                    )
                )
            self._awaiting.pop(key, None)
            return out

        # Secondary cmd parse (never replaces raw transcript).
        cmd_m = _CMD_LINE.match(text)
        if cmd_m:
            cmd = cmd_m.group("cmd")[:512]
            session.cmds.append(cmd)
            details: dict = {
                "user": session.user,
                "command": cmd,
                "line": text[:512],
            }
            out.append(ParsedEvent("cmd", session, details))
            if _EGRESS_HINT.search(cmd):
                out.append(
                    ParsedEvent(
                        "egress_staging",
                        session,
                        {
                            "user": session.user,
                            "command": cmd,
                            "reason": "download_execute_hint",
                            "correlate": "egress",
                        },
                    )
                )
            return out

        return out
