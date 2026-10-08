"""Parse IMAP lines from tcpdump -A payload (tcp/143): tags, LOGIN creds, banners."""

from __future__ import annotations

import re

from ambercell.timeutil import utc_now_rfc3339_nano

# Client command: "a001 LOGIN user pass" / "a001 CAPABILITY"
_CMD = re.compile(
    r"^[A-Za-z0-9.]+ (LOGIN|AUTHENTICATE|CAPABILITY|LIST|SELECT|EXAMINE|FETCH|STORE|STATUS|APPEND|IDLE|NOOP|ID|LOGOUT|STARTTLS)(?:\s+(.*))?$"
)
# Untagged server lines: "* OK ...", "* CAPABILITY ...", "* NO/BAD ..."
_SRV = re.compile(r"^\* (OK|NO|BAD|BYE|PREAUTH|CAPABILITY)(?:\s+(.*))?$")
# LOGIN arguments: quoted or bare user + password.
_CRED = re.compile(r'^(?:"([^"]*)"|(\S+))\s+(?:"([^"]*)"|(\S+))$')


def parse_imap_line(line: str) -> dict | None:
    text = line.rstrip("\r").lstrip()
    if not text:
        return None
    ts = utc_now_rfc3339_nano()
    m = _CMD.match(text)
    if m is not None:
        cmd, args = m.group(1), (m.group(2) or "").strip()
        rec = {"ts": ts, "raw": text, "event": "imap.command", "command": cmd, "argument": args[:120]}
        if cmd == "LOGIN":
            rec["event"] = "imap.login"
            cm = _CRED.match(args)
            if cm is not None:
                rec["user"] = next(g for g in cm.groups()[:2] if g is not None)
                rec["password"] = next(g for g in cm.groups()[2:] if g is not None)
        elif cmd == "AUTHENTICATE":
            rec["event"] = "imap.auth_attempt"
        return rec
    m = _SRV.match(text)
    if m is not None:
        return {
            "ts": ts,
            "raw": text,
            "event": "imap.banner",
            "response": m.group(1),
            "detail": (m.group(2) or "")[:120],
        }
    return None
