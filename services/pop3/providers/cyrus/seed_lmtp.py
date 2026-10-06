#!/usr/bin/env python3
"""Inject AmberCell mbox seeds into Cyrus via LMTP (unix socket)."""
from __future__ import annotations

import socket
import sys
from pathlib import Path


def mbox_to_rfc822(path: Path, user: str) -> bytes:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    if lines and lines[0].startswith("From "):
        lines = lines[1:]
    # Ensure a From: header — Cyrus may store/discard oddly without it.
    has_from = any(l.lower().startswith("from:") for l in lines)
    if not has_from:
        lines.insert(0, f"From: seed@corp.example.net")
        if not any(l.lower().startswith("to:") for l in lines):
            lines.insert(1, f"To: {user}@corp.example.net")
    # LMTP DATA: double-dot escape; CRLF line endings.
    out: list[str] = []
    for line in lines:
        if line.startswith("."):
            line = "." + line
        out.append(line)
    return ("\r\n".join(out) + "\r\n.\r\n").encode("utf-8", errors="replace")


def lmtp_deliver(sock_path: str, user: str, payload: bytes) -> None:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(sock_path)

    def recv() -> bytes:
        return s.recv(8192)

    def cmd(line: str) -> bytes:
        s.sendall((line + "\r\n").encode())
        return recv()

    recv()
    cmd("LHLO ambercell")
    cmd("MAIL FROM:<seed@corp.example.net>")
    resp = cmd(f"RCPT TO:<{user}>")
    if not resp.startswith(b"250"):
        raise RuntimeError(f"RCPT failed for {user}: {resp!r}")
    cmd("DATA")
    s.sendall(payload)
    resp = recv()
    if not resp.startswith(b"250"):
        raise RuntimeError(f"DATA failed for {user}: {resp!r}")
    cmd("QUIT")
    s.close()


def main() -> int:
    seeds_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "/opt/amber-seeds")
    sock = sys.argv[2] if len(sys.argv) > 2 else "/run/cyrus/socket/lmtp"
    users = ["exec", "finance", "hr", "it", "canary"]
    for user in users:
        path = seeds_dir / f"{user}.mbox"
        if not path.is_file():
            continue
        try:
            lmtp_deliver(sock, user, mbox_to_rfc822(path, user))
            print(f"seeded {user}", flush=True)
        except Exception as exc:  # noqa: BLE001 — lab seed best-effort
            print(f"seed skip {user}: {exc}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
