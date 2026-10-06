#!/usr/bin/env python3
"""Out-of-band canary monitor stub: correlate canary prefix hits with session/cell IDs."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

PREFIX = "AMBERCANARY_"


def evidence_root() -> Path:
    return Path(os.environ.get("AMBER_EVIDENCE_ROOT", "/var/ambercell"))


def scan_canary_values(svc: str = "") -> list[dict]:
    root = evidence_root() / "state" / "canaries"
    hits: list[dict] = []
    if not root.is_dir():
        return hits
    for path in root.rglob("*.txt"):
        if svc and f"/{svc}/" not in path.as_posix():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if PREFIX in text:
            hits.append(
                {
                    "svc": path.parent.name,
                    "path": str(path),
                    "canary_prefix": PREFIX,
                    "note": "monitor JSONL/transcripts for RETR/STOR/auth using this value",
                }
            )
    return hits


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--svc", default="")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    hits = scan_canary_values(args.svc)
    if args.json:
        print(json.dumps(hits, indent=2))
    else:
        for h in hits:
            print(f"{h['svc']}\t{h['path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
