#!/usr/bin/env python3
"""Heuristic campaign aggregation (Stage-4): shared creds, hashes, subnets, timing."""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict
from pathlib import Path


def evidence_root() -> Path:
    return Path(os.environ.get("AMBER_EVIDENCE_ROOT", "/var/ambercell"))


def load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def aggregate(svc: str = "") -> dict:
    jsonl_root = evidence_root() / "jsonl"
    by_user: dict[str, int] = defaultdict(int)
    by_src: dict[str, int] = defaultdict(int)
    for path in jsonl_root.rglob("*.jsonl*"):
        if path.name.endswith(".active"):
            continue
        if svc and f"/{svc}/" not in path.as_posix():
            continue
        for row in load_jsonl(path):
            user = row.get("user") or row.get("username")
            if user:
                by_user[str(user)] += 1
            src = row.get("src_ip")
            if src:
                by_src[str(src)] += 1
    return {
        "schema_version": "campaign-heuristic.v1",
        "top_users": sorted(by_user.items(), key=lambda x: -x[1])[:10],
        "top_src_ips": sorted(by_src.items(), key=lambda x: -x[1])[:10],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--svc", default="")
    args = parser.parse_args()
    print(json.dumps(aggregate(args.svc), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
