#!/usr/bin/env python3
"""Uncertainty review queue: enqueue low/borderline AI decisions for operator review."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def evidence_root() -> Path:
    return Path(os.environ.get("AMBER_EVIDENCE_ROOT", "/var/ambercell"))


def should_review(decision: dict) -> bool:
    conf = (decision.get("confidence") or "").lower()
    dtype = decision.get("decision_type") or ""
    if conf not in ("low", "medium"):
        return False
    return dtype in ("alert", "quarantine_then_rebuild", "snapshot_then_rebuild")


def scan_decisions(svc_filter: str = "") -> list[Path]:
    root = evidence_root() / "decisions"
    if not root.is_dir():
        return []
    out: list[Path] = []
    for path in root.rglob("*.json"):
        if svc_filter and f"/{svc_filter}/" not in path.as_posix() and svc_filter not in path.name:
            continue
        out.append(path)
    return out


def enqueue(path: Path) -> Path | None:
    raw = path.read_text(encoding="utf-8")
    decision = json.loads(raw)
    if not should_review(decision):
        return None
    decision_id = decision.get("decision_id") or path.stem
    pending = evidence_root() / "state" / "review" / "pending"
    pending.mkdir(parents=True, exist_ok=True)
    item = {
        "schema_version": "review-item.v1",
        "item_id": decision_id,
        "decision_id": decision_id,
        "svc": decision.get("cell_id", ""),
        "confidence": decision.get("confidence"),
        "reason_summary": decision.get("reason_summary"),
        "status": "pending",
        "source_path": str(path),
    }
    out = pending / f"{decision_id}.json"
    out.write_text(json.dumps(item, indent=2) + "\n", encoding="utf-8")
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--svc", default="", help="optional svc filter")
    parser.add_argument("--scan", action="store_true", help="scan decisions/ and enqueue borderline items")
    args = parser.parse_args()
    if not args.scan:
        parser.error("use --scan to populate the review queue")
    count = 0
    for path in scan_decisions(args.svc):
        if enqueue(path):
            count += 1
    print(f"enqueued {count} review item(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
