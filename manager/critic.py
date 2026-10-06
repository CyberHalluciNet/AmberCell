#!/usr/bin/env python3
"""
Deterministic decision critic (Stage-3): fail closed on missing/stale evidence refs.

Validates decision.v1 records against closed JSONL/event index under AMBER_EVIDENCE_ROOT.
Never mutates evidence. Exit 0 when all refs resolve; non-zero otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

DEFAULT_EVIDENCE_ROOT = "/var/ambercell"


def evidence_root() -> Path:
    import os

    return Path(os.environ.get("AMBER_EVIDENCE_ROOT", DEFAULT_EVIDENCE_ROOT))


def load_event_index(root: Path) -> dict[str, dict[str, Any]]:
    """Index event_id → record from closed + active JSONL under jsonl/."""
    index: dict[str, dict[str, Any]] = {}
    jsonl_root = root / "jsonl"
    if not jsonl_root.is_dir():
        return index
    for path in sorted(jsonl_root.rglob("*.jsonl*")):
        if path.name.endswith(".lock"):
            continue
        if path.suffix == ".active" or path.name.endswith(".jsonl") or ".jsonl." in path.name:
            _ingest_file(path, index)
    return index


def _ingest_file(path: Path, index: dict[str, dict[str, Any]]) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        eid = obj.get("event_id")
        if isinstance(eid, str) and eid:
            index[eid] = obj


def load_cell_state(root: Path, svc: str) -> dict[str, Any] | None:
    state_path = root / "state" / f"{svc}.json"
    if not state_path.is_file():
        return None
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def svc_from_cell_id(cell_id: str) -> str:
    if cell_id.startswith("ftp-"):
        return "ftp"
    if cell_id.startswith("telnet-"):
        return "telnet"
    if cell_id.startswith("smtp-"):
        return "smtp"
    if cell_id.startswith("pop3-"):
        return "pop3"
    return ""


def validate_decision(dec: dict[str, Any], index: dict[str, dict[str, Any]], root: Path) -> list[str]:
    errors: list[str] = []
    if dec.get("schema_version") != "decision.v1":
        errors.append("schema_version must be decision.v1")
    for field in (
        "decision_id",
        "decision_type",
        "evidence_refs",
        "policy_refs",
        "decision_version",
        "cell_id",
    ):
        if field not in dec or dec[field] in (None, "", []):
            errors.append(f"missing required field {field!r}")

    refs = dec.get("evidence_refs") or []
    if not isinstance(refs, list):
        errors.append("evidence_refs must be a list")
        refs = []

    for ref in refs:
        if not isinstance(ref, str) or not ref:
            errors.append("evidence_refs contains invalid entry")
            continue
        if ref not in index:
            errors.append(f"evidence ref {ref!r} not found in jsonl index (stale/hallucinated)")

    cell_id = str(dec.get("cell_id") or "")
    svc = svc_from_cell_id(cell_id)
    if svc:
        st = load_cell_state(root, svc)
        if st is None:
            errors.append(f"cell state missing for svc {svc!r} (fail closed)")
        elif not st.get("provider_id"):
            errors.append(f"cell state for {svc!r} missing provider_id")

    policy_refs = dec.get("policy_refs") or []
    if not policy_refs:
        errors.append("policy_refs empty")
    if not dec.get("decision_version"):
        errors.append("decision_version empty")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="AmberCell deterministic decision critic")
    parser.add_argument(
        "decision",
        nargs="?",
        help="Path to decision JSON file (default: read stdin)",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read decision JSON from stdin",
    )
    args = parser.parse_args()

    if args.stdin or not args.decision:
        raw = sys.stdin.read()
    else:
        raw = Path(args.decision).read_text(encoding="utf-8")

    try:
        dec = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"critic: invalid JSON: {exc}", file=sys.stderr)
        return 2

    root = evidence_root()
    index = load_event_index(root)
    errors = validate_decision(dec, index, root)
    if errors:
        for e in errors:
            print(f"critic: REJECT: {e}", file=sys.stderr)
        return 1
    print("critic: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
