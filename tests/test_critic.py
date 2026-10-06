#!/usr/bin/env python3
"""Critic unit tests (fail closed on bad evidence refs)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def run_critic(evidence_root: Path, decision: dict) -> int:
    dec_path = evidence_root / "decision.json"
    dec_path.write_text(json.dumps(decision), encoding="utf-8")
    # seed event index
    ev_dir = evidence_root / "jsonl" / "ftp"
    ev_dir.mkdir(parents=True, exist_ok=True)
    (ev_dir / "events.jsonl").write_text(
        json.dumps(
            {
                "schema_version": "event.v1",
                "seq_id": 1,
                "event_id": "evt_ok",
                "ts": "2026-10-05T08:32:12.200000000Z",
                "svc": "ftp",
                "event": "auth",
                "session_id": "fp_x",
                "cell_id": "ftp-cell-01",
                "collector_id": "ftp-collector-a",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (evidence_root / "state").mkdir(parents=True, exist_ok=True)
    (evidence_root / "state" / "ftp.json").write_text(
        json.dumps({"provider_id": "vsftpd", "image_digest": "sha256:abc"}),
        encoding="utf-8",
    )
    env = {**os.environ, "AMBER_EVIDENCE_ROOT": str(evidence_root)}
    proc = subprocess.run(
        ["python3", str(REPO / "manager" / "critic.py"), str(dec_path)],
        env=env,
        capture_output=True,
        text=True,
    )
    return proc.returncode


def base_decision(**overrides):
    d = {
        "schema_version": "decision.v1",
        "decision_id": "dec_test",
        "ts": "2026-10-05T08:33:00.000000000Z",
        "scope": "session",
        "target_id": "fp_x",
        "cell_id": "ftp-cell-01",
        "decision_type": "alert",
        "confidence": "medium",
        "evidence_refs": ["evt_ok"],
        "policy_refs": ["credential-abuse.v1"],
        "executor_status": "pending",
        "decision_version": "2026-10-05.1",
        "source": "deterministic_rule",
    }
    d.update(overrides)
    return d


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        if run_critic(root, base_decision()) != 0:
            print("critic should accept valid decision", file=sys.stderr)
            return 1
        if run_critic(root, base_decision(evidence_refs=["evt_missing"])) == 0:
            print("critic should reject missing evidence ref", file=sys.stderr)
            return 1
    print("critic tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
