#!/usr/bin/env python3
"""Close active JSONL segments for a service (rebuild evidence flush)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ambercell.paths import jsonl_dir, raw_flows_dir
from ambercell.vault import active_jsonl_path, close_active_segment, ensure_vault_notes
from ambercell.paths import ROOT


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--svc", required=True)
    args = parser.parse_args()
    svc = args.svc
    ensure_vault_notes(ROOT)
    closed = 0
    for base in (
        jsonl_dir(svc) / "events.jsonl",
        raw_flows_dir(svc) / "flows.jsonl",
    ):
        active = active_jsonl_path(base)
        if close_active_segment(active, archive=True):
            closed += 1
    print(f"vault_flush: svc={svc} closed_segments={closed}\n", end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
