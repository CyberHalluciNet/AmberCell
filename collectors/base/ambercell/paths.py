"""Evidence directory layout under /var/ambercell."""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(os.environ.get("AMBER_EVIDENCE_ROOT", "/var/ambercell"))


def svc_root(svc: str) -> Path:
    return ROOT / svc


def raw_flows_dir(svc: str) -> Path:
    return ROOT / "raw-flows" / svc


def jsonl_dir(svc: str) -> Path:
    return ROOT / "jsonl" / svc


def pcap_dir(svc: str) -> Path:
    return ROOT / "pcap" / svc


def pcap_ring_dir(svc: str) -> Path:
    return pcap_dir(svc) / "ring"


def state_dir() -> Path:
    return ROOT / "state"


def state_file(svc: str) -> Path:
    return state_dir() / f"{svc}.json"


def transcripts_dir(svc: str) -> Path:
    return ROOT / "transcripts" / svc


def ensure_svc_dirs(svc: str) -> None:
    for d in (
        raw_flows_dir(svc),
        jsonl_dir(svc),
        pcap_ring_dir(svc),
        transcripts_dir(svc),
        state_dir(),
    ):
        d.mkdir(parents=True, exist_ok=True)
