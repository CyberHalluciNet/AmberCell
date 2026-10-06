"""Append-only JSONL writers for raw flows and normalized events."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, TextIO

from ambercell.sequence import Sequence
from ambercell.validate import validate_event, validate_rawflow
from ambercell.paths import ROOT
from ambercell.vault import active_jsonl_path, ensure_lab_symlink, ensure_vault_notes


def _use_active_segments() -> bool:
    import os

    v = os.environ.get("AMBER_JSONL_ACTIVE", "1").strip().lower()
    return v not in ("0", "false", "no", "off")


class JsonlWriter:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        ensure_vault_notes(ROOT)
        logical = path
        if _use_active_segments():
            self._path = active_jsonl_path(path)
            ensure_lab_symlink(logical, self._path)
        else:
            self._path = path
        self._lock = threading.Lock()
        self._fh: TextIO = self._path.open("a", encoding="utf-8", buffering=1)

    def write(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()

    def close(self) -> None:
        with self._lock:
            self._fh.close()


class RawFlowEmitter:
    def __init__(self, path: Path, sequence: Sequence) -> None:
        self._writer = JsonlWriter(path)
        self._seq = sequence

    def emit(self, record: dict[str, Any]) -> dict[str, Any]:
        record = dict(record)
        record.setdefault("schema_version", "rawflow.v1")
        record.setdefault("seq_id", self._seq.next_id())
        validate_rawflow(record)
        self._writer.write(record)
        return record

    def close(self) -> None:
        self._writer.close()


class EventEmitter:
    def __init__(self, path: Path, sequence: Sequence) -> None:
        self._writer = JsonlWriter(path)
        self._seq = sequence

    def emit(self, record: dict[str, Any]) -> dict[str, Any]:
        record = dict(record)
        record.setdefault("schema_version", "event.v1")
        record.setdefault("seq_id", self._seq.next_id())
        validate_event(record)
        self._writer.write(record)
        return record

    def close(self) -> None:
        self._writer.close()
