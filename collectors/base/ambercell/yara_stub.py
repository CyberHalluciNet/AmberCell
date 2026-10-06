"""Async YARA / ClamAV hook (Stage-3): tags only, never blocks capture.

Scan work runs in the artifact UDS worker thread pool. Raw JSONL/pcap writes
are never gated on scan completion.
"""

from __future__ import annotations

import logging
import os
import queue
import threading
from pathlib import Path

log = logging.getLogger("ambercell.yara_stub")

_SCAN_Q: queue.Queue[tuple[Path, "FutureTags"]] | None = None
_WORKER: threading.Thread | None = None


class FutureTags:
    def __init__(self) -> None:
        self._tags: list[str] = []
        self._done = threading.Event()

    def set(self, tags: list[str]) -> None:
        self._tags = list(tags)
        self._done.set()

    def wait(self, timeout: float = 30.0) -> list[str]:
        self._done.wait(timeout)
        return list(self._tags)


def _ensure_worker() -> queue.Queue[tuple[Path, FutureTags]]:
    global _SCAN_Q, _WORKER
    if _SCAN_Q is not None:
        return _SCAN_Q
    _SCAN_Q = queue.Queue()

    def _loop() -> None:
        assert _SCAN_Q is not None
        while True:
            item = _SCAN_Q.get()
            if item is None:
                break
            path, fut = item
            try:
                fut.set(_scan_sync(path))
            except Exception:  # noqa: BLE001
                log.exception("yara worker failed path=%s", path)
                fut.set([])

    _WORKER = threading.Thread(target=_loop, name="yara-async", daemon=True)
    _WORKER.start()
    return _SCAN_Q


def _scan_sync(path: Path) -> list[str]:
    if not path.is_file():
        return []
    tags: list[str] = []
    if os.environ.get("AMBER_YARA_RULES"):
        log.debug("yara rules configured; stub tags only path=%s", path)
        if path.suffix.lower() in (".exe", ".elf", ".sh"):
            tags.append("yara:stub-suspicious-ext")
    if os.environ.get("AMBER_CLAMAV_SOCKET"):
        log.debug("clamav socket configured; stub clean path=%s", path)
        tags.append("clamav:stub-clean")
    return tags


def scan_async(path: Path) -> FutureTags:
    """Queue scan; caller may wait briefly in artifact worker (not on capture hot path)."""
    fut = FutureTags()
    if not path.is_file():
        fut.set([])
        return fut
    _ensure_worker().put((path, fut))
    return fut


def scan_stub(path: Path) -> list[str]:
    """Wait briefly for queued scan tags (artifact worker only — never capture).

    Timeout is short so a missing/slow real scanner cannot stall the UDS worker.
    Capture/JSONL writers never call this helper.
    """
    timeout = 0.5
    try:
        timeout = float(os.environ.get("AMBER_YARA_WAIT_SEC", "0.5"))
    except ValueError:
        timeout = 0.5
    return scan_async(path).wait(timeout=max(0.05, timeout))
