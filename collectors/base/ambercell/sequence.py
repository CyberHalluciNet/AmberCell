"""Monotonic seq_id per collector process."""

from __future__ import annotations

import threading


class Sequence:
    def __init__(self, start: int = 0) -> None:
        self._lock = threading.Lock()
        self._next = start

    def next_id(self) -> int:
        with self._lock:
            n = self._next
            self._next += 1
            return n
