"""In-collector upload directory watch → artifact UDS enqueue.

Runs inside the collector mount namespace (shared volume with *-hi uploads).
Does not use host recursive inotify on /var/ambercell.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path
from typing import Callable

log = logging.getLogger("ambercell.upload_watch")


class UploadWatch:
    """Poll/watch a shared upload directory and notify on new files."""

    def __init__(
        self,
        watch_dir: str,
        on_path: Callable[[str], None],
        *,
        interval_s: float = 2.0,
    ) -> None:
        self.watch_dir = Path(watch_dir)
        self.on_path = on_path
        self.interval_s = interval_s
        self._seen: set[str] = set()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        # Seed known files so bootstrap README is not treated as attacker upload.
        for p in self.watch_dir.rglob("*"):
            if p.is_file():
                self._seen.add(str(p))
        self._thread = threading.Thread(target=self._loop, name="upload-watch", daemon=True)
        self._thread.start()
        log.info("upload watch on %s (interval=%.1fs)", self.watch_dir, self.interval_s)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._scan()
            except Exception:  # noqa: BLE001
                log.exception("upload watch scan failed")
            self._stop.wait(self.interval_s)

    def _scan(self) -> None:
        if not self.watch_dir.is_dir():
            return
        for p in self.watch_dir.rglob("*"):
            if not p.is_file():
                continue
            key = str(p)
            if key in self._seen:
                continue
            # Wait briefly for writer to finish.
            try:
                size1 = p.stat().st_size
                time.sleep(0.2)
                size2 = p.stat().st_size
                if size1 != size2:
                    continue
            except OSError:
                continue
            self._seen.add(key)
            name = p.name
            if name.startswith("README"):
                continue
            log.info("new upload path %s", key)
            self.on_path(key)


def default_upload_dir() -> str:
    return os.environ.get("AMBER_FTP_UPLOAD_DIR", "/mnt/hi-uploads")
