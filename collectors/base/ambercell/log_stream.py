"""FIFO/UDS log streaming into collectors (Stage-2 mail)."""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable

log = logging.getLogger("ambercell.log_stream")


def start_fifo_reader(
    fifo_path: str,
    on_line: Callable[[str], None],
    stop: threading.Event,
) -> threading.Thread:
    """Block-read lines from a named pipe; reconnect if the writer restarts."""

    def _loop() -> None:
        while not stop.is_set():
            if not fifo_path or not os.path.exists(fifo_path):
                stop.wait(1.0)
                continue
            try:
                with open(fifo_path, "r", encoding="utf-8", errors="replace") as fh:
                    log.info("log fifo open %s", fifo_path)
                    while not stop.is_set():
                        line = fh.readline()
                        if not line:
                            break
                        on_line(line.rstrip("\n"))
            except OSError as exc:
                log.debug("fifo read: %s", exc)
            stop.wait(0.5)

    t = threading.Thread(target=_loop, name=f"fifo-{os.path.basename(fifo_path)}", daemon=True)
    t.start()
    return t
