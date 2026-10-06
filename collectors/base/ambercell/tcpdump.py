"""Line-oriented tcpdump subprocess reader."""

from __future__ import annotations

import logging
import subprocess
import threading
from collections.abc import Callable, Iterator
from typing import TextIO

log = logging.getLogger(__name__)


class TcpdumpStream:
    """Runs tcpdump -l and invokes a callback per stdout line."""

    def __init__(
        self,
        bpf_filter: str,
        *,
        interface: str = "any",
        extra_args: list[str] | None = None,
        on_line: Callable[[str], None] | None = None,
    ) -> None:
        self.bpf_filter = bpf_filter
        self.interface = interface
        self.extra_args = extra_args or []
        self.on_line = on_line
        self._proc: subprocess.Popen[str] | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def _build_cmd(self) -> list[str]:
        return [
            "tcpdump",
            "-i",
            self.interface,
            "-l",
            "-n",
            "-tttt",
            *self.extra_args,
            self.bpf_filter,
        ]

    def start(self) -> None:
        cmd = self._build_cmd()
        log.info("starting tcpdump stream: %s", " ".join(cmd))
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._stop.clear()
        self._thread = threading.Thread(target=self._read_loop, name="tcpdump-stream", daemon=True)
        self._thread.start()
        threading.Thread(
            target=self._drain_stderr, name="tcpdump-stream-stderr", daemon=True
        ).start()

    def _drain_stderr(self) -> None:
        assert self._proc is not None and self._proc.stderr is not None
        for line in self._proc.stderr:
            text = line.rstrip()
            if text:
                log.debug("tcpdump: %s", text)

    def _read_loop(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        fh: TextIO = self._proc.stdout
        for line in fh:
            if self._stop.is_set():
                break
            line = line.rstrip("\n")
            if not line:
                continue
            if self.on_line:
                try:
                    self.on_line(line)
                except Exception:
                    log.exception("tcpdump line handler error")

    def iter_lines(self) -> Iterator[str]:
        assert self._proc is not None and self._proc.stdout is not None
        for line in self._proc.stdout:
            yield line.rstrip("\n")

    def stop(self) -> None:
        self._stop.set()
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None
