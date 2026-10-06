"""Rotating pcap capture via tcpdump subprocess."""

from __future__ import annotations

import logging
import signal
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


@dataclass
class PcapRingConfig:
    interface: str = "any"
    bpf_filter: str = "tcp"
    rotate_seconds: int = 3600
    rotate_files: int = 5
    snaplen: int = 65535


class PcapRingWriter:
    """Runs tcpdump with -G/-W ring rotation under a directory."""

    def __init__(self, ring_dir: Path, config: PcapRingConfig) -> None:
        self.ring_dir = ring_dir
        self.config = config
        self._proc: subprocess.Popen[bytes] | None = None
        self._prefix = "capture"
        self._watch_stop = threading.Event()
        self._watch_thread: threading.Thread | None = None

    @property
    def write_path(self) -> Path:
        """tcpdump -w argument (basename; tcpdump appends rotation suffix)."""
        return self.ring_dir / f"{self._prefix}.pcap"

    def current_pcap_ref(self, svc: str) -> str:
        """Relative pcap_ref for evidence records (newest ring segment if known)."""
        segments = sorted(self.ring_dir.glob(f"{self._prefix}.pcap*"))
        if segments:
            name = segments[-1].name
            return f"pcap/{svc}/ring/{name}"
        return f"pcap/{svc}/ring/{self._prefix}.pcap0"

    def start(self) -> None:
        self.ring_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            "tcpdump",
            "-i",
            self.config.interface,
            "-n",
            "-U",
            "-s",
            str(self.config.snaplen),
            "-G",
            str(self.config.rotate_seconds),
            "-W",
            str(self.config.rotate_files),
            "-w",
            str(self.write_path),
            self.config.bpf_filter,
        ]
        log.info("starting pcap ring: %s", " ".join(cmd))
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        self._watch_stop.clear()
        self._watch_thread = threading.Thread(
            target=self._drain_stderr, name="pcap-ring-stderr", daemon=True
        )
        self._watch_thread.start()

    def _drain_stderr(self) -> None:
        assert self._proc is not None and self._proc.stderr is not None
        for line in self._proc.stderr:
            text = line.decode("utf-8", errors="replace").rstrip()
            if text:
                log.debug("tcpdump: %s", text)
        self._watch_stop.set()

    def stop(self) -> None:
        if self._proc is None:
            return
        if self._proc.poll() is None:
            self._proc.send_signal(signal.SIGTERM)
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=5)
        self._watch_stop.set()
        if self._watch_thread is not None:
            self._watch_thread.join(timeout=2)
        self._proc = None

    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None
