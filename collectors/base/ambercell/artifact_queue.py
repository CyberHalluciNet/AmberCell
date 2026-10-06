"""Collector-local UDS artifact queue (no host recursive inotify).

HI cells never see this socket. A companion process (or the collector itself)
enqueues path notifications; workers hash bytes and emit artifact.v1 records.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import secrets
import socket
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ambercell.timeutil import utc_now_rfc3339_nano
from ambercell.yara_stub import scan_async

log = logging.getLogger("ambercell.artifact_queue")

DEFAULT_SOCK = "/var/ambercell/run/artifact.sock"


@dataclass
class ArtifactJob:
    svc: str
    session_id: str
    kind: str  # upload | download | other
    path: str
    provider_id: str
    cell_id: str
    collector_id: str
    filename: str = ""
    resolve_roots: tuple[str, ...] = ()


def sha256_file(path: Path, *, max_bytes: int = 64 * 1024 * 1024) -> tuple[str, int]:
    """Hash file contents (cap read at max_bytes; report full st_size)."""
    h = hashlib.sha256()
    size = path.stat().st_size
    read = 0
    with path.open("rb") as fh:
        while read < max_bytes:
            chunk = fh.read(min(1024 * 1024, max_bytes - read))
            if not chunk:
                break
            h.update(chunk)
            read += len(chunk)
    if size > max_bytes:
        # Distinguish truncated hashes from full-file digests.
        h.update(f":truncated:{size}".encode())
    return h.hexdigest(), size


def resolve_path(rel_or_abs: str, roots: tuple[str, ...]) -> Path | None:
    candidate = Path(rel_or_abs)
    if candidate.is_file():
        return candidate
    name = candidate.name
    for root in roots:
        base = Path(root)
        # Try as-is under root, then basename search one level deep.
        direct = base / rel_or_abs.lstrip("/")
        if direct.is_file():
            return direct
        named = base / name
        if named.is_file():
            return named
        if base.is_dir():
            for child in base.rglob(name):
                if child.is_file():
                    return child
    return None


class ArtifactQueue:
    """Unix-datagram / stream queue + worker that writes artifact JSONL."""

    def __init__(
        self,
        *,
        sock_path: str,
        write_record: Callable[[dict], None],
        next_seq: Callable[[], int],
    ) -> None:
        self.sock_path = sock_path
        self.write_record = write_record
        self.next_seq = next_seq
        self._q: queue.Queue[ArtifactJob | None] = queue.Queue()
        self._stop = threading.Event()
        self._server: socket.socket | None = None
        self._threads: list[threading.Thread] = []

    def enqueue(self, job: ArtifactJob) -> None:
        self._q.put(job)

    def start(self) -> None:
        Path(self.sock_path).parent.mkdir(parents=True, exist_ok=True)
        if os.path.exists(self.sock_path):
            os.unlink(self.sock_path)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(self.sock_path)
        try:
            os.chmod(self.sock_path, 0o660)
        except OSError as exc:
            # Docker Desktop / virtiofs bind mounts often reject chmod on UDS (EINVAL).
            log.warning("chmod %s: %s (continuing)", self.sock_path, exc)
        srv.listen(16)
        srv.settimeout(1.0)
        self._server = srv

        t_accept = threading.Thread(target=self._accept_loop, name="artifact-uds", daemon=True)
        t_work = threading.Thread(target=self._worker_loop, name="artifact-worker", daemon=True)
        t_accept.start()
        t_work.start()
        self._threads = [t_accept, t_work]
        log.info("artifact UDS listening at %s", self.sock_path)

    def stop(self) -> None:
        self._stop.set()
        self._q.put(None)
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
        if os.path.exists(self.sock_path):
            try:
                os.unlink(self.sock_path)
            except OSError:
                pass
        for t in self._threads:
            t.join(timeout=2.0)

    def _accept_loop(self) -> None:
        assert self._server is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                continue
            threading.Thread(
                target=self._handle_conn, args=(conn,), daemon=True
            ).start()

    def _handle_conn(self, conn: socket.socket) -> None:
        try:
            with conn:
                buf = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        self._ingest_line(line.decode("utf-8", errors="replace"))
        except OSError as exc:
            log.debug("artifact uds conn: %s", exc)

    def _ingest_line(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            log.warning("artifact uds malformed json: %s", line[:120])
            return
        if not isinstance(obj, dict):
            return
        roots = obj.get("resolve_roots") or []
        if isinstance(roots, list):
            root_t = tuple(str(x) for x in roots)
        else:
            root_t = ()
        job = ArtifactJob(
            svc=str(obj.get("svc") or ""),
            session_id=str(obj.get("session_id") or ""),
            kind=str(obj.get("kind") or "other"),
            path=str(obj.get("path") or ""),
            provider_id=str(obj.get("provider_id") or ""),
            cell_id=str(obj.get("cell_id") or ""),
            collector_id=str(obj.get("collector_id") or ""),
            filename=str(obj.get("filename") or ""),
            resolve_roots=root_t,
        )
        self.enqueue(job)

    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            try:
                job = self._q.get(timeout=1.0)
            except queue.Empty:
                continue
            if job is None:
                break
            try:
                self._process(job)
            except Exception:  # noqa: BLE001 — never kill collector on hash errors
                log.exception("artifact job failed path=%s", job.path)

    def _process(self, job: ArtifactJob) -> None:
        path = resolve_path(job.path, job.resolve_roots)
        sha = "0" * 64
        length = 0
        stub = True
        yara_tags: list[str] = []
        yara_fut = None
        if path is not None and path.is_file():
            sha, length = sha256_file(path)
            stub = False
            filename = path.name
            # Queue YARA off the capture path; wait briefly only in this worker.
            yara_fut = scan_async(path)
        else:
            filename = job.filename or Path(job.path).name
            log.info("artifact path not yet visible; emitting stub sha path=%s", job.path)

        if yara_fut is not None:
            try:
                timeout = float(os.environ.get("AMBER_YARA_WAIT_SEC", "0.5"))
            except ValueError:
                timeout = 0.5
            yara_tags = yara_fut.wait(timeout=max(0.05, timeout))

        record = {
            "schema_version": "artifact.v1",
            "seq_id": self.next_seq(),
            "artifact_id": f"art_{secrets.token_hex(4)}",
            "ts": utc_now_rfc3339_nano(),
            "svc": job.svc,
            "provider_id": job.provider_id,
            "session_id": job.session_id,
            "cell_id": job.cell_id,
            "collector_id": job.collector_id,
            "kind": job.kind,
            "path": job.path,
            "filename": filename,
            "byte_length": length,
            "sha256": sha,
            "sha256_stub": stub,
        }
        if yara_tags:
            record["yara_tags"] = yara_tags
        self.write_record(record)
        log.info(
            "artifact %s kind=%s sha=%s… stub=%s bytes=%d yara_tags=%s",
            job.session_id,
            job.kind,
            sha[:12],
            stub,
            length,
            yara_tags or [],
        )
