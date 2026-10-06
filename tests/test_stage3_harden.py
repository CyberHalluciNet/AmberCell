#!/usr/bin/env python3
"""Stage-3 harden unit checks: WORM vault close + async YARA path."""

from __future__ import annotations

import os
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "collectors" / "base"))

from ambercell.vault import close_active_segment, ensure_vault_notes, vault_root  # noqa: E402
from ambercell.yara_stub import scan_async, scan_stub  # noqa: E402


def test_vault_worm_closed_segments() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        os.environ["AMBER_EVIDENCE_ROOT"] = str(root)
        ensure_vault_notes(root)
        jsonl = root / "jsonl" / "ftp"
        jsonl.mkdir(parents=True)
        active = jsonl / "events.jsonl.active"
        active.write_text('{"schema_version":"event.v1","seq_id":1}\n', encoding="utf-8")
        closed = close_active_segment(active, archive=True)
        assert closed is not None and closed.is_file()
        assert not active.exists()
        mode = closed.stat().st_mode
        assert not (mode & stat.S_IWUSR), f"closed segment still user-writable: {oct(mode)}"
        archived = list((vault_root(root) / "jsonl" / "ftp").glob("events.jsonl.*"))
        assert archived, "vault archive missing"
        amode = archived[0].stat().st_mode
        assert not (amode & stat.S_IWUSR), f"vault copy still user-writable: {oct(amode)}"


def test_yara_async_queue_does_not_block_caller_enqueue() -> None:
    with tempfile.TemporaryDirectory() as td:
        sample = Path(td) / "drop.exe"
        sample.write_bytes(b"MZ-fake")
        os.environ["AMBER_YARA_RULES"] = "/nonexistent/rules"  # enable stub branch
        t0 = time.monotonic()
        fut = scan_async(sample)
        enqueue_ms = (time.monotonic() - t0) * 1000
        assert enqueue_ms < 200, f"scan_async enqueue too slow: {enqueue_ms:.1f}ms"
        tags = fut.wait(timeout=2.0)
        assert "yara:stub-suspicious-ext" in tags
        # scan_stub used by artifact worker must return quickly for stub
        os.environ["AMBER_YARA_WAIT_SEC"] = "0.5"
        tags2 = scan_stub(sample)
        assert "yara:stub-suspicious-ext" in tags2


def test_yara_worker_is_daemon_thread() -> None:
    # Touch worker
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "x.bin"
        p.write_bytes(b"x")
        scan_async(p).wait(timeout=1.0)
    daemons = [t for t in threading.enumerate() if t.name == "yara-async"]
    assert daemons, "yara-async worker thread missing"
    assert daemons[0].daemon is True


def main() -> int:
    test_vault_worm_closed_segments()
    print("vault WORM: OK")
    test_yara_async_queue_does_not_block_caller_enqueue()
    print("yara async: OK")
    test_yara_worker_is_daemon_thread()
    print("yara daemon worker: OK")
    print("OK: stage3 harden unit checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
