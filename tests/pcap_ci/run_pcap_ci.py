#!/usr/bin/env python3
"""Hermetic pcap CI: fixture → sha256 + rawflow.v1 JSONL + artifact hash path.

Does not require tcpreplay, Docker, or a live collector. When ``tcpreplay`` is
present, prints an optional live-replay note; set ``AMBER_PCAP_TCPREPLAY=1`` to
fail if tcpreplay is missing (Linux CI opt-in). Default CI path is always the
fixture assertion below.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PCAP_CI = Path(__file__).resolve().parent
FIX = PCAP_CI / "fixtures"
EXP = PCAP_CI / "expected"
SYS_PATH_COLLECTORS = REPO / "collectors" / "base"

# Ensure ambercell imports for sha256_file / vault helpers
if str(SYS_PATH_COLLECTORS) not in sys.path:
    sys.path.insert(0, str(SYS_PATH_COLLECTORS))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def parse_first_ipv4_tcp(pcap: bytes) -> dict:
    """Minimal classic-pcap parser: return first IPv4/TCP 5-tuple + lengths."""
    if len(pcap) < 24:
        raise AssertionError("pcap too short for global header")
    magic = struct.unpack_from("<I", pcap, 0)[0]
    if magic != 0xA1B2C3D4:
        raise AssertionError(f"unsupported pcap magic {magic:#x}")
    off = 24
    if len(pcap) < off + 16:
        raise AssertionError("missing packet header")
    incl_len = struct.unpack_from("<I", pcap, off + 8)[0]
    frame = pcap[off + 16 : off + 16 + incl_len]
    if len(frame) < 34:
        raise AssertionError("frame too short for eth+ip")
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    if ethertype != 0x0800:
        raise AssertionError(f"expected IPv4 ethertype, got {ethertype:#x}")
    ip = frame[14:]
    vihl = ip[0]
    ihl = (vihl & 0x0F) * 4
    proto = ip[9]
    if proto != 6:
        raise AssertionError(f"expected TCP proto 6, got {proto}")
    src_ip = ".".join(str(b) for b in ip[12:16])
    dst_ip = ".".join(str(b) for b in ip[16:20])
    tcp = ip[ihl:]
    src_port, dst_port = struct.unpack_from("!HH", tcp, 0)
    return {
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "transport": "tcp",
        "frame_len": incl_len,
        "ip_payload_len": len(ip) - ihl,
    }


def load_expected_flow() -> dict:
    line = (EXP / "flows.expected.jsonl").read_text(encoding="utf-8").strip().splitlines()[0]
    return json.loads(line)


def validate_schema(obj: dict, schema_name: str) -> None:
    try:
        import jsonschema
    except ImportError:
        print("jsonschema required: pip install jsonschema", file=sys.stderr)
        raise SystemExit(2)
    schema = json.loads((REPO / "docs" / "schemas" / schema_name).read_text(encoding="utf-8"))
    jsonschema.validate(obj, schema)


def assert_hashes() -> dict:
    expected = json.loads((EXP / "hashes.expected.json").read_text(encoding="utf-8"))
    actual: dict[str, str] = {}
    for rel, want in expected.items():
        path = PCAP_CI / rel
        if not path.is_file():
            raise AssertionError(f"missing fixture {rel}")
        got = sha256_path(path)
        if got != want:
            raise AssertionError(f"hash mismatch {rel}: got {got} want {want}")
        actual[rel] = got
    return actual


def assert_flow_from_pcap() -> dict:
    pcap_path = FIX / "ftp_pasv_syn.pcap"
    parsed = parse_first_ipv4_tcp(pcap_path.read_bytes())
    expected = load_expected_flow()
    for key in ("src_ip", "src_port", "dst_ip", "dst_port", "transport"):
        if parsed[key] != expected[key]:
            raise AssertionError(
                f"pcap 5-tuple mismatch on {key}: parsed={parsed[key]!r} expected={expected[key]!r}"
            )
    # Build the hermetic raw-flow record (pcap_ref points at fixture path under tests/)
    record = dict(expected)
    validate_schema(record, "rawflow.v1.schema.json")
    if record.get("pcap_ref") != "tests/pcap_ci/fixtures/ftp_pasv_syn.pcap":
        raise AssertionError("expected pcap_ref must point at committed fixture")
    if record.get("parser_status") != "unknown":
        # Unknown SYN-only traffic still emits raw flow (Stage-3 kill bar)
        raise AssertionError("SYN-only fixture must be parser_status=unknown")
    return record


def assert_artifact_hash_path() -> str:
    from ambercell.artifact_queue import sha256_file

    sample = FIX / "upload_sample.bin"
    digest, length = sha256_file(sample)
    want = json.loads((EXP / "hashes.expected.json").read_text(encoding="utf-8"))[
        "fixtures/upload_sample.bin"
    ]
    if digest != want:
        raise AssertionError(f"artifact sha256_file mismatch: {digest} != {want}")
    if length != sample.stat().st_size:
        raise AssertionError("artifact byte_length mismatch")
    # Emit a minimal artifact.v1-shaped dict for schema check (no live UDS)
    art = {
        "schema_version": "artifact.v1",
        "seq_id": 1,
        "artifact_id": "art_pcapci01",
        "ts": "2026-10-05T08:32:11.123456789Z",
        "svc": "ftp",
        "session_id": "fp_pcapci01",
        "cell_id": "ftp-cell-01",
        "collector_id": "ftp-collector-a",
        "kind": "upload",
        "path": str(sample),
        "filename": sample.name,
        "byte_length": length,
        "sha256": digest,
    }
    validate_schema(art, "artifact.v1.schema.json")
    return digest


def assert_enrichment_path(flow: dict) -> dict:
    """Enrichment cites the hermetic flow session_id (evidence_refs only; no mutation)."""
    path = EXP / "enrichment.expected.jsonl"
    line = path.read_text(encoding="utf-8").strip().splitlines()[0]
    obj = json.loads(line)
    validate_schema(obj, "enrichment.v1.schema.json")
    refs = obj.get("evidence_refs") or []
    sid = flow["session_id"]
    if sid not in refs and f"session:{sid}" not in refs:
        raise AssertionError(f"enrichment must cite flow session_id {sid!r} in evidence_refs")
    if obj.get("mapping_mode") not in ("rule", "heuristic", "model_assisted", "manual"):
        raise AssertionError("enrichment mapping_mode invalid")
    return obj


def maybe_note_tcpreplay() -> None:
    enforce = os.environ.get("AMBER_PCAP_TCPREPLAY", "").strip() in ("1", "true", "yes")
    path = shutil.which("tcpreplay")
    if path:
        print(f"note: tcpreplay available at {path} (optional live replay; hermetic fixture path is authoritative)")
        return
    msg = (
        "tcpreplay not in PATH — hermetic fixture→JSONL/hash path still runs; "
        "install tcpreplay on Linux runners for optional live replay"
    )
    if enforce:
        print(msg, file=sys.stderr)
        raise SystemExit(3)
    print(f"note: {msg}")


def main() -> int:
    print("==> pcap CI: fixture hashes")
    hashes = assert_hashes()
    print(f"    ok ({len(hashes)} files)")

    print("==> pcap CI: parse fixture → rawflow.v1")
    flow = assert_flow_from_pcap()
    print(
        f"    ok {flow['src_ip']}:{flow['src_port']} -> "
        f"{flow['dst_ip']}:{flow['dst_port']} parser_status={flow['parser_status']}"
    )

    print("==> pcap CI: artifact hash path")
    digest = assert_artifact_hash_path()
    print(f"    ok sha256={digest[:16]}…")

    print("==> pcap CI: enrichment cites flow")
    enr = assert_enrichment_path(flow)
    print(f"    ok enrichment_id={enr['enrichment_id']} confidence={enr['confidence']}")

    maybe_note_tcpreplay()
    print("OK: hermetic pcap CI")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
