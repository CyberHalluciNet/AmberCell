#!/usr/bin/env python3
"""FTP collector entrypoint — capture, PASV map, raw-flow + event JSONL + artifacts."""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

from ambercell.artifact_queue import ArtifactJob, ArtifactQueue
from ambercell.emitters import EventEmitter, JsonlWriter, RawFlowEmitter
from ambercell.flow_tracker import FlowState, FlowTracker, parse_tcpdump_line
from ambercell.ids import new_event_id, new_session_id
from ambercell.paths import ensure_svc_dirs, jsonl_dir, pcap_ring_dir, raw_flows_dir, state_file
from ambercell.pcap_ring import PcapRingConfig, PcapRingWriter
from ambercell.sequence import Sequence
from ambercell.state import write_cell_state
from ambercell.tcpdump import TcpdumpStream
from ambercell.timeutil import utc_now_rfc3339_nano
from ambercell.upload_watch import UploadWatch, default_upload_dir

from ftp_collector.control import ControlSession, FtpControlParser

log = logging.getLogger("ftp_collector")

SVC = "ftp"
CELL_IP = os.environ.get("AMBER_FTP_CELL_IP", "172.30.30.10")
CELL_ID = os.environ.get("AMBER_FTP_CELL_ID", "ftp-cell-01")
COLLECTOR_ID = os.environ.get("AMBER_FTP_COLLECTOR_ID", "ftp-collector-a")
PROVIDER_ID = os.environ.get("AMBER_FTP_PROVIDER", "vsftpd")
IMAGE_DIGEST = os.environ.get("AMBER_IMAGE_DIGEST", "")
HI_DIGEST = os.environ.get("AMBER_FTP_HI_DIGEST", "")
CELL_INSTANCE_ID = os.environ.get("AMBER_CELL_INSTANCE_ID", os.environ.get("HOSTNAME", "local"))
ARTIFACT_SOCK = os.environ.get("AMBER_ARTIFACT_SOCK", "/var/ambercell/run/artifact-ftp.sock")
UPLOAD_DIR = default_upload_dir()
SEED_DIR = os.environ.get("AMBER_FTP_SEED_DIR", "/mnt/hi-seed")

BPF_ALL = "tcp port 21 or (tcp portrange 30000-30049)"
BPF_CONTROL = "tcp port 21"


@dataclass
class CollectorContext:
    provider_id: str
    pcap_ref: str
    raw_flows: RawFlowEmitter
    events: EventEmitter
    artifacts: JsonlWriter
    artifact_seq: Sequence
    artifact_q: ArtifactQueue
    tracker: FlowTracker
    control: FtpControlParser
    control_keys: dict[str, tuple[str, int, str, int]]
    lock: threading.Lock
    last_session_id: str | None = None


def _write_state() -> None:
    write_cell_state(
        state_file(SVC),
        {
            "svc": SVC,
            "cell_id": CELL_ID,
            "collector_id": COLLECTOR_ID,
            "provider_id": PROVIDER_ID,
            "image_digest": IMAGE_DIGEST,
            "hi_image_digest": HI_DIGEST,
            "cell_instance_id": CELL_INSTANCE_ID,
            "cell_ip": CELL_IP,
            "updated_at": utc_now_rfc3339_nano(),
        },
    )


def _emit_rawflow(ctx: CollectorContext, flow: FlowState, *, protocol_guess: str) -> None:
    ctx.raw_flows.emit(
        {
            "session_id": flow.session_id,
            "svc": SVC,
            "provider_id": ctx.provider_id,
            "cell_id": CELL_ID,
            "collector_id": COLLECTOR_ID,
            "src_ip": flow.src_ip,
            "src_port": flow.src_port,
            "dst_ip": flow.dst_ip,
            "dst_port": flow.dst_port,
            "transport": "tcp",
            "first_seen": flow.first_seen or utc_now_rfc3339_nano(),
            "last_seen": flow.last_seen or utc_now_rfc3339_nano(),
            "bytes_in": flow.bytes_in,
            "bytes_out": flow.bytes_out,
            "packet_count_in": flow.packet_count_in,
            "packet_count_out": flow.packet_count_out,
            "pcap_ref": ctx.pcap_ref,
            "parser_status": flow.parser_status,
            "classification_status": flow.classification_status,
            "protocol_guess": protocol_guess,
        }
    )


def _emit_event(
    ctx: CollectorContext,
    session: ControlSession,
    event_name: str,
    details: dict,
) -> None:
    record: dict = {
        "event_id": new_event_id(),
        "ts": utc_now_rfc3339_nano(),
        "svc": SVC,
        "provider_id": ctx.provider_id,
        "event": event_name,
        "session_id": session.session_id,
        "cell_id": CELL_ID,
        "collector_id": COLLECTOR_ID,
        "src_ip": session.src_ip,
        "src_port": session.src_port,
        "dst_ip": session.dst_ip,
        "dst_port": session.dst_port,
    }
    if "user" in details and details["user"] is not None:
        record["user"] = details["user"]
    if "ok" in details:
        record["ok"] = details["ok"]
    if "reason" in details:
        record["reason"] = details["reason"]
    for key in (
        "command",
        "argument",
        "path",
        "stage",
        "sha256",
        "byte_length",
        "line",
        "pasv_port",
        "banner",
    ):
        if key in details:
            record[key] = details[key]
    ctx.events.emit(record)


def _enqueue_transfer(
    ctx: CollectorContext,
    session: ControlSession,
    *,
    kind: str,
    path: str,
) -> None:
    roots = (UPLOAD_DIR, SEED_DIR, "/var/ftp")
    ctx.artifact_q.enqueue(
        ArtifactJob(
            svc=SVC,
            session_id=session.session_id,
            kind=kind,
            path=path,
            provider_id=ctx.provider_id,
            cell_id=CELL_ID,
            collector_id=COLLECTOR_ID,
            filename=Path(path).name,
            resolve_roots=roots,
        )
    )


def _on_flow_close(ctx: CollectorContext, flow: FlowState) -> None:
    guess = flow.protocol_guess or "ftp-data"
    if flow.dst_port == 21 or flow.src_port == 21:
        guess = "ftp-control"
    if flow.extra.get("rawflow_emitted") and guess == "ftp-control":
        return
    _emit_rawflow(ctx, flow, protocol_guess=guess)


def _ensure_control_session(
    ctx: CollectorContext,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    ts: str,
) -> None:
    key = (src_ip, src_port, CELL_IP, 21)
    with ctx.lock:
        if ctx.tracker.get(src_ip, src_port, CELL_IP, 21) is not None:
            return
        session_id = new_session_id()
        ctrl = ControlSession(
            session_id=session_id,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=CELL_IP,
            dst_port=21,
        )
        flow = FlowState(
            session_id=session_id,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=CELL_IP,
            dst_port=21,
            first_seen=ts,
            last_seen=ts,
            parser_status="recognized",
            classification_status="known",
            protocol_guess="ftp-control",
        )
        ctx.control.register(key, ctrl)
        if dst_ip != CELL_IP:
            ctx.control.register((src_ip, src_port, dst_ip, 21), ctrl)
        ctx.control_keys[session_id] = key
        ctx.tracker.register(flow)
        ctx.last_session_id = session_id
    log.info(
        "control session %s %s:%d -> %s:21 (wire_dst=%s)",
        session_id,
        src_ip,
        src_port,
        CELL_IP,
        dst_ip,
    )


def _emit_unknown_flow(ctx: CollectorContext, pkt: dict) -> None:
    """Unknown/malformed: still emit raw-flow (anti-drift for parsers)."""
    session_id = new_session_id("unk")
    flow = FlowState(
        session_id=session_id,
        src_ip=pkt["src_ip"],
        src_port=pkt["src_port"],
        dst_ip=pkt["dst_ip"],
        dst_port=pkt["dst_port"],
        first_seen=pkt["ts"],
        last_seen=pkt["ts"],
        parser_status="unrecognized",
        classification_status="unknown",
        protocol_guess="unknown",
        bytes_in=pkt.get("length") or 0,
        packet_count_in=1,
    )
    with ctx.lock:
        ctx.tracker.register(flow)
    _emit_rawflow(ctx, flow, protocol_guess="unknown")
    flow.extra["rawflow_emitted"] = True
    log.info(
        "unknown flow %s %s:%d -> %s:%d",
        session_id,
        pkt["src_ip"],
        pkt["src_port"],
        pkt["dst_ip"],
        pkt["dst_port"],
    )


def _handle_syn(ctx: CollectorContext, pkt: dict) -> None:
    dst_ip, dst_port = pkt["dst_ip"], pkt["dst_port"]
    src_ip, src_port = pkt["src_ip"], pkt["src_port"]

    control_hit = dst_port == 21 and (
        dst_ip == CELL_IP or os.environ.get("AMBER_FTP_RELAX_DST", "1") == "1"
    )
    if control_hit:
        _ensure_control_session(ctx, src_ip, src_port, dst_ip, pkt["ts"])
        return

    pasv_hit = 30000 <= dst_port <= 30049 and (
        dst_ip == CELL_IP or os.environ.get("AMBER_FTP_RELAX_DST", "1") == "1"
    )
    if pasv_hit:
        parent = ctx.tracker.session_for_dst_port(dst_port, CELL_IP)
        if not parent:
            parent = ctx.tracker.session_for_dst_port(dst_port, dst_ip)
        if not parent:
            # Unmapped PASV-range SYN — still evidence (unknown correlation).
            _emit_unknown_flow(ctx, pkt)
            return
        session_id = parent
        flow = FlowState(
            session_id=session_id,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=CELL_IP,
            dst_port=dst_port,
            first_seen=pkt["ts"],
            last_seen=pkt["ts"],
            parser_status="recognized",
            classification_status="known",
            protocol_guess="ftp-data",
        )
        with ctx.lock:
            ctx.tracker.register(flow)
        log.info("pasv data flow session=%s port=%d", session_id, dst_port)
        return

    # Other TCP to cell IP → raw unknown flow.
    if dst_ip == CELL_IP or os.environ.get("AMBER_FTP_RELAX_DST", "1") == "1":
        _emit_unknown_flow(ctx, pkt)


def _on_flow_line(ctx: CollectorContext, line: str) -> None:
    pkt = parse_tcpdump_line(line)
    if pkt is None:
        _on_control_line(ctx, line)
        return
    flags = pkt["flags"]
    is_syn = "S" in flags and "." not in flags
    if is_syn:
        _handle_syn(ctx, pkt)
    elif pkt["dst_port"] == 21:
        _ensure_control_session(
            ctx, pkt["src_ip"], pkt["src_port"], pkt["dst_ip"], pkt["ts"]
        )
    _on_control_line(ctx, line)
    kind, flow = ctx.tracker.ingest(line)
    if kind == "fin" and flow is not None:
        _on_flow_close(ctx, flow)


def _on_control_line(ctx: CollectorContext, line: str) -> None:
    events = ctx.control.handle_line(line)
    for ev in events:
        _emit_event(ctx, ev.session, ev.name, ev.details)
        if ev.name in ("stor", "retr"):
            kind = "upload" if ev.name == "stor" else "download"
            path = str(ev.details.get("path") or "")
            _enqueue_transfer(ctx, ev.session, kind=kind, path=path)
        if ev.name == "pasv_open":
            port = ev.details.get("pasv_port")
            if isinstance(port, int):
                ctx.tracker.map_pasv_port(port, ev.session.session_id)
        if ev.name in ("session_open", "pasv_open", "auth", "port_denied"):
            flow = ctx.tracker.get(
                ev.session.src_ip,
                ev.session.src_port,
                ev.session.dst_ip,
                ev.session.dst_port,
            )
            if flow is not None and not flow.extra.get("rawflow_emitted"):
                flow.last_seen = utc_now_rfc3339_nano()
                if not flow.first_seen:
                    flow.first_seen = flow.last_seen
                _emit_rawflow(ctx, flow, protocol_guess="ftp-control")
                flow.extra["rawflow_emitted"] = True


def configure_logging() -> None:
    level = os.environ.get("AMBER_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def main() -> int:
    configure_logging()
    ensure_svc_dirs(SVC)
    Path("/var/ambercell/run").mkdir(parents=True, exist_ok=True)
    Path("/var/ambercell/artifacts").mkdir(parents=True, exist_ok=True)
    _write_state()

    seq = Sequence()
    artifact_seq = Sequence()
    raw_path = raw_flows_dir(SVC) / "flows.jsonl"
    event_path = jsonl_dir(SVC) / "events.jsonl"
    artifact_path = (
        Path(os.environ.get("AMBER_EVIDENCE_ROOT", "/var/ambercell"))
        / "artifacts"
        / SVC
        / "transfers.jsonl"
    )
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifacts_writer = JsonlWriter(artifact_path)

    ring = PcapRingWriter(
        pcap_ring_dir(SVC),
        PcapRingConfig(bpf_filter=BPF_ALL, interface=os.environ.get("AMBER_CAPTURE_IF", "any")),
    )
    ring.start()
    pcap_ref = ring.current_pcap_ref(SVC)

    artifact_q = ArtifactQueue(
        sock_path=ARTIFACT_SOCK,
        write_record=artifacts_writer.write,
        next_seq=artifact_seq.next_id,
    )

    ctx = CollectorContext(
        provider_id=PROVIDER_ID,
        pcap_ref=pcap_ref,
        raw_flows=RawFlowEmitter(raw_path, seq),
        events=EventEmitter(event_path, seq),
        artifacts=artifacts_writer,
        artifact_seq=artifact_seq,
        artifact_q=artifact_q,
        tracker=FlowTracker(cell_ip=CELL_IP),
        control=FtpControlParser(CELL_IP),
        control_keys={},
        lock=threading.Lock(),
    )

    def on_upload_path(path: str) -> None:
        sid = ctx.last_session_id or new_session_id()
        artifact_q.enqueue(
            ArtifactJob(
                svc=SVC,
                session_id=sid,
                kind="upload",
                path=path,
                provider_id=PROVIDER_ID,
                cell_id=CELL_ID,
                collector_id=COLLECTOR_ID,
                filename=Path(path).name,
                resolve_roots=(UPLOAD_DIR, SEED_DIR),
            )
        )

    upload_watch = UploadWatch(UPLOAD_DIR, on_upload_path)
    artifact_q.start()
    upload_watch.start()

    flow_stream = TcpdumpStream(BPF_ALL, on_line=lambda ln: _on_flow_line(ctx, ln))
    ctrl_stream = TcpdumpStream(
        BPF_CONTROL,
        on_line=lambda ln: _on_control_line(ctx, ln),
    )

    stop = threading.Event()

    def _shutdown(signum: int, _frame: object) -> None:
        log.info("signal %s, shutting down", signum)
        stop.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    flow_stream.start()
    ctrl_stream.start()
    log.info(
        "ftp collector running cell=%s ip=%s provider=%s upload=%s uds=%s",
        CELL_ID,
        CELL_IP,
        PROVIDER_ID,
        UPLOAD_DIR,
        ARTIFACT_SOCK,
    )

    try:
        while not stop.is_set():
            stop.wait(timeout=1.0)
            if not ring.running():
                log.error("pcap ring tcpdump exited")
                break
    finally:
        flow_stream.stop()
        ctrl_stream.stop()
        upload_watch.stop()
        artifact_q.stop()
        ring.stop()
        ctx.raw_flows.close()
        ctx.events.close()
        ctx.artifacts.close()
        _write_state()

    return 0


if __name__ == "__main__":
    sys.exit(main())
