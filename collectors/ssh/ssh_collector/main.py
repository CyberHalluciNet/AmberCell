#!/usr/bin/env python3
"""SSH collector — tcp/22 flows, FIFO sshd/PTY lines, SFTP upload artifacts."""

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
from ambercell.log_stream import start_fifo_reader
from ambercell.paths import (
    ensure_svc_dirs,
    jsonl_dir,
    pcap_ring_dir,
    raw_flows_dir,
    state_file,
    transcripts_dir,
)
from ambercell.pcap_ring import PcapRingConfig, PcapRingWriter
from ambercell.sequence import Sequence
from ambercell.state import write_cell_state
from ambercell.tcpdump import TcpdumpStream
from ambercell.timeutil import utc_now_rfc3339_nano
from ambercell.upload_watch import UploadWatch

from ssh_collector.control import ParsedEvent, SshControlParser, SshSession

log = logging.getLogger("ssh_collector")

SVC = "ssh"
CELL_IP = os.environ.get("AMBER_SSH_CELL_IP", "172.30.50.10")
CELL_ID = os.environ.get("AMBER_SSH_CELL_ID", "ssh-cell-01")
COLLECTOR_ID = os.environ.get("AMBER_SSH_COLLECTOR_ID", "ssh-collector-a")
PROVIDER_ID = os.environ.get("AMBER_SSH_PROVIDER", "openssh")
LOG_FIFO = os.environ.get("AMBER_SSH_LOG_FIFO", "/run/amber/log/ssh.fifo")
UPLOAD_DIR = os.environ.get("AMBER_SSH_UPLOAD_DIR", "/mnt/hi-uploads")
ARTIFACT_SOCK = os.environ.get("AMBER_ARTIFACT_SOCK", "/var/ambercell/run/artifact-ssh.sock")
IMAGE_DIGEST = os.environ.get("AMBER_IMAGE_DIGEST", "")
HI_DIGEST = os.environ.get("AMBER_SSH_HI_DIGEST", "")
CELL_INSTANCE_ID = os.environ.get("AMBER_CELL_INSTANCE_ID", os.environ.get("HOSTNAME", "local"))
BPF = "tcp port 22"


@dataclass
class CollectorContext:
    provider_id: str
    pcap_ref: str
    raw_flows: RawFlowEmitter
    events: EventEmitter
    artifacts: JsonlWriter
    artifact_q: ArtifactQueue
    tracker: FlowTracker
    control: SshControlParser
    sessions: dict[str, SshSession]
    lock: threading.Lock
    egress_ids: list[str]


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


def _write_transcript(session: SshSession) -> None:
    if not session.transcript:
        return
    body = "\n".join(session.transcript).strip()
    out_dir = transcripts_dir(SVC)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{session.session_id}.txt"
    path.write_text(body + "\n", encoding="utf-8")


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


def _emit_event(ctx: CollectorContext, session: SshSession, event_name: str, details: dict) -> None:
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
    for key, val in details.items():
        if val is not None:
            record[key] = val
    ctx.events.emit(record)


def _apply_parsed(ctx: CollectorContext, ev: ParsedEvent) -> None:
    details = dict(ev.details)
    if ev.name == "egress_staging" and ctx.egress_ids:
        details["egress_session_ids"] = list(ctx.egress_ids[-5:])
    _emit_event(ctx, ev.session, ev.name, details)


def _ensure_session(ctx: CollectorContext, src_ip: str, src_port: int, ts: str) -> None:
    with ctx.lock:
        if ctx.tracker.get(src_ip, src_port, CELL_IP, 22) is not None:
            return
        session_id = new_session_id("sh")
        sess = SshSession(
            session_id=session_id,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=CELL_IP,
            dst_port=22,
        )
        flow = FlowState(
            session_id=session_id,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=CELL_IP,
            dst_port=22,
            first_seen=ts,
            last_seen=ts,
            parser_status="recognized",
            classification_status="known",
            protocol_guess="ssh",
        )
        ctx.sessions[session_id] = sess
        ctx.control.register(sess)
        ctx.tracker.register(flow)
        _emit_rawflow(ctx, flow, protocol_guess="ssh")
        flow.extra["rawflow_emitted"] = True
    log.info("ssh session %s %s:%d", session_id, src_ip, src_port)


def _on_line(ctx: CollectorContext, line: str) -> None:
    pkt = parse_tcpdump_line(line)
    if pkt is not None:
        flags = pkt["flags"]
        is_syn = "S" in flags and "." not in flags
        if is_syn and pkt["dst_port"] == 22:
            relax = os.environ.get("AMBER_SSH_RELAX_DST", "0") == "1"
            if pkt["dst_ip"] == CELL_IP or relax:
                _ensure_session(ctx, pkt["src_ip"], pkt["src_port"], pkt["ts"])
        elif pkt["src_ip"] == CELL_IP and pkt["dst_port"] not in (22,):
            eg_id = new_session_id("eg")
            flow = FlowState(
                session_id=eg_id,
                src_ip=pkt["src_ip"],
                src_port=pkt["src_port"],
                dst_ip=pkt["dst_ip"],
                dst_port=pkt["dst_port"],
                first_seen=pkt["ts"],
                last_seen=pkt["ts"],
                parser_status="recognized",
                classification_status="known",
                protocol_guess="egress-tcp",
            )
            ctx.tracker.register(flow)
            ctx.egress_ids.append(eg_id)
            _emit_rawflow(ctx, flow, protocol_guess="egress-tcp")
            flow.extra["rawflow_emitted"] = True
        kind, flow = ctx.tracker.ingest(line)
        if kind == "fin" and flow is not None:
            sess = ctx.sessions.get(flow.session_id)
            if sess is not None:
                _write_transcript(sess)
        return

    for ev in ctx.control.handle_line(line):
        _apply_parsed(ctx, ev)


def configure_logging() -> None:
    level = os.environ.get("AMBER_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def main() -> int:
    configure_logging()
    ensure_svc_dirs(SVC)
    _write_state()

    seq = Sequence()
    raw_path = raw_flows_dir(SVC) / "flows.jsonl"
    event_path = jsonl_dir(SVC) / "events.jsonl"
    art_path = Path(os.environ.get("AMBER_EVIDENCE_ROOT", "/var/ambercell")) / "artifacts" / SVC / "uploads.jsonl"
    artifact_seq = Sequence()

    ring = PcapRingWriter(
        pcap_ring_dir(SVC),
        PcapRingConfig(bpf_filter=BPF, interface=os.environ.get("AMBER_CAPTURE_IF", "any")),
    )
    ring.start()
    pcap_ref = ring.current_pcap_ref(SVC)

    artifacts_writer = JsonlWriter(art_path)
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
        artifact_q=artifact_q,
        tracker=FlowTracker(cell_ip=CELL_IP),
        control=SshControlParser(CELL_IP),
        sessions={},
        lock=threading.Lock(),
        egress_ids=[],
    )

    artifact_q.start()

    def on_upload(path: str) -> None:
        sid = new_session_id("sh")
        ctx.artifact_q.enqueue(
            ArtifactJob(
                svc=SVC,
                session_id=sid,
                kind="sftp_upload",
                path=path,
                provider_id=PROVIDER_ID,
                cell_id=CELL_ID,
                collector_id=COLLECTOR_ID,
                resolve_roots=(UPLOAD_DIR,),
            )
        )

    upload_watch = UploadWatch(UPLOAD_DIR, on_upload)
    upload_watch.start()

    stop = threading.Event()

    def on_log(line: str) -> None:
        _on_line(ctx, line)

    start_fifo_reader(LOG_FIFO, on_log, stop)

    stream = TcpdumpStream(BPF, extra_args=["-A"], on_line=lambda ln: _on_line(ctx, ln))

    def _shutdown(signum: int, _frame: object) -> None:
        log.info("signal %s, shutting down", signum)
        stop.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    stream.start()
    log.info("ssh collector cell=%s ip=%s provider=%s", CELL_ID, CELL_IP, PROVIDER_ID)

    try:
        while not stop.is_set():
            stop.wait(1.0)
            if not ring.running():
                break
    finally:
        for sess in ctx.sessions.values():
            _write_transcript(sess)
        upload_watch.stop()
        stream.stop()
        ring.stop()
        artifact_q.stop()
        ctx.raw_flows.close()
        ctx.events.close()
        ctx.artifacts.close()
        _write_state()

    return 0


if __name__ == "__main__":
    sys.exit(main())
