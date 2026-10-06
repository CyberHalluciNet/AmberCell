#!/usr/bin/env python3
"""Redis collector — tcp/6379, command JSONL, file-drop artifact hashing."""

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
from ambercell.paths import ensure_svc_dirs, jsonl_dir, pcap_ring_dir, raw_flows_dir, state_file
from ambercell.pcap_ring import PcapRingConfig, PcapRingWriter
from ambercell.sequence import Sequence
from ambercell.state import write_cell_state
from ambercell.tcpdump import TcpdumpStream
from ambercell.timeutil import utc_now_rfc3339_nano
from ambercell.upload_watch import UploadWatch

from redis_collector.control import ParsedEvent, RedisControlParser, RedisSession

log = logging.getLogger("redis_collector")

SVC = "redis"
CELL_IP = os.environ.get("AMBER_REDIS_CELL_IP", "172.30.60.10")
CELL_ID = os.environ.get("AMBER_REDIS_CELL_ID", "redis-cell-01")
COLLECTOR_ID = os.environ.get("AMBER_REDIS_COLLECTOR_ID", "redis-collector-a")
PROVIDER_ID = os.environ.get("AMBER_REDIS_PROVIDER", "redis-server")
LOG_FIFO = os.environ.get("AMBER_REDIS_LOG_FIFO", "/run/amber/log/redis.fifo")
DROP_DIR = os.environ.get("AMBER_REDIS_DROP_DIR", "/mnt/redis-data")
ARTIFACT_SOCK = os.environ.get("AMBER_ARTIFACT_SOCK", "/var/ambercell/run/artifact-redis.sock")
IMAGE_DIGEST = os.environ.get("AMBER_IMAGE_DIGEST", "")
HI_DIGEST = os.environ.get("AMBER_REDIS_HI_DIGEST", "")
CELL_INSTANCE_ID = os.environ.get("AMBER_CELL_INSTANCE_ID", os.environ.get("HOSTNAME", "local"))
BPF = "tcp port 6379"


@dataclass
class CollectorContext:
    provider_id: str
    pcap_ref: str
    raw_flows: RawFlowEmitter
    events: EventEmitter
    tracker: FlowTracker
    control: RedisControlParser
    session: RedisSession
    lock: threading.Lock
    artifact_q: ArtifactQueue


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


def _emit_rawflow(ctx: CollectorContext, flow: FlowState) -> None:
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
            "protocol_guess": "redis",
        }
    )


def _emit_event(ctx: CollectorContext, ev: ParsedEvent, *, raw_emitted: dict[str, bool] | None = None) -> None:
    sess = ev.session
    if raw_emitted is not None and not raw_emitted.get("ok"):
        ts = utc_now_rfc3339_nano()
        raw_emitted["ok"] = True
        ctx.raw_flows.emit(
            {
                "session_id": sess.session_id,
                "svc": SVC,
                "provider_id": ctx.provider_id,
                "cell_id": CELL_ID,
                "collector_id": COLLECTOR_ID,
                "src_ip": sess.src_ip or "0.0.0.0",
                "src_port": sess.src_port or 0,
                "dst_ip": CELL_IP,
                "dst_port": 6379,
                "transport": "tcp",
                "first_seen": ts,
                "last_seen": ts,
                "bytes_in": 0,
                "bytes_out": 0,
                "packet_count_in": 0,
                "packet_count_out": 0,
                "pcap_ref": ctx.pcap_ref,
                "parser_status": "recognized",
                "classification_status": "known",
                "protocol_guess": "redis",
            }
        )
    record = {
        "event_id": new_event_id(),
        "ts": utc_now_rfc3339_nano(),
        "svc": SVC,
        "provider_id": ctx.provider_id,
        "event": ev.name,
        "session_id": sess.session_id,
        "cell_id": CELL_ID,
        "collector_id": COLLECTOR_ID,
        "src_ip": sess.src_ip,
        "src_port": sess.src_port,
        "dst_ip": CELL_IP,
        "dst_port": 6379,
    }
    record.update(ev.details)
    ctx.events.emit(record)


def _ensure_session(ctx: CollectorContext, src_ip: str, src_port: int, ts: str) -> None:
    with ctx.lock:
        if ctx.tracker.get(src_ip, src_port, CELL_IP, 6379) is not None:
            return
        sid = new_session_id("rd")
        ctx.session.session_id = sid
        ctx.session.src_ip = src_ip
        ctx.session.src_port = src_port
        ctx.control.register(ctx.session)
        flow = FlowState(
            session_id=sid,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=CELL_IP,
            dst_port=6379,
            first_seen=ts,
            last_seen=ts,
            parser_status="recognized",
            classification_status="known",
            protocol_guess="redis",
        )
        ctx.tracker.register(flow)
        _emit_rawflow(ctx, flow)
        flow.extra["rawflow_emitted"] = True


def _on_line(ctx: CollectorContext, line: str, raw_emitted: dict[str, bool]) -> None:
    pkt = parse_tcpdump_line(line)
    if pkt is not None:
        flags = pkt["flags"]
        is_syn = "S" in flags and "." not in flags
        if is_syn and pkt["dst_port"] == 6379:
            relax = os.environ.get("AMBER_REDIS_RELAX_DST", "0") == "1"
            if pkt["dst_ip"] == CELL_IP or relax:
                _ensure_session(ctx, pkt["src_ip"], pkt["src_port"], pkt["ts"])
        ctx.tracker.ingest(line)
        return
    for ev in ctx.control.handle_line(line):
        _emit_event(ctx, ev, raw_emitted=raw_emitted)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    ensure_svc_dirs(SVC)
    _write_state()

    seq = Sequence()
    artifact_seq = Sequence()
    raw_path = raw_flows_dir(SVC) / "flows.jsonl"
    event_path = jsonl_dir(SVC) / "events.jsonl"
    art_path = Path(os.environ.get("AMBER_EVIDENCE_ROOT", "/var/ambercell")) / "artifacts" / SVC / "drops.jsonl"

    ring = PcapRingWriter(
        pcap_ring_dir(SVC),
        PcapRingConfig(bpf_filter=BPF, interface=os.environ.get("AMBER_CAPTURE_IF", "any")),
    )
    ring.start()
    pcap_ref = ring.current_pcap_ref(SVC)

    session = RedisSession(session_id=new_session_id("rd"), src_ip="0.0.0.0", src_port=0)
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
        tracker=FlowTracker(cell_ip=CELL_IP),
        control=RedisControlParser(CELL_IP),
        session=session,
        lock=threading.Lock(),
        artifact_q=artifact_q,
    )
    ctx.control.register(session)
    raw_emitted = {"ok": False}
    artifact_q.start()

    def on_drop(path: str) -> None:
        name = Path(path).name.lower()
        kind = "file_drop"
        if "cron" in name or name.endswith("crontab"):
            kind = "cron_drop"
        elif "authorized_keys" in name:
            kind = "authorized_keys_drop"
        ctx.artifact_q.enqueue(
            ArtifactJob(
                svc=SVC,
                session_id=ctx.session.session_id,
                kind=kind,
                path=path,
                provider_id=PROVIDER_ID,
                cell_id=CELL_ID,
                collector_id=COLLECTOR_ID,
                resolve_roots=(DROP_DIR,),
            )
        )
        _emit_event(
            ctx,
            ParsedEvent(
                "redis.file_drop",
                ctx.session,
                {"path": path, "filename": Path(path).name},
            ),
            raw_emitted=raw_emitted,
        )

    drop_watch = UploadWatch(DROP_DIR, on_drop, interval_s=1.5)
    drop_watch.start()

    stop = threading.Event()
    start_fifo_reader(LOG_FIFO, lambda ln: _on_line(ctx, ln, raw_emitted), stop)
    stream = TcpdumpStream(BPF, extra_args=["-A"], on_line=lambda ln: _on_line(ctx, ln, raw_emitted))

    def _shutdown(signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    stream.start()

    try:
        while not stop.is_set():
            stop.wait(1.0)
            if not ring.running():
                break
    finally:
        drop_watch.stop()
        stream.stop()
        ring.stop()
        artifact_q.stop()
        ctx.raw_flows.close()
        ctx.events.close()
        artifacts_writer.close()
        _write_state()
    return 0


if __name__ == "__main__":
    sys.exit(main())
