#!/usr/bin/env python3
"""POP3 collector — tcp/110 capture, RETR artifacts, log FIFO handoff."""

from __future__ import annotations

import hashlib
import logging
import os
import signal
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

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

from pop3_collector.control import ParsedEvent, Pop3ControlParser, Pop3Session

log = logging.getLogger("pop3_collector")

SVC = "pop3"
CELL_IP = os.environ.get("AMBER_POP3_CELL_IP", "172.30.20.10")
CELL_ID = os.environ.get("AMBER_POP3_CELL_ID", "pop3-cell-01")
COLLECTOR_ID = os.environ.get("AMBER_POP3_COLLECTOR_ID", "pop3-collector-a")
PROVIDER_ID = os.environ.get("AMBER_POP3_PROVIDER", "dovecot")
IMAGE_DIGEST = os.environ.get("AMBER_IMAGE_DIGEST", "")
HI_DIGEST = os.environ.get("AMBER_POP3_HI_DIGEST", "")
CELL_INSTANCE_ID = os.environ.get("AMBER_CELL_INSTANCE_ID", os.environ.get("HOSTNAME", "local"))
LOG_FIFO = os.environ.get("AMBER_POP3_LOG_FIFO", "/run/amber/log/pop3.fifo")

BPF = "tcp port 110"
HIGH_VALUE_USERS = frozenset({"exec", "finance", "hr", "canary"})


@dataclass
class CollectorContext:
    provider_id: str
    pcap_ref: str
    raw_flows: RawFlowEmitter
    events: EventEmitter
    retr_artifacts: JsonlWriter
    tracker: FlowTracker
    control: Pop3ControlParser
    sessions: dict[str, Pop3Session]
    lock: threading.Lock
    retr_dir: Path
    last_session: Pop3Session | None = None


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


def _emit_event(ctx: CollectorContext, session: Pop3Session, event_name: str, details: dict) -> None:
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
    for key in (
        "user",
        "ok",
        "reason",
        "line",
        "banner",
        "msg_num",
        "byte_length",
        "sha256",
        "artifact_path",
        "high_value_mailbox",
    ):
        if key in details:
            record[key] = details[key]
    ctx.events.emit(record)


def _store_retr(ctx: CollectorContext, session: Pop3Session, body: str, details: dict) -> None:
    raw = body.encode("utf-8", errors="replace")
    digest = hashlib.sha256(raw).hexdigest()
    user = session.user or "unknown"
    fname = f"{session.session_id}_{user}_msg{details.get('msg_num')}_{digest[:12]}.mbox"
    path = ctx.retr_dir / fname
    path.write_bytes(raw)
    rel = f"artifacts/pop3/retr/{fname}"
    details = dict(details)
    details["sha256"] = digest
    details["artifact_path"] = rel
    details["byte_length"] = len(raw)
    if user in HIGH_VALUE_USERS:
        details["high_value_mailbox"] = True
    ctx.retr_artifacts.write(
        {
            "schema_version": "artifact.v1",
            "svc": SVC,
            "session_id": session.session_id,
            "kind": "retr",
            "sha256": digest,
            "byte_length": len(raw),
            "path": rel,
            "provider_id": ctx.provider_id,
            "user": user,
        }
    )
    _emit_event(ctx, session, "retr", details)


def _ensure_session(ctx: CollectorContext, src_ip: str, src_port: int, dst_ip: str, ts: str) -> None:
    with ctx.lock:
        existing = ctx.tracker.get(src_ip, src_port, CELL_IP, 110)
        if existing is not None:
            ctx.last_session = ctx.sessions.get(existing.session_id)
            return
        session_id = new_session_id("po")
        po = Pop3Session(
            session_id=session_id,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=CELL_IP,
            dst_port=110,
        )
        flow = FlowState(
            session_id=session_id,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=CELL_IP,
            dst_port=110,
            first_seen=ts,
            last_seen=ts,
            parser_status="recognized",
            classification_status="known",
            protocol_guess="pop3",
        )
        key = (src_ip, src_port, CELL_IP, 110)
        ctx.control.register(key, po)
        if dst_ip != CELL_IP:
            ctx.control.register((src_ip, src_port, dst_ip, 110), po)
        ctx.sessions[session_id] = po
        ctx.last_session = po
        ctx.tracker.register(flow)


def _emit_unknown(ctx: CollectorContext, pkt: dict) -> None:
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
    )
    with ctx.lock:
        ctx.tracker.register(flow)
    _emit_rawflow(ctx, flow, protocol_guess="unknown")
    flow.extra["rawflow_emitted"] = True


def _handle_syn(ctx: CollectorContext, pkt: dict) -> None:
    if pkt["dst_port"] == 110:
        relax = os.environ.get("AMBER_POP3_RELAX_DST", "0") == "1"
        if pkt["dst_ip"] != CELL_IP and not relax:
            return
        _ensure_session(ctx, pkt["src_ip"], pkt["src_port"], pkt["dst_ip"], pkt["ts"])
        return
    if pkt["dst_ip"] == CELL_IP or os.environ.get("AMBER_POP3_RELAX_DST", "0") == "1":
        _emit_unknown(ctx, pkt)


def _apply_parsed(ctx: CollectorContext, ev: ParsedEvent) -> None:
    if ev.name == "retr" and ev.details.get("body"):
        body = str(ev.details.pop("body"))
        _store_retr(ctx, ev.session, body, ev.details)
        return
    if ev.name == "retr_start":
        _emit_event(ctx, ev.session, ev.name, ev.details)
        return
    _emit_event(ctx, ev.session, ev.name, ev.details)
    if ev.name in ("session_open", "auth", "user", "retr", "dele"):
        flow = ctx.tracker.get(
            ev.session.src_ip, ev.session.src_port, ev.session.dst_ip, ev.session.dst_port
        )
        if flow is not None and not flow.extra.get("rawflow_emitted"):
            _emit_rawflow(ctx, flow, protocol_guess="pop3")
            flow.extra["rawflow_emitted"] = True


def _on_line(ctx: CollectorContext, line: str) -> None:
    pkt = parse_tcpdump_line(line)
    if pkt is None:
        for ev in ctx.control.handle_line(line):
            _apply_parsed(ctx, ev)
        return
    flags = pkt["flags"]
    is_syn = "S" in flags and "." not in flags
    if is_syn:
        _handle_syn(ctx, pkt)
    elif pkt["dst_port"] == 110 or pkt["src_port"] == 110:
        _ensure_session(ctx, pkt["src_ip"], pkt["src_port"], pkt["dst_ip"], pkt["ts"])
    for ev in ctx.control.handle_line(line):
        _apply_parsed(ctx, ev)
    kind, flow = ctx.tracker.ingest(line)
    if kind == "fin" and flow is not None and not flow.extra.get("rawflow_emitted"):
        _emit_rawflow(ctx, flow, protocol_guess=flow.protocol_guess or "pop3")
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
    retr_dir = Path(os.environ.get("AMBER_EVIDENCE_ROOT", "/var/ambercell")) / "artifacts" / SVC / "retr"
    retr_dir.mkdir(parents=True, exist_ok=True)
    _write_state()

    seq = Sequence()
    raw_path = raw_flows_dir(SVC) / "flows.jsonl"
    event_path = jsonl_dir(SVC) / "events.jsonl"
    retr_path = retr_dir.parent / "retr.jsonl"

    ring = PcapRingWriter(
        pcap_ring_dir(SVC),
        PcapRingConfig(bpf_filter=BPF, interface=os.environ.get("AMBER_CAPTURE_IF", "any")),
    )
    ring.start()
    pcap_ref = ring.current_pcap_ref(SVC)

    ctx = CollectorContext(
        provider_id=PROVIDER_ID,
        pcap_ref=pcap_ref,
        raw_flows=RawFlowEmitter(raw_path, seq),
        events=EventEmitter(event_path, seq),
        retr_artifacts=JsonlWriter(retr_path),
        tracker=FlowTracker(cell_ip=CELL_IP),
        control=Pop3ControlParser(CELL_IP),
        sessions={},
        lock=threading.Lock(),
        retr_dir=retr_dir,
    )

    stop = threading.Event()
    def on_log(line: str) -> None:
        for ev in ctx.control.handle_line(line):
            _apply_parsed(ctx, ev)

    start_fifo_reader(LOG_FIFO, on_log, stop)

    stream = TcpdumpStream(BPF, extra_args=["-A"], on_line=lambda ln: _on_line(ctx, ln))

    def _shutdown(signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    stream.start()
    log.info("pop3 collector cell=%s ip=%s", CELL_ID, CELL_IP)

    try:
        while not stop.is_set():
            stop.wait(1.0)
            if not ring.running():
                break
    finally:
        stream.stop()
        ring.stop()
        ctx.raw_flows.close()
        ctx.events.close()
        ctx.retr_artifacts.close()
        _write_state()
    return 0


if __name__ == "__main__":
    sys.exit(main())
