#!/usr/bin/env python3
"""Telnet collector — tcp/23 capture, PTY transcript, cmd + egress correlation."""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
from dataclasses import dataclass

from ambercell.emitters import EventEmitter, RawFlowEmitter
from ambercell.flow_tracker import FlowState, FlowTracker, parse_tcpdump_line
from ambercell.ids import new_event_id, new_session_id
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

from telnet_collector.control import ParsedEvent, TelnetControlParser, TelnetSession

log = logging.getLogger("telnet_collector")

SVC = "telnet"
CELL_IP = os.environ.get("AMBER_TELNET_CELL_IP", "172.30.40.10")
CELL_ID = os.environ.get("AMBER_TELNET_CELL_ID", "telnet-cell-01")
COLLECTOR_ID = os.environ.get("AMBER_TELNET_COLLECTOR_ID", "telnet-collector-a")
PROVIDER_ID = os.environ.get("AMBER_TELNET_PROVIDER", "busybox-telnetd")
IMAGE_DIGEST = os.environ.get("AMBER_IMAGE_DIGEST", "")
HI_DIGEST = os.environ.get("AMBER_TELNET_HI_DIGEST", "")
CELL_INSTANCE_ID = os.environ.get("AMBER_CELL_INSTANCE_ID", os.environ.get("HOSTNAME", "local"))

@dataclass
class CollectorContext:
    provider_id: str
    pcap_ref: str
    raw_flows: RawFlowEmitter
    events: EventEmitter
    tracker: FlowTracker
    control: TelnetControlParser
    sessions: dict[str, TelnetSession]
    lock: threading.Lock
    egress_by_src: dict[str, list[str]]


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


def _write_transcript(session: TelnetSession) -> None:
    body = "\n".join(session.transcript).strip()
    if not body:
        return
    out_dir = transcripts_dir(SVC)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{session.session_id}.txt"
    path.write_text(body + "\n", encoding="utf-8")
    # Sidecar metadata for PTY completeness (commands secondary).
    meta = out_dir / f"{session.session_id}.meta.json"
    import json

    meta.write_text(
        json.dumps(
            {
                "session_id": session.session_id,
                "user": session.user,
                "line_count": len(session.transcript),
                "cmd_count": len(session.cmds),
                "cmds": session.cmds[:64],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    log.info("transcript %s bytes=%d path=%s", session.session_id, len(body), path)


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


def _emit_event(ctx: CollectorContext, session: TelnetSession, event_name: str, details: dict) -> None:
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
    for key in ("stage", "command", "line", "auth_format", "correlate", "egress_session_ids", "banner"):
        if key in details:
            record[key] = details[key]
    ctx.events.emit(record)


def _on_flow_close(ctx: CollectorContext, flow: FlowState) -> None:
    session = ctx.sessions.get(flow.session_id)
    if session is not None:
        _write_transcript(session)
    if flow.extra.get("rawflow_emitted"):
        return
    guess = flow.protocol_guess or "telnet"
    _emit_rawflow(ctx, flow, protocol_guess=guess)


def _ensure_session(
    ctx: CollectorContext,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    ts: str,
) -> None:
    with ctx.lock:
        if ctx.tracker.get(src_ip, src_port, CELL_IP, 23) is not None:
            return
        session_id = new_session_id("tn")
        tn = TelnetSession(
            session_id=session_id,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=CELL_IP,
            dst_port=23,
        )
        flow = FlowState(
            session_id=session_id,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=CELL_IP,
            dst_port=23,
            first_seen=ts,
            last_seen=ts,
            parser_status="recognized",
            classification_status="known",
            protocol_guess="telnet",
        )
        key = (src_ip, src_port, CELL_IP, 23)
        ctx.control.register(key, tn)
        if dst_ip != CELL_IP:
            ctx.control.register((src_ip, src_port, dst_ip, 23), tn)
        ctx.sessions[session_id] = tn
        ctx.tracker.register(flow)
    log.info(
        "telnet session %s %s:%d -> %s:23 (wire_dst=%s)",
        session_id,
        src_ip,
        src_port,
        CELL_IP,
        dst_ip,
    )


def _handle_egress_syn(ctx: CollectorContext, pkt: dict) -> None:
    """Cell-originated TCP (egress) — correlate later with cmd egress_staging."""
    if pkt["src_ip"] != CELL_IP:
        return
    if pkt["dst_port"] == 23:
        return
    session_id = new_session_id("eg")
    flow = FlowState(
        session_id=session_id,
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
    with ctx.lock:
        ctx.tracker.register(flow)
        ctx.egress_by_src.setdefault(CELL_IP, []).append(session_id)
    _emit_rawflow(ctx, flow, protocol_guess="egress-tcp")
    flow.extra["rawflow_emitted"] = True
    log.info(
        "egress flow %s %s:%d -> %s:%d",
        session_id,
        pkt["src_ip"],
        pkt["src_port"],
        pkt["dst_ip"],
        pkt["dst_port"],
    )


def _handle_syn(ctx: CollectorContext, pkt: dict) -> None:
    dst_ip, dst_port = pkt["dst_ip"], pkt["dst_port"]
    if dst_port == 23:
        relax = os.environ.get("AMBER_TELNET_RELAX_DST", "0") == "1"
        if dst_ip != CELL_IP and not relax:
            return
        _ensure_session(ctx, pkt["src_ip"], pkt["src_port"], dst_ip, pkt["ts"])
        return
    if pkt["src_ip"] == CELL_IP:
        _handle_egress_syn(ctx, pkt)
        return
    # Unknown inbound to cell (non-23) still emits raw flow.
    if dst_ip == CELL_IP:
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


def _apply_parsed(ctx: CollectorContext, ev: ParsedEvent) -> None:
    details = dict(ev.details)
    if ev.name == "egress_staging":
        with ctx.lock:
            eg = list(ctx.egress_by_src.get(CELL_IP, [])[-5:])
        if eg:
            details["egress_session_ids"] = eg
    _emit_event(ctx, ev.session, ev.name, details)
    if ev.name in ("session_open", "auth"):
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
            _emit_rawflow(ctx, flow, protocol_guess="telnet")
            flow.extra["rawflow_emitted"] = True


def _on_control_line(ctx: CollectorContext, line: str) -> None:
    for ev in ctx.control.handle_line(line):
        _apply_parsed(ctx, ev)


def _on_flow_line(ctx: CollectorContext, line: str) -> None:
    pkt = parse_tcpdump_line(line)
    if pkt is None:
        _on_control_line(ctx, line)
        return
    flags = pkt["flags"]
    is_syn = "S" in flags and "." not in flags
    if is_syn:
        _handle_syn(ctx, pkt)
    elif pkt["dst_port"] == 23:
        _ensure_session(ctx, pkt["src_ip"], pkt["src_port"], pkt["dst_ip"], pkt["ts"])
    _on_control_line(ctx, line)
    kind, flow = ctx.tracker.ingest(line)
    if kind == "fin" and flow is not None:
        _on_flow_close(ctx, flow)


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

    ring = PcapRingWriter(
        pcap_ring_dir(SVC),
        PcapRingConfig(bpf_filter="tcp", interface=os.environ.get("AMBER_CAPTURE_IF", "any")),
    )
    ring.start()
    pcap_ref = ring.current_pcap_ref(SVC)

    ctx = CollectorContext(
        provider_id=PROVIDER_ID,
        pcap_ref=pcap_ref,
        raw_flows=RawFlowEmitter(raw_path, seq),
        events=EventEmitter(event_path, seq),
        tracker=FlowTracker(cell_ip=CELL_IP),
        control=TelnetControlParser(CELL_IP),
        sessions={},
        lock=threading.Lock(),
        egress_by_src={},
    )

    flow_stream = TcpdumpStream(
        "tcp",
        extra_args=["-A"],
        on_line=lambda ln: _on_flow_line(ctx, ln),
    )

    stop = threading.Event()

    def _shutdown(signum: int, _frame: object) -> None:
        log.info("signal %s, shutting down", signum)
        stop.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    flow_stream.start()
    log.info(
        "telnet collector running cell=%s ip=%s provider=%s evidence=/var/ambercell",
        CELL_ID,
        CELL_IP,
        PROVIDER_ID,
    )

    try:
        while not stop.is_set():
            stop.wait(timeout=1.0)
            if not ring.running():
                log.error("pcap ring tcpdump exited")
                break
    finally:
        # Flush open transcripts on shutdown.
        for session in list(ctx.sessions.values()):
            _write_transcript(session)
        flow_stream.stop()
        ring.stop()
        ctx.raw_flows.close()
        ctx.events.close()
        _write_state()

    return 0


if __name__ == "__main__":
    sys.exit(main())
