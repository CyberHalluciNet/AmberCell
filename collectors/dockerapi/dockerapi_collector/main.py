#!/usr/bin/env python3
"""Docker API trap collector — tcp/2375 JSONL."""

from __future__ import annotations

import logging
import os
import signal
import threading

from ambercell.emitters import EventEmitter, RawFlowEmitter
from ambercell.flow_tracker import FlowState, FlowTracker, parse_tcpdump_line
from ambercell.ids import new_event_id, new_session_id
from ambercell.log_stream import start_fifo_reader
from ambercell.paths import ensure_svc_dirs, jsonl_dir, pcap_ring_dir, raw_flows_dir, state_file
from ambercell.pcap_ring import PcapRingConfig, PcapRingWriter
from ambercell.sequence import Sequence
from ambercell.state import write_cell_state
from ambercell.tcpdump import TcpdumpStream
from ambercell.timeutil import utc_now_rfc3339_nano

from dockerapi_collector.control import DockerapiControlParser, ParsedEvent, TrapSession

log = logging.getLogger("dockerapi_collector")

SVC = "dockerapi"
CELL_IP = os.environ.get("AMBER_DOCKERAPI_CELL_IP", "172.30.140.10")
CELL_ID = os.environ.get("AMBER_DOCKERAPI_CELL_ID", "dockerapi-cell-01")
COLLECTOR_ID = os.environ.get("AMBER_DOCKERAPI_COLLECTOR_ID", "dockerapi-collector-a")
PROVIDER_ID = os.environ.get("AMBER_DOCKERAPI_PROVIDER", "trap")
LOG_FIFO = os.environ.get("AMBER_DOCKERAPI_LOG_FIFO", "/run/amber/log/dockerapi.fifo")
PORT = 2375
BPF = f"tcp port {PORT}"


def _write_state() -> None:
    write_cell_state(
        state_file(SVC),
        {
            "svc": SVC,
            "cell_id": CELL_ID,
            "collector_id": COLLECTOR_ID,
            "provider_id": PROVIDER_ID,
            "trap": True,
            "image_digest": os.environ.get("AMBER_IMAGE_DIGEST", ""),
            "hi_image_digest": os.environ.get("AMBER_DOCKERAPI_HI_DIGEST", ""),
            "cell_instance_id": os.environ.get("AMBER_CELL_INSTANCE_ID", "local"),
            "cell_ip": CELL_IP,
            "updated_at": utc_now_rfc3339_nano(),
        },
    )


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    ensure_svc_dirs(SVC)
    _write_state()

    seq = Sequence()
    raw_path = raw_flows_dir(SVC) / "flows.jsonl"
    event_path = jsonl_dir(SVC) / "events.jsonl"

    ring = PcapRingWriter(
        pcap_ring_dir(SVC),
        PcapRingConfig(bpf_filter=BPF, interface=os.environ.get("AMBER_CAPTURE_IF", "any")),
    )
    ring.start()
    pcap_ref = ring.current_pcap_ref(SVC)

    session = TrapSession(session_id=new_session_id("dk"))
    parser = DockerapiControlParser()
    parser.bind(session)
    tracker = FlowTracker(cell_ip=CELL_IP)
    raw_flows = RawFlowEmitter(raw_path, seq)
    events = EventEmitter(event_path, seq)
    lock = threading.Lock()

    def emit_event(ev: ParsedEvent) -> None:
        record = {
            "event_id": new_event_id(),
            "ts": utc_now_rfc3339_nano(),
            "svc": SVC,
            "provider_id": PROVIDER_ID,
            "event": ev.name,
            "session_id": ev.session.session_id,
            "cell_id": CELL_ID,
            "collector_id": COLLECTOR_ID,
            "src_ip": ev.session.src_ip,
            "src_port": ev.session.src_port,
            "dst_ip": CELL_IP,
            "dst_port": PORT,
        }
        record.update(ev.details)
        events.emit(record)

    def ensure_session(src_ip: str, src_port: int, ts: str) -> None:
        with lock:
            if tracker.get(src_ip, src_port, CELL_IP, PORT) is not None:
                return
            sid = new_session_id("dk")
            session.session_id = sid
            session.src_ip = src_ip
            session.src_port = src_port
            parser.bind(session)
            flow = FlowState(
                session_id=sid,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=CELL_IP,
                dst_port=PORT,
                first_seen=ts,
                last_seen=ts,
                parser_status="recognized",
                classification_status="known",
                protocol_guess="docker-api",
            )
            tracker.register(flow)
            raw_flows.emit(
                {
                    "session_id": sid,
                    "svc": SVC,
                    "provider_id": PROVIDER_ID,
                    "cell_id": CELL_ID,
                    "collector_id": COLLECTOR_ID,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": CELL_IP,
                    "dst_port": PORT,
                    "transport": "tcp",
                    "first_seen": ts,
                    "last_seen": ts,
                    "bytes_in": 0,
                    "bytes_out": 0,
                    "packet_count_in": 0,
                    "packet_count_out": 0,
                    "pcap_ref": pcap_ref,
                    "parser_status": "recognized",
                    "classification_status": "known",
                    "protocol_guess": "docker-api",
                }
            )

    def on_line(line: str) -> None:
        pkt = parse_tcpdump_line(line)
        if pkt is not None:
            flags = pkt["flags"]
            is_syn = "S" in flags and "." not in flags
            if is_syn and pkt["dst_port"] == PORT:
                relax = os.environ.get("AMBER_DOCKERAPI_RELAX_DST", "0") == "1"
                if pkt["dst_ip"] == CELL_IP or relax:
                    ensure_session(pkt["src_ip"], pkt["src_port"], pkt["ts"])
            tracker.ingest(line)
            return
        for ev in parser.handle_line(line):
            emit_event(ev)

    stop = threading.Event()
    start_fifo_reader(LOG_FIFO, on_line, stop)
    stream = TcpdumpStream(BPF, extra_args=["-A"], on_line=on_line)

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
        stream.stop()
        ring.stop()
        raw_flows.close()
        events.close()
        _write_state()
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
