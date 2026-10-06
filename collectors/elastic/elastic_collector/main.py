#!/usr/bin/env python3
"""elastic collector — tcp/9200 JSONL."""

from __future__ import annotations

import logging
import os
import signal
import sys
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

from elastic_collector.control import ElasticControlParser, ElasticSession, ParsedEvent

log = logging.getLogger("elastic_collector")

SVC = "elastic"
CELL_IP = os.environ.get("AMBER_ELASTIC_CELL_IP", "172.30.130.10")
CELL_ID = os.environ.get("AMBER_ELASTIC_CELL_ID", "elastic-cell-01")
COLLECTOR_ID = os.environ.get("AMBER_ELASTIC_COLLECTOR_ID", "elastic-collector-a")
PROVIDER_ID = os.environ.get("AMBER_ELASTIC_PROVIDER", "elasticsearch")
LOG_FIFO = os.environ.get("AMBER_ELASTIC_LOG_FIFO", "/run/amber/log/elastic.fifo")
IMAGE_DIGEST = os.environ.get("AMBER_IMAGE_DIGEST", "")
HI_DIGEST = os.environ.get("AMBER_ELASTIC_HI_DIGEST", "")
CELL_INSTANCE_ID = os.environ.get("AMBER_CELL_INSTANCE_ID", os.environ.get("HOSTNAME", "local"))
BPF = "tcp port 9200"
RELAX_ENV = "AMBER_ELASTIC_RELAX_DST"


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

    session = ElasticSession(session_id=new_session_id("es"))
    parser = ElasticControlParser()
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
            "src_ip": getattr(ev.session, "src_ip", "0.0.0.0"),
            "src_port": getattr(ev.session, "src_port", 0),
            "dst_ip": CELL_IP,
            "dst_port": 9200,
        }
        record.update(ev.details)
        events.emit(record)

    def ensure_session(src_ip: str, src_port: int, ts: str) -> None:
        with lock:
            if tracker.get(src_ip, src_port, CELL_IP, 9200) is not None:
                return
            sid = new_session_id("es")
            session.session_id = sid
            session.src_ip = src_ip
            if hasattr(session, "src_port"):
                session.src_port = src_port
            parser.bind(session)
            flow = FlowState(
                session_id=sid,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=CELL_IP,
                dst_port=9200,
                first_seen=ts,
                last_seen=ts,
                parser_status="recognized",
                classification_status="known",
                protocol_guess="elastic",
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
                    "dst_port": 9200,
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
                    "protocol_guess": "elastic",
                }
            )

    def on_line(line: str) -> None:
        pkt = parse_tcpdump_line(line)
        if pkt is not None:
            flags = pkt["flags"]
            is_syn = "S" in flags and "." not in flags
            if is_syn and pkt["dst_port"] == 9200:
                relax = os.environ.get(RELAX_ENV, "0") == "1"
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
    sys.exit(main())
