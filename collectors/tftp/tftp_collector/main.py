#!/usr/bin/env python3
"""TFTP collector — udp/69 RRQ/WRQ/ERROR JSONL + raw flows."""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading

from ambercell.emitters import EventEmitter, RawFlowEmitter
from ambercell.ids import new_event_id, new_session_id
from ambercell.log_stream import start_fifo_reader
from ambercell.paths import ensure_svc_dirs, jsonl_dir, pcap_ring_dir, raw_flows_dir, state_file
from ambercell.pcap_ring import PcapRingConfig, PcapRingWriter
from ambercell.sequence import Sequence
from ambercell.state import write_cell_state
from ambercell.tcpdump import TcpdumpStream
from ambercell.timeutil import utc_now_rfc3339_nano

from tftp_collector.parse import parse_tftp_line

log = logging.getLogger("tftp_collector")

SVC = "tftp"
CELL_IP = os.environ.get("AMBER_TFTP_CELL_IP", "172.30.180.10")
CELL_ID = os.environ.get("AMBER_TFTP_CELL_ID", "tftp-cell-01")
COLLECTOR_ID = os.environ.get("AMBER_TFTP_COLLECTOR_ID", "tftp-collector-a")
PROVIDER_ID = os.environ.get("AMBER_TFTP_PROVIDER", "tftpd-hpa")
LOG_FIFO = os.environ.get("AMBER_TFTP_LOG_FIFO", "/run/amber/log/tftp.fifo")
IMAGE_DIGEST = os.environ.get("AMBER_IMAGE_DIGEST", "")
HI_DIGEST = os.environ.get("AMBER_TFTP_HI_DIGEST", "")
CELL_INSTANCE_ID = os.environ.get("AMBER_CELL_INSTANCE_ID", os.environ.get("HOSTNAME", "local"))
BPF = "udp port 69"


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
    ring = PcapRingWriter(
        pcap_ring_dir(SVC),
        PcapRingConfig(bpf_filter=BPF, interface=os.environ.get("AMBER_CAPTURE_IF", "any")),
    )
    ring.start()
    pcap_ref = ring.current_pcap_ref(SVC)
    raw_flows = RawFlowEmitter(raw_flows_dir(SVC) / "flows.jsonl", seq)
    events = EventEmitter(jsonl_dir(SVC) / "events.jsonl", seq)
    relax = os.environ.get("AMBER_TFTP_RELAX_DST", "0") == "1"

    def on_line(line: str) -> None:
        rec = parse_tftp_line(line)
        if rec is None:
            return
        session_id = new_session_id("tf")
        inbound = rec["dst_port"] == 69 and (rec["dst_ip"] == CELL_IP or relax)
        length = rec["length"]
        raw_flows.emit(
            {
                "session_id": session_id,
                "svc": SVC,
                "provider_id": PROVIDER_ID,
                "cell_id": CELL_ID,
                "collector_id": COLLECTOR_ID,
                "src_ip": rec["src_ip"],
                "src_port": rec["src_port"],
                "dst_ip": rec["dst_ip"],
                "dst_port": rec["dst_port"],
                "transport": "udp",
                "first_seen": rec["ts"],
                "last_seen": rec["ts"],
                "bytes_in": length if inbound else 0,
                "bytes_out": 0 if inbound else length,
                "packet_count_in": 1 if inbound else 0,
                "packet_count_out": 0 if inbound else 1,
                "pcap_ref": pcap_ref,
                "parser_status": "recognized" if rec["kind"] != "undecoded" else "partial",
                "classification_status": "known" if rec["kind"] != "undecoded" else "unknown",
                "protocol_guess": "tftp",
            }
        )
        if rec["kind"] == "query":
            events.emit(
                {
                    "event_id": new_event_id(),
                    "ts": rec["ts"],
                    "svc": SVC,
                    "provider_id": PROVIDER_ID,
                    "event": "tftp." + rec["op"].lower(),
                    "session_id": session_id,
                    "cell_id": CELL_ID,
                    "collector_id": COLLECTOR_ID,
                    "src_ip": rec["src_ip"],
                    "src_port": rec["src_port"],
                    "dst_ip": rec["dst_ip"],
                    "dst_port": rec["dst_port"],
                    "filename": rec["filename"],
                    "mode": rec["mode"],
                }
            )
        elif rec["kind"] == "op":
            events.emit(
                {
                    "event_id": new_event_id(),
                    "ts": rec["ts"],
                    "svc": SVC,
                    "provider_id": PROVIDER_ID,
                    "event": "tftp." + rec["op"].lower(),
                    "session_id": session_id,
                    "cell_id": CELL_ID,
                    "collector_id": COLLECTOR_ID,
                    "src_ip": rec["src_ip"],
                    "src_port": rec["src_port"],
                    "dst_ip": rec["dst_ip"],
                    "dst_port": rec["dst_port"],
                }
            )

    stop = threading.Event()
    start_fifo_reader(LOG_FIFO, lambda line: None, stop)
    stream = TcpdumpStream(BPF, on_line=on_line)

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
