#!/usr/bin/env python3
"""NetBIOS collector — udp/137 NBNS query decode (names/suffixes) + raw flows."""

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

from netbios_collector.parse import _HEXLINE, parse_nbns_hex_lines

log = logging.getLogger("netbios_collector")

SVC = "netbios"
CELL_IP = os.environ.get("AMBER_NETBIOS_CELL_IP", "172.30.253.10")
CELL_ID = os.environ.get("AMBER_NETBIOS_CELL_ID", "netbios-cell-01")
COLLECTOR_ID = os.environ.get("AMBER_NETBIOS_COLLECTOR_ID", "netbios-collector-a")
PROVIDER_ID = os.environ.get("AMBER_NETBIOS_PROVIDER", "nmbd")
LOG_FIFO = os.environ.get("AMBER_NETBIOS_LOG_FIFO", "/run/amber/log/netbios.fifo")
IMAGE_DIGEST = os.environ.get("AMBER_IMAGE_DIGEST", "")
HI_DIGEST = os.environ.get("AMBER_NETBIOS_HI_DIGEST", "")
CELL_INSTANCE_ID = os.environ.get("AMBER_CELL_INSTANCE_ID", os.environ.get("HOSTNAME", "local"))
BPF = "udp port 137"
EXTRA_ARGS = ["-x"]


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

    # tcpdump -x emits a summary line per datagram, then indented hex lines.
    pending_hex: list[str] = []
    pending_hdr = ""
    lock = threading.Lock()

    def flush_hex() -> None:
        nonlocal pending_hex, pending_hdr
        with lock:
            lines, hdr = pending_hex, pending_hdr
            pending_hex, pending_hdr = [], ""
        if not lines:
            return
        rec = parse_nbns_hex_lines(lines)
        if rec is None:
            return
        from ambercell.flow_tracker import parse_tcpdump_line

        pkt = parse_tcpdump_line(hdr)
        if pkt is not None:
            src_ip, src_port = pkt["src_ip"], pkt["src_port"]
        else:
            src_ip, src_port = "0.0.0.0", 0
        session_id = new_session_id("nb")
        raw_flows.emit(
            {
                "session_id": session_id,
                "svc": SVC,
                "provider_id": PROVIDER_ID,
                "cell_id": CELL_ID,
                "collector_id": COLLECTOR_ID,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": CELL_IP,
                "dst_port": 137,
                "transport": "udp",
                "first_seen": rec["ts"],
                "last_seen": rec["ts"],
                "bytes_in": 50,
                "bytes_out": 0,
                "packet_count_in": 1,
                "packet_count_out": 0,
                "pcap_ref": pcap_ref,
                "parser_status": "recognized" if rec["qname"] else "partial",
                "classification_status": "known" if rec["qname"] else "unknown",
                "protocol_guess": "netbios",
            }
        )
        events.emit(
            {
                "event_id": new_event_id(),
                "ts": rec["ts"],
                "svc": SVC,
                "provider_id": PROVIDER_ID,
                "session_id": session_id,
                "cell_id": CELL_ID,
                "collector_id": COLLECTOR_ID,
                "event": "netbios.response" if rec["is_response"] else "netbios.query",
                "src_ip": src_ip,
                "src_port": src_port,
                "tid": rec["tid"],
                "qname": rec["qname"],
                "suffix": rec["suffix"],
                "suffix_name": rec["suffix_name"],
            }
        )

    def on_line(line: str) -> None:
        nonlocal pending_hdr
        if _HEXLINE.match(line):
            with lock:
                pending_hex.append(line)
            return
        flush_hex()
        if " > " in line and "137" in line:
            pending_hdr = line

    stop = threading.Event()
    start_fifo_reader(LOG_FIFO, lambda line: None, stop)
    stream = TcpdumpStream(BPF, extra_args=EXTRA_ARGS, on_line=on_line)

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
        flush_hex()
        stream.stop()
        ring.stop()
        raw_flows.close()
        events.close()
        _write_state()
    return 0


if __name__ == "__main__":
    sys.exit(main())
