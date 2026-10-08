#!/usr/bin/env python3
"""VNC collector — tcp/5900 RFB banner events + SYN-gated raw flows."""

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

from vnc_collector.parse import parse_vnc_line
from ambercell.timeutil import utc_now_rfc3339_nano

log = logging.getLogger("vnc_collector")

SVC = "vnc"
CELL_IP = os.environ.get("AMBER_VNC_CELL_IP", "172.30.252.10")
CELL_ID = os.environ.get("AMBER_RDP_CELL_ID", "vnc-cell-01")
COLLECTOR_ID = os.environ.get("AMBER_RDP_COLLECTOR_ID", "vnc-collector-a")
PROVIDER_ID = os.environ.get("AMBER_VNC_PROVIDER", "tigervnc")
LOG_FIFO = os.environ.get("AMBER_VNC_LOG_FIFO", "/run/amber/log/vnc.fifo")
IMAGE_DIGEST = os.environ.get("AMBER_IMAGE_DIGEST", "")
HI_DIGEST = os.environ.get("AMBER_VNC_HI_DIGEST", "")
CELL_INSTANCE_ID = os.environ.get("AMBER_CELL_INSTANCE_ID", os.environ.get("HOSTNAME", "local"))
BPF = "tcp port 5900"
EXTRA_ARGS = []


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

    def emit_flow(ts, src_ip, src_port, dst_ip, dst_port, transport, length, status) -> str:
        relax = os.environ.get("AMBER_VNC_RELAX_DST", "0") == "1"
        session_id = new_session_id("vn")
        inbound = dst_ip == CELL_IP or (relax and dst_ip in ("127.0.0.1", "0.0.0.0"))
        raw_flows.emit(
            {
                "session_id": session_id,
                "svc": SVC,
                "provider_id": PROVIDER_ID,
                "cell_id": CELL_ID,
                "collector_id": COLLECTOR_ID,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "transport": transport,
                "first_seen": ts,
                "last_seen": ts,
                "bytes_in": length if inbound else 0,
                "bytes_out": 0 if inbound else length,
                "packet_count_in": 1 if inbound else 0,
                "packet_count_out": 0 if inbound else 1,
                "pcap_ref": pcap_ref,
                "parser_status": status,
                "classification_status": "known" if status == "recognized" else "unknown",
                "protocol_guess": "rdp",
            }
        )
        return session_id

    def on_syn(line: str) -> bool:
        if "Flags [S]" not in line or "Flags [S.]" in line or " > " not in line:
            return False
        from ambercell.flow_tracker import parse_tcpdump_line

        pkt = parse_tcpdump_line(line)
        if pkt is None or pkt["dst_port"] != 5900:
            return False
        emit_flow(pkt["ts"], pkt["src_ip"], pkt["src_port"], pkt["dst_ip"], 5900, "tcp", 0, "partial")
        return True

    def on_line(line: str) -> None:
        if on_syn(line):
            return
        ev = parse_vnc_line(line)
        if ev is None:
            return
        session_id = emit_flow(ev["ts"], "0.0.0.0", 0, CELL_IP, 5900, "tcp", len(ev["raw"]), "recognized")
        events.emit(
            {
                "event_id": new_event_id(),
                "ts": ev["ts"],
                "svc": SVC,
                "provider_id": PROVIDER_ID,
                "session_id": session_id,
                "cell_id": CELL_ID,
                "collector_id": COLLECTOR_ID,
                "event": ev["event"],
                "protocol_version": ev["protocol_version"],
            }
        )

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
        stream.stop()
        ring.stop()
        raw_flows.close()
        events.close()
        _write_state()
    return 0


if __name__ == "__main__":
    sys.exit(main())
