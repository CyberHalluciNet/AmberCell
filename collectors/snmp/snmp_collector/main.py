#!/usr/bin/env python3
"""SNMP collector — UDP+TCP/161 get/set/trap decode JSONL + raw flows."""

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

from snmp_collector.parse import OP_EVENTS, parse_snmp_line

log = logging.getLogger("snmp_collector")

SVC = "snmp"
CELL_IP = os.environ.get("AMBER_SNMP_CELL_IP", "172.30.190.10")
CELL_ID = os.environ.get("AMBER_SNMP_CELL_ID", "snmp-cell-01")
COLLECTOR_ID = os.environ.get("AMBER_SNMP_COLLECTOR_ID", "snmp-collector-a")
PROVIDER_ID = os.environ.get("AMBER_SNMP_PROVIDER", "snmpd")
LOG_FIFO = os.environ.get("AMBER_SNMP_LOG_FIFO", "/run/amber/log/snmp.fifo")
IMAGE_DIGEST = os.environ.get("AMBER_IMAGE_DIGEST", "")
HI_DIGEST = os.environ.get("AMBER_SNMP_HI_DIGEST", "")
CELL_INSTANCE_ID = os.environ.get("AMBER_CELL_INSTANCE_ID", os.environ.get("HOSTNAME", "local"))
BPF = "udp port 161 or tcp port 161"
EXTRA_ARGS = ["-v"]


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

    def base(rec: dict, session_id: str) -> dict:
        return {
            "event_id": new_event_id(),
            "ts": rec["ts"],
            "svc": SVC,
            "provider_id": PROVIDER_ID,
            "session_id": session_id,
            "cell_id": CELL_ID,
            "collector_id": COLLECTOR_ID,
            "src_ip": rec["src_ip"],
            "src_port": rec["src_port"],
            "dst_ip": rec["dst_ip"],
            "dst_port": rec["dst_port"],
        }

    def emit_flow(rec: dict, session_id: str, transport: str, status: str) -> None:
        relax = os.environ.get("AMBER_SNMP_RELAX_DST", "0") == "1"
        inbound = rec["dst_ip"] == CELL_IP or (relax and rec["dst_ip"] in ("127.0.0.1", "0.0.0.0"))
        length = rec.get("length", 0)
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
                "transport": transport,
                "first_seen": rec["ts"],
                "last_seen": rec["ts"],
                "bytes_in": length if inbound else 0,
                "bytes_out": 0 if inbound else length,
                "packet_count_in": 1 if inbound else 0,
                "packet_count_out": 0 if inbound else 1,
                "pcap_ref": pcap_ref,
                "parser_status": status,
                "classification_status": "known" if status == "recognized" else "unknown",
                "protocol_guess": "snmp",
            }
        )

    def on_line(line: str) -> None:
        transport = "udp"
        rec = parse_snmp_line(line, transport)
        if rec is None:
            # tcpdump prints TCP summary lines (Flags) separately; re-tag.
            rec = parse_snmp_line(line, "tcp")
            transport = "tcp"
            if rec is None:
                return
        rec["transport"] = transport
        session_id = new_session_id("sn")
        status = "recognized" if rec["kind"] == "snmp" else "partial"
        emit_flow(rec, session_id, rec["transport"], status)
        if rec["kind"] == "snmp":
            events.emit(
                {
                    **base(rec, session_id),
                    "event": OP_EVENTS.get(rec["op"], "snmp.op"),
                    "version": rec["version"],
                    "snmp_op": rec["op"],
                    "reqid": rec["reqid"],
                    "oids": rec["oids"],
                    "transport": rec["transport"],
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
