#!/usr/bin/env python3
"""DNS collector — udp/tcp 53 query/response/AXFR/CHAOS JSONL.

Authoritative-only honeypot cells must never recurse upstream (G13); this
collector captures whatever reaches the cell: parse tcpdump's native DNS decode
on the summary line, emit one raw flow per query (unknown traffic never drops,
G5), plus dns.* normalized events (query, response, axfr_attempt, chaos_probe,
update_attempt).
"""

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

from dns_collector.parse import (
    AXFR_TYPES,
    from_cell,
    is_chaos_probe,
    parse_dns_line,
    toward_cell,
)

log = logging.getLogger("dns_collector")

SVC = "dns"
CELL_IP = os.environ.get("AMBER_DNS_CELL_IP", "172.30.170.10")
CELL_ID = os.environ.get("AMBER_DNS_CELL_ID", "dns-cell-01")
COLLECTOR_ID = os.environ.get("AMBER_DNS_COLLECTOR_ID", "dns-collector-a")
PROVIDER_ID = os.environ.get("AMBER_DNS_PROVIDER", "coredns")
LOG_FIFO = os.environ.get("AMBER_DNS_LOG_FIFO", "/run/amber/log/dns.fifo")
IMAGE_DIGEST = os.environ.get("AMBER_IMAGE_DIGEST", "")
HI_DIGEST = os.environ.get("AMBER_DNS_HI_DIGEST", "")
CELL_INSTANCE_ID = os.environ.get("AMBER_CELL_INSTANCE_ID", os.environ.get("HOSTNAME", "local"))
BPF = "udp port 53 or tcp port 53"
PENDING_LIMIT = 4096


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


def _relax_dst() -> bool:
    return os.environ.get("AMBER_DNS_RELAX_DST", "0") == "1"


class DnsSessionBook:
    """Tracks pending queries so responses correlate to the query session."""

    def __init__(self) -> None:
        self._pending: dict[tuple, dict] = {}
        self._lock = threading.Lock()

    @staticmethod
    def query_key(rec: dict) -> tuple:
        return (rec["qid"], rec["src_ip"], rec["src_port"], rec["dst_ip"], rec["dst_port"])

    @staticmethod
    def response_key(rec: dict) -> tuple:
        return (
            rec["qid"],
            rec["dst_ip"],
            rec["dst_port"],
            rec["src_ip"],
            rec["src_port"],
        )

    def put_query(self, rec: dict, session_id: str) -> None:
        with self._lock:
            if len(self._pending) >= PENDING_LIMIT:
                # Drop the oldest pending entries; raw flows are already written.
                for k in list(self._pending.keys())[: PENDING_LIMIT // 4]:
                    self._pending.pop(k, None)
            self._pending[self.query_key(rec)] = {"session_id": session_id, **rec}

    def take_for_response(self, rec: dict) -> dict | None:
        with self._lock:
            return self._pending.pop(self.response_key(rec), None)


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

    raw_flows = RawFlowEmitter(raw_path, seq)
    events = EventEmitter(event_path, seq)
    book = DnsSessionBook()
    relax = _relax_dst()

    def base_record(rec: dict, session_id: str) -> dict:
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

    def emit_raw_flow(rec: dict, session_id: str, status: str, guess: str) -> None:
        inbound = toward_cell(rec, cell_ip=CELL_IP, relax=relax)
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
                "transport": rec["transport"],
                "first_seen": rec["ts"],
                "last_seen": rec["ts"],
                "bytes_in": length if inbound else 0,
                "bytes_out": 0 if inbound else length,
                "packet_count_in": 1 if inbound else 0,
                "packet_count_out": 0 if inbound else 1,
                "pcap_ref": pcap_ref,
                "parser_status": status,
                "classification_status": "known" if status == "recognized" else "unknown",
                "protocol_guess": guess,
            }
        )

    def special_events(rec: dict, session_id: str) -> None:
        qtype = (rec.get("qtype") or "").upper()
        if qtype in AXFR_TYPES:
            events.emit(
                {
                    **base_record(rec, session_id),
                    "event": "dns.axfr_attempt",
                    "qid": rec["qid"],
                    "qtype": qtype,
                    "qname": rec.get("qname", ""),
                    "qclass": rec.get("qclass", "IN"),
                    "transport": rec["transport"],
                }
            )
        elif is_chaos_probe(rec):
            events.emit(
                {
                    **base_record(rec, session_id),
                    "event": "dns.chaos_probe",
                    "qid": rec["qid"],
                    "qtype": qtype,
                    "qname": rec.get("qname", ""),
                    "qclass": rec.get("qclass", "CH"),
                    "transport": rec["transport"],
                }
            )
        elif rec.get("update"):
            events.emit(
                {
                    **base_record(rec, session_id),
                    "event": "dns.update_attempt",
                    "qid": rec["qid"],
                    "transport": rec["transport"],
                }
            )

    def handle_query(rec: dict) -> None:
        session_id = new_session_id("dn")
        emit_raw_flow(rec, session_id, "recognized", "dns")
        if rec["kind"] == "query":
            # Only genuine queries become pending; spoofed responses sent to
            # the cell keep a raw flow but never enter the correlation map.
            book.put_query(rec, session_id)
            events.emit(
                {
                    **base_record(rec, session_id),
                    "event": "dns.query",
                    "qid": rec["qid"],
                    "qtype": rec.get("qtype", ""),
                    "qname": rec.get("qname", ""),
                    "qclass": rec.get("qclass", "IN"),
                    "dns_flags": rec.get("dns_flags", ""),
                    "edns": rec.get("edns", False),
                    "truncated": rec.get("truncated", False),
                    "transport": rec["transport"],
                }
            )
            special_events(rec, session_id)

    def handle_response(rec: dict) -> None:
        pending = book.take_for_response(rec)
        session_id = pending["session_id"] if pending else new_session_id("dn")
        record = {
            **base_record(rec, session_id),
            "event": "dns.response",
            "qid": rec["qid"],
            "rcode": rec.get("rcode", ""),
            "ancount": rec.get("ancount", 0),
            "nscount": rec.get("nscount", 0),
            "arcount": rec.get("arcount", 0),
            "bytes_out": rec.get("length", 0),
            "truncated": rec.get("truncated", False),
            "transport": rec["transport"],
        }
        if pending:
            record["qtype"] = pending.get("qtype", "")
            record["qname"] = pending.get("qname", "")
        events.emit(record)

    def handle_other(rec: dict) -> None:
        """Port-53 traffic outside the client→cell query direction."""
        if rec["kind"] == "undecoded":
            # TCP handshake/ACK lines carry no DNS decode and would spam raw
            # flows per packet; the decoded TCP DNS lines carry the exchange.
            # Undecoded UDP/53 is genuine unknown traffic — raw flow (G5).
            if rec["transport"] == "tcp":
                return
            emit_raw_flow(rec, new_session_id("dn"), "partial", "dns-unknown")
            return
        session_id = new_session_id("dn")
        emit_raw_flow(rec, session_id, "recognized", "dns")
        if rec["kind"] == "query":
            events.emit(
                {
                    **base_record(rec, session_id),
                    "event": "dns.query",
                    "qid": rec["qid"],
                    "qtype": rec.get("qtype", ""),
                    "qname": rec.get("qname", ""),
                    "qclass": rec.get("qclass", "IN"),
                    "dns_flags": rec.get("dns_flags", ""),
                    "edns": rec.get("edns", False),
                    "truncated": rec.get("truncated", False),
                    "transport": rec["transport"],
                }
            )
            special_events(rec, session_id)

    def on_line(line: str, transport: str) -> None:
        rec = parse_dns_line(line)
        if rec is None:
            return
        rec["transport"] = transport
        if rec["kind"] == "undecoded":
            handle_other(rec)
            return
        if toward_cell(rec, cell_ip=CELL_IP, relax=relax):
            handle_query(rec)
        elif from_cell(rec, cell_ip=CELL_IP, relax=relax) and rec["kind"] == "response":
            handle_response(rec)
        else:
            # From-cell queries (recursion attempts — G13 signal) and any
            # other decoded port-53 traffic.
            handle_other(rec)

    stop = threading.Event()
    start_fifo_reader(LOG_FIFO, lambda line: None, stop)
    streams = [
        TcpdumpStream("udp port 53", on_line=lambda l: on_line(l, "udp")),
        TcpdumpStream("tcp port 53", on_line=lambda l: on_line(l, "tcp")),
    ]

    def _shutdown(signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    for s in streams:
        s.start()

    try:
        while not stop.is_set():
            stop.wait(1.0)
            if not ring.running():
                break
    finally:
        for s in streams:
            s.stop()
        ring.stop()
        raw_flows.close()
        events.close()
        _write_state()
    return 0


if __name__ == "__main__":
    sys.exit(main())
