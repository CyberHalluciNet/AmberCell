"""Track TCP flows from tcpdump summary lines."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

_LINE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}\.\d+) "
    r"(?:(?P<iface>\S+)\s+(?P<dir>In|Out)\s+)?"
    r"IP (?P<src>[\d.]+)\.(?P<src_port>\d+) > (?P<dst>[\d.]+)\.(?P<dst_port>\d+): "
    r"Flags \[(?P<flags>[^\]]*)\]"
    r"(?:, length (?P<length>\d+))?"
)


def parse_tcpdump_timestamp(line: str) -> str | None:
    m = _LINE.match(line)
    if not m:
        return None
    frac = m.group("time").split(".", 1)[1]
    frac = (frac + "000000000")[:9]
    return f"{m.group('date')}T{m.group('time').split('.')[0]}.{frac}Z".replace(
        " ", "T", 1
    ).split("T", 1)[0] + "T" + m.group("time").split(" ")[0] if False else (
        f"{m.group('date')}T{m.group('time').split('.')[0]}.{frac}Z"
    )


def parse_tcpdump_line(line: str) -> dict | None:
    m = _LINE.match(line)
    if not m:
        return None
    frac = m.group("time").split(".", 1)[1]
    frac = (frac + "000000000")[:9]
    ts = f"{m.group('date')}T{m.group('time').split('.')[0]}.{frac}Z"
    return {
        "ts": ts,
        "src_ip": m.group("src"),
        "src_port": int(m.group("src_port")),
        "dst_ip": m.group("dst"),
        "dst_port": int(m.group("dst_port")),
        "flags": m.group("flags"),
        "length": int(m.group("length") or 0),
    }


@dataclass
class FlowState:
    session_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    first_seen: str = ""
    last_seen: str = ""
    bytes_in: int = 0
    bytes_out: int = 0
    packet_count_in: int = 0
    packet_count_out: int = 0
    parser_status: str = "partial"
    classification_status: str = "known"
    protocol_guess: str = ""
    closed: bool = False
    extra: dict = field(default_factory=dict)

    @property
    def client_key(self) -> tuple[str, int, str, int]:
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port)


class FlowTracker:
    def __init__(self, *, cell_ip: str, on_close: Callable[[FlowState], None] | None = None) -> None:
        self.cell_ip = cell_ip
        self.on_close = on_close
        self._flows: dict[tuple[str, int, str, int], FlowState] = {}
        self._pasv_session: dict[int, str] = {}

    def map_pasv_port(self, port: int, session_id: str) -> None:
        self._pasv_session[port] = session_id

    def session_for_dst_port(self, dst_port: int, dst_ip: str) -> str | None:
        # PASV map is port-keyed; dst_ip check is advisory for multi-cell hosts.
        sid = self._pasv_session.get(dst_port)
        if sid is None:
            return None
        if dst_ip == self.cell_ip or dst_ip == "0.0.0.0":
            return sid
        # Lab published-port path may show a rewritten destination.
        return sid

    def register(self, flow: FlowState) -> None:
        self._flows[flow.client_key] = flow

    def get(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> FlowState | None:
        key = (src_ip, src_port, dst_ip, dst_port)
        rev = (dst_ip, dst_port, src_ip, src_port)
        return self._flows.get(key) or self._flows.get(rev)

    def ingest(self, line: str) -> tuple[str, FlowState | None]:
        """Returns (kind, flow): kind is 'syn', 'packet', 'fin', or 'skip'."""
        pkt = parse_tcpdump_line(line)
        if pkt is None:
            return ("skip", None)

        flags = pkt["flags"]
        key = (pkt["src_ip"], pkt["src_port"], pkt["dst_ip"], pkt["dst_port"])
        rev = (pkt["dst_ip"], pkt["dst_port"], pkt["src_ip"], pkt["src_port"])

        is_syn = "S" in flags and "." not in flags

        if is_syn:
            return ("syn", None)

        flow = self._flows.get(key) or self._flows.get(rev)
        if flow is None:
            return ("skip", None)

        flow.last_seen = pkt["ts"]
        if not flow.first_seen:
            flow.first_seen = pkt["ts"]

        if pkt["dst_ip"] == self.cell_ip:
            flow.bytes_in += pkt["length"]
            flow.packet_count_in += 1
        elif pkt["src_ip"] == self.cell_ip:
            flow.bytes_out += pkt["length"]
            flow.packet_count_out += 1

        if "F" in flags or "R" in flags:
            flow.closed = True
            self._flows.pop(flow.client_key, None)
            if self.on_close:
                self.on_close(flow)
            return ("fin", flow)

        return ("packet", flow)
