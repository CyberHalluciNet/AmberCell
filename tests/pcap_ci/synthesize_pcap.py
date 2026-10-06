#!/usr/bin/env python3
"""Synthesize a minimal classic pcap (stdlib only; no scapy/malware).

One Ethernet/IPv4/TCP SYN: 203.0.113.10:51820 -> 172.30.30.10:21 (FTP control).
Regenerate fixtures with: python3 tests/pcap_ci/synthesize_pcap.py
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

REPO = Path(__file__).resolve().parent
DEFAULT_OUT = REPO / "fixtures" / "ftp_pasv_syn.pcap"

# Fixed addresses matching docs/schemas/examples/rawflow.example.json
SRC_IP = (203, 0, 113, 10)
DST_IP = (172, 30, 30, 10)
SRC_PORT = 51820
DST_PORT = 21


def _ipv4(addr: tuple[int, int, int, int]) -> bytes:
    return bytes(addr)


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def build_tcp_syn_frame() -> bytes:
    eth = (
        b"\x02\x00\x00\x00\x00\x02"  # dst MAC
        + b"\x02\x00\x00\x00\x00\x01"  # src MAC
        + b"\x08\x00"  # IPv4
    )
    # TCP header (20 bytes) — SYN, seq=1, window=64240
    tcp_wo_cksum = struct.pack(
        "!HHIIBBHHH",
        SRC_PORT,
        DST_PORT,
        1,  # seq
        0,  # ack
        (5 << 4),  # data offset
        0x02,  # SYN
        64240,
        0,  # checksum placeholder
        0,  # urg
    )
    ip_hdr_len = 20
    tcp_len = len(tcp_wo_cksum)
    total_len = ip_hdr_len + tcp_len
    ip_wo_cksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        0xAC01,  # id
        0x4000,  # DF
        64,
        6,  # TCP
        0,
        _ipv4(SRC_IP),
        _ipv4(DST_IP),
    )
    ip_ck = _checksum(ip_wo_cksum)
    ip_hdr = ip_wo_cksum[:10] + struct.pack("!H", ip_ck) + ip_wo_cksum[12:]

    pseudo = (
        _ipv4(SRC_IP)
        + _ipv4(DST_IP)
        + struct.pack("!BBH", 0, 6, tcp_len)
        + tcp_wo_cksum
    )
    tcp_ck = _checksum(pseudo)
    tcp = tcp_wo_cksum[:16] + struct.pack("!H", tcp_ck) + tcp_wo_cksum[18:]
    return eth + ip_hdr + tcp


def write_pcap(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    frame = build_tcp_syn_frame()
    # Global header: magic, v2.4, thiszone=0, sigfigs=0, snaplen, LINKTYPE_ETHERNET=1
    gh = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    # Packet header: ts_sec, ts_usec, incl_len, orig_len — fixed for hermetic hashes
    ph = struct.pack("<IIII", 1696494731, 123456, len(frame), len(frame))
    path.write_bytes(gh + ph + frame)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-o", "--output", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()
    write_pcap(args.output)
    print(f"wrote {args.output} ({args.output.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
