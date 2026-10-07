"""Unit tests for DNS tcpdump-line parsing and CHAOS / direction helpers."""

from __future__ import annotations

import os
import sys
import unittest

# Allow `python3 -m unittest` from repo root or collectors/dns.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns_collector.parse import (  # noqa: E402
    from_cell,
    is_chaos_probe,
    parse_dns_line,
    toward_cell,
)

CELL = "172.30.170.10"


def _line(body: str, *, src="1.2.3.4.53000", dst=f"{CELL}.53") -> str:
    return f"2026-10-07 12:00:00.123456 IP {src} > {dst}: {body}"


class ParseDnsLineTests(unittest.TestCase):
    def test_lure_a_query(self) -> None:
        rec = parse_dns_line(_line("16640+ A? www.ambercell.lab. (32)"))
        assert rec is not None
        self.assertEqual(rec["kind"], "query")
        self.assertEqual(rec["qtype"], "A")
        self.assertEqual(rec["qname"], "www.ambercell.lab")
        self.assertEqual(rec["qclass"], "IN")
        self.assertEqual(rec["length"], 32)

    def test_chaos_modern_tcpdump(self) -> None:
        # tcpdump prints non-IN class between type and '?'.
        rec = parse_dns_line(_line("16640+ TXT CH? version.bind. (37)"))
        assert rec is not None
        self.assertEqual(rec["kind"], "query")
        self.assertEqual(rec["qtype"], "TXT")
        self.assertEqual(rec["qclass"], "CH")
        self.assertEqual(rec["qname"], "version.bind")
        self.assertTrue(is_chaos_probe(rec))

    def test_chaos_trailing_class(self) -> None:
        rec = parse_dns_line(_line("16640+ TXT? version.bind. CH (37)"))
        assert rec is not None
        self.assertEqual(rec["qtype"], "TXT")
        self.assertEqual(rec["qclass"], "CH")
        self.assertTrue(is_chaos_probe(rec))

    def test_chaos_paren_class(self) -> None:
        rec = parse_dns_line(_line("16640+ TXT? version.bind. (CH)"))
        assert rec is not None
        self.assertEqual(rec["qclass"], "CH")
        self.assertTrue(is_chaos_probe(rec))

    def test_axfr_query(self) -> None:
        rec = parse_dns_line(_line("16640+ AXFR? corp.example.net. (40)"))
        assert rec is not None
        self.assertEqual(rec["qtype"], "AXFR")
        self.assertFalse(is_chaos_probe(rec))

    def test_refused_response(self) -> None:
        rec = parse_dns_line(
            _line("16640 0/0/0 RefUsed (29)", src=f"{CELL}.53", dst="1.2.3.4.53000")
        )
        assert rec is not None
        self.assertEqual(rec["kind"], "response")
        self.assertEqual(rec["rcode"], "Refused")

    def test_nxdomain_response(self) -> None:
        rec = parse_dns_line(
            _line("16640 0/1/0 NXDomain (48)", src=f"{CELL}.53", dst="1.2.3.4.53000")
        )
        assert rec is not None
        self.assertEqual(rec["rcode"], "NXDomain")
        self.assertEqual(rec["nscount"], 1)


class DirectionTests(unittest.TestCase):
    def test_toward_cell_exact_ip(self) -> None:
        rec = {"dst_port": 53, "dst_ip": CELL, "src_port": 53000, "src_ip": "1.2.3.4"}
        self.assertTrue(toward_cell(rec, cell_ip=CELL, relax=False))
        self.assertFalse(from_cell(rec, cell_ip=CELL, relax=False))

    def test_relax_only_loopback_not_any_resolver(self) -> None:
        # Cell as client toward an external resolver (recursion attempt / G13).
        # Source port is ephemeral — must not classify as toward_cell even with
        # lab relax, so the collector's else/handle_other path can signal it.
        external = {
            "dst_port": 53,
            "dst_ip": "8.8.8.8",
            "src_port": 53000,
            "src_ip": CELL,
        }
        self.assertFalse(toward_cell(external, cell_ip=CELL, relax=True))
        self.assertFalse(from_cell(external, cell_ip=CELL, relax=True))

        loopback = {
            "dst_port": 53,
            "dst_ip": "127.0.0.1",
            "src_port": 53000,
            "src_ip": "9.9.9.9",
        }
        self.assertFalse(toward_cell(loopback, cell_ip=CELL, relax=False))
        self.assertTrue(toward_cell(loopback, cell_ip=CELL, relax=True))

        # Authoritative answer from the cell: src port 53.
        response = {
            "dst_port": 53000,
            "dst_ip": "1.2.3.4",
            "src_port": 53,
            "src_ip": CELL,
        }
        self.assertTrue(from_cell(response, cell_ip=CELL, relax=False))
        self.assertFalse(toward_cell(response, cell_ip=CELL, relax=True))


if __name__ == "__main__":
    unittest.main()
