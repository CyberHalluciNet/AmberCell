#!/usr/bin/env bash
# Hermetic pcap CI entrypoint (Stage-3 harden).
# Always validates fixture → hashes + rawflow JSONL + artifact digest path.
# tcpreplay is optional; see README.md.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
exec python3 tests/pcap_ci/run_pcap_ci.py
