#!/usr/bin/env bash
# Isolation kill bars G2–G4 + IPv6 drop + FTP active-mode deny (Linux production host).
# Lab stub: documents checks; skips on Darwin/non-Linux.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "SKIP: isolation tests require Linux (G2–G4, nftables, icc); Darwin lab exempt"
  exit 0
fi

if [[ "${AMBER_RUN_ISOLATION:-}" != "1" ]]; then
  echo "SKIP: set AMBER_RUN_ISOLATION=1 on dedicated Linux lab host to run negative tests"
  exit 0
fi

echo "==> G2 icc=false (compose ambernet)"
grep -q 'enable_icc: false' "$ROOT/compose.yaml" || grep -q 'enable_icc: false' "$ROOT/compose.lab.yaml"

echo "==> G3 metadata drop stub in egress.nft"
grep -q '169.254.169.254' "$ROOT/nftables/egress.nft"

echo "==> IPv6 drop stub"
grep -q 'ip6' "$ROOT/nftables/egress.nft"

echo "==> FTP active mode deny in provider"
grep -rq 'port_enable=NO' "$ROOT/services/ftp/providers/" || grep -rq 'PORT' "$ROOT/collectors/ftp/"

echo "OK: isolation contract (manual nft/conntrack execution still operator-driven)"
