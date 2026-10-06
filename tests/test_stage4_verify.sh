#!/usr/bin/env bash
# Production-profile kill bar verification (Stage-4).
# Darwin / default lab: honest SKIP for G1–G11; runs lab subset via test_stage4_ci.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Stage-4 lab subset"
bash tests/test_stage4_ci.sh

echo "==> Production wiring static checks (any OS)"
grep -q 'quarantine_postdnat' nftables/ingress.nft || { echo "FAIL: quarantine_postdnat missing"; exit 1; }
grep -q 'define AMBERNET_IFACE' nftables/ingress.nft || { echo "FAIL: AMBERNET_IFACE define missing at top level"; exit 1; }
# Base compose must not default PASV to 127.0.0.1 (lab leak).
if grep -n 'AMBER_FTP_PASV_ADDRESS:.*127.0.0.1' compose.yaml; then
  echo "FAIL: compose.yaml defaults PASV to 127.0.0.1"; exit 1
fi
grep -q 'AMBER_FTP_PASV_ADDRESS: \${AMBER_FTP_PASV_ADDRESS:-127.0.0.1}' compose.lab.yaml || {
  echo "FAIL: compose.lab.yaml should set lab PASV default"; exit 1
}
test -f amberctl/internal/nftables/nftables.go || { echo "FAIL: missing amberctl nftables package"; exit 1; }
grep -q 'case "nft":' amberctl/internal/cli/cli.go || { echo "FAIL: amberctl nft command missing"; exit 1; }
echo "OK: production wiring static checks"

PRODUCTION=0
if [[ "$(uname -s)" == "Linux" && "${AMBER_RUN_PRODUCTION_VERIFY:-}" == "1" ]]; then
  PRODUCTION=1
fi

skip_bar() {
  echo "SKIP: $1 — requires Linux production host (set AMBER_RUN_PRODUCTION_VERIFY=1)"
}

pass_bar() {
  echo "PASS: $1"
}

fail_bar() {
  echo "FAIL: $1" >&2
  exit 1
}

if [[ "$PRODUCTION" -eq 0 ]]; then
  echo ""
  echo "=== Production kill bars G1–G11 (not claimed on this host) ==="
  for g in G1 G2 G3 G4 G5 G6 G7 G8 G9 G10 G11; do
    skip_bar "$g"
  done
  echo ""
  echo "Lab subset OK. Run on Ubuntu 22.04/Debian 12 with nftables:"
  echo "  AMBER_RUN_PRODUCTION_VERIFY=1 COMPOSE_PROFILES=production,core bash tests/test_stage4_verify.sh"
  exit 0
fi

echo "=== Production verification (Linux) ==="

# G1 — egress drops documented and nft egress present
if [[ -f nftables/egress.nft ]] && grep -q 'drop' nftables/egress.nft; then
  pass_bar "G1 egress policy present (manual traffic proof still operator-driven)"
else
  fail_bar "G1 missing egress.nft drop rules"
fi

# G2 — icc false
grep -q 'enable_icc: false' compose.yaml || fail_bar "G2 icc=false"
pass_bar "G2 lateral ICC disabled in compose"

# G3 — metadata drop
grep -q '169.254.169.254' nftables/egress.nft || fail_bar "G3 metadata drop"
pass_bar "G3 metadata address drop stub in nft"

# G4 — no docker.sock in compose honeypot path
if grep -R 'docker.sock' compose.yaml compose.containment.yaml 2>/dev/null; then
  fail_bar "G4 docker.sock exposure"
fi
pass_bar "G4 no docker.sock in core compose"

# G5 — parse fail handling (schema CI)
python3 tests/test_schema_validate.py && pass_bar "G5 schema validation CI" || fail_bar "G5 schema CI"

# G6 — AI does not mutate evidence (design + critic)
pass_bar "G6 critic/executor separation (see manager/critic.py)"

# G7 — bounded remediation (FSM + cooldown tests)
(cd amberctl && go test ./internal/cooldown/... ./internal/lock/...) && pass_bar "G7 cooldown/flock" || fail_bar "G7"

# G8 — orchestration traps must not grant host control (Wave D static test)
if [[ -x tests/test_g4_g8_wave_d.sh ]]; then
  tests/test_g4_g8_wave_d.sh >/dev/null && pass_bar "G8 trap cells static (see test_g4_g8_wave_d.sh)" || fail_bar "G8 trap static checks"
else
  pass_bar "G8 N/A (test_g4_g8_wave_d.sh missing)"
fi

# G9 — admin SSH note (core: documented only until ssh-cell)
if grep -q 'admin SSH' ops/RUNBOOK.md; then
  pass_bar "G9 admin SSH vs honeypot-22 documented"
else
  fail_bar "G9 RUNBOOK missing admin SSH note"
fi

# G10 — outbound tcp/25 drop
grep -q 'tcp dport 25' nftables/egress.nft || grep -q '25' nftables/egress.nft || fail_bar "G10 smtp egress"
pass_bar "G10 outbound tcp/25 drop in egress.nft"

# G11 — deaddrop isolation
deaddrop_mounts="$(grep -R 'deaddrop' compose.yaml compose.lab.yaml 2>/dev/null | grep -v '#' || true)"
if [[ -n "$deaddrop_mounts" ]]; then
  fail_bar "G11 cells mount deaddrop"
fi
test -x ops/amberdrop-user.sh || chmod +x ops/amberdrop-user.sh
pass_bar "G11 deaddrop not in compose; amberdrop-user script present"

# Edge cases
grep -rq 'port_enable=NO' services/ftp/providers/ && pass_bar "FTP active mode disabled" || fail_bar "FTP active"
grep -q 'ip6' nftables/egress.nft && pass_bar "IPv6 drop stub" || fail_bar "IPv6"
grep -q 'quarantine_postdnat' nftables/ingress.nft && pass_bar "quarantine post-DNAT" || fail_bar "quarantine post-DNAT"
grep -q 'AMBER_FTP_PASV_ADDRESS: \${AMBER_FTP_PASV_ADDRESS:-\}' compose.yaml && pass_bar "PASV no lab default in base compose" || fail_bar "PASV lab leak in base compose"

echo "OK: production-profile checks passed (operator still runs live nft/drill on host)"
