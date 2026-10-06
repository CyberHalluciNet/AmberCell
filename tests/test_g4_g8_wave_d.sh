#!/usr/bin/env bash
# G4/G8 negative checks for Wave D orchestration traps (lab + compose static analysis).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() { echo "FAIL: $*"; exit 1; }
pass() { echo "PASS: $*"; }

# G4 — no docker.sock volume/mount in honeypot compose (ignore comment-only lines)
sock_hits="$(grep -R 'docker\.sock' compose.yaml compose.lab.yaml compose.containment.yaml 2>/dev/null | grep -v '^[^:]*:#' || true)"
if [[ -n "$sock_hits" ]]; then
  echo "$sock_hits"
  fail "G4 docker.sock reference in compose"
fi
pass "G4 no docker.sock in compose overlays"

# G4/G8 — trap cells must not be privileged or mount docker socket
for svc in dockerapi-hi kubelet-hi; do
  if awk "/^  ${svc}:/,/^  [a-z].*:/{print}" compose.yaml | grep -q 'privileged: true'; then
    fail "G8 ${svc} is privileged"
  fi
done
pass "G8 trap hi cells not privileged"

# Provider image must not install dockerd or mount sockets (Dockerfile only)
if grep -vi '^#' services/dockerapi/providers/trap/Dockerfile 2>/dev/null | grep -qi 'dockerd\|docker\.sock\|/var/run/docker'; then
  fail "G4 dockerd/docker.sock in dockerapi trap Dockerfile"
fi
pass "G4 dockerapi provider is sandbox mock only"

if grep -qi 'kind\|k3s\|kube-apiserver' services/kubelet/providers/trap/Dockerfile 2>/dev/null; then
  fail "G8 real cluster bits in kubelet trap Dockerfile"
fi
pass "G8 kubelet provider has no real cluster engine"

# State files record trap flag when cells run (optional runtime check)
if [[ "${AMBER_G48_RUNTIME:-0}" == "1" ]]; then
  EVID="${AMBER_EVIDENCE_ROOT:-$ROOT/.ambercell-data}"
  for svc in dockerapi kubelet; do
    st="$EVID/state/${svc}.json"
    [[ -f "$st" ]] || fail "missing state $st (start wave-d first)"
    python3 - "$st" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d.get("trap") is True, "trap flag missing"
assert d.get("provider_id") == "trap"
PY
  done
  pass "G8 runtime state marks traps"
fi

echo "==> G4/G8 Wave D static checks OK (production bars verified on Linux maintainer host)"
