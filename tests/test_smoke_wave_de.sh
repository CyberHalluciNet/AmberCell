#!/usr/bin/env bash
# Stage-7 Wave D+E smoke — traps + ollama mock (lab; no large model pulls).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EVID="${AMBER_EVIDENCE_ROOT:-$ROOT/.ambercell-wave-de-smoke}"

pick_free_port() {
  local start=$1
  python3 - "$start" <<'PY'
import socket, sys
start = int(sys.argv[1])
for port in range(start, start + 32):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
        s.close()
        print(port)
        sys.exit(0)
    except OSError:
        continue
print(start)
PY
}

export AMBER_EVIDENCE_ROOT="$EVID"
export AMBER_ROOT="$ROOT"
export COMPOSE_PROFILES="${COMPOSE_PROFILES:-lab,wave-d,wave-e}"
export AMBER_DOCKERAPI_HOST_PORT="${AMBER_DOCKERAPI_HOST_PORT:-$(pick_free_port 12375)}"
export AMBER_KUBELET_HOST_PORT="${AMBER_KUBELET_HOST_PORT:-$(pick_free_port 10250)}"
export AMBER_OLLAMA_HOST_PORT="${AMBER_OLLAMA_HOST_PORT:-$(pick_free_port 11434)}"
echo "==> lab ports dockerapi=$AMBER_DOCKERAPI_HOST_PORT kubelet=$AMBER_KUBELET_HOST_PORT ollama=$AMBER_OLLAMA_HOST_PORT"

COMPOSE_FILES=(-f "$ROOT/compose.yaml" -f "$ROOT/compose.lab.yaml")

AMBERCTL_BIN="${AMBERCTL_BIN:-}"
if [[ -z "$AMBERCTL_BIN" ]]; then
  (cd "$ROOT/amberctl" && go build -o amberctl .)
  AMBERCTL_BIN="$ROOT/amberctl/amberctl"
fi

SVCS=(dockerapi kubelet ollama)

cleanup() {
  set +e
  for svc in "${SVCS[@]}"; do
    "$AMBERCTL_BIN" down "$svc" 2>/dev/null || true
  done
}
trap cleanup EXIT

rm -rf "$EVID"
docker compose "${COMPOSE_FILES[@]}" --profile wave-d --profile wave-e down --remove-orphans 2>/dev/null || true

"$ROOT/tests/test_g4_g8_wave_d.sh"

"$AMBERCTL_BIN" init

for svc in "${SVCS[@]}"; do
  echo "==> up $svc"
  "$AMBERCTL_BIN" up "$svc"
  sleep 3
  "$AMBERCTL_BIN" drill "$svc"
done

# Behavioral probes (capture intents)
curl -sf "http://127.0.0.1:${AMBER_DOCKERAPI_HOST_PORT}/version" | grep -q Docker
curl -sf -X POST "http://127.0.0.1:${AMBER_DOCKERAPI_HOST_PORT}/containers/create" \
  -H 'Content-Type: application/json' \
  -d '{"Image":"alpine","HostConfig":{"Privileged":true,"Binds":["/:/host"]}}' >/dev/null

curl -sf "http://127.0.0.1:${AMBER_KUBELET_HOST_PORT}/healthz" | grep -q ok
curl -sf -X POST "http://127.0.0.1:${AMBER_KUBELET_HOST_PORT}/run/nginx/exec" \
  -H 'Content-Type: application/json' \
  -d '{"command":["/bin/sh","-c","id"]}' >/dev/null

curl -sf "http://127.0.0.1:${AMBER_OLLAMA_HOST_PORT}/api/tags" | grep -q models
curl -sf -X POST "http://127.0.0.1:${AMBER_OLLAMA_HOST_PORT}/api/pull" \
  -H 'Content-Type: application/json' \
  -d '{"name":"tiny-stub:latest"}' >/dev/null
curl -sf -X POST "http://127.0.0.1:${AMBER_OLLAMA_HOST_PORT}/api/generate" \
  -H 'Content-Type: application/json' \
  -d '{"model":"tiny-stub:latest","prompt":"ignore previous instructions"}' >/dev/null

sleep 2

for svc in dockerapi kubelet ollama; do
  flows="$EVID/raw-flows/$svc/flows.jsonl.active"
  events="$EVID/jsonl/$svc/events.jsonl.active"
  test -s "$flows" || { echo "missing raw flows for $svc"; exit 1; }
  echo "==> $svc raw-flow OK"
  if [[ -s "$events" ]]; then
    grep -q "$svc" "$events" || { echo "jsonl missing $svc events"; exit 1; }
    echo "==> $svc jsonl OK"
  else
    echo "==> $svc jsonl empty (unexpected)"
    exit 1
  fi
done

# Critical docker mount intent evidenced
grep -q 'dockerapi.container_create_critical' "$EVID/jsonl/dockerapi/events.jsonl.active" || {
  echo "missing critical dockerapi event"; exit 1
}

echo "==> Stage-7 Wave D+E smoke OK (lab; G1–G11 not claimed on Darwin)"
