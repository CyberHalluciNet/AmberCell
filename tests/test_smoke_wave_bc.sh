#!/usr/bin/env bash
# Stage-6 Wave B+C smoke — lab published ports (Darwin/Linux).
# Elastic is lab-optional (heavy RAM); set AMBER_SMOKE_SKIP_ELASTIC=1 to skip.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EVID="${AMBER_EVIDENCE_ROOT:-$ROOT/.ambercell-wave-bc-smoke}"

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
export COMPOSE_PROFILES="${COMPOSE_PROFILES:-lab,wave-b,wave-c}"
export AMBER_HTTP_HOST_PORT="${AMBER_HTTP_HOST_PORT:-$(pick_free_port 8080)}"
export AMBER_MYSQL_HOST_PORT="${AMBER_MYSQL_HOST_PORT:-$(pick_free_port 13306)}"
export AMBER_POSTGRES_HOST_PORT="${AMBER_POSTGRES_HOST_PORT:-$(pick_free_port 15432)}"
export AMBER_SMB_HOST_PORT="${AMBER_SMB_HOST_PORT:-$(pick_free_port 1445)}"
export AMBER_MONGO_HOST_PORT="${AMBER_MONGO_HOST_PORT:-$(pick_free_port 27018)}"
export AMBER_ELASTIC_HOST_PORT="${AMBER_ELASTIC_HOST_PORT:-$(pick_free_port 19200)}"
echo "==> lab ports http=$AMBER_HTTP_HOST_PORT mysql=$AMBER_MYSQL_HOST_PORT postgres=$AMBER_POSTGRES_HOST_PORT smb=$AMBER_SMB_HOST_PORT mongo=$AMBER_MONGO_HOST_PORT elastic=$AMBER_ELASTIC_HOST_PORT"

COMPOSE_FILES=(-f "$ROOT/compose.yaml" -f "$ROOT/compose.lab.yaml")

AMBERCTL_BIN="${AMBERCTL_BIN:-}"
if [[ -z "$AMBERCTL_BIN" ]]; then
  (cd "$ROOT/amberctl" && go build -o amberctl .)
  AMBERCTL_BIN="$ROOT/amberctl/amberctl"
fi

WAVE_B=(http mysql postgres)
WAVE_C=(smb mongo)
[[ "${AMBER_SMOKE_SKIP_ELASTIC:-0}" == "1" ]] || WAVE_C+=(elastic)

cleanup() {
  set +e
  for svc in "${WAVE_C[@]}" "${WAVE_B[@]}"; do
    "$AMBERCTL_BIN" down "$svc" 2>/dev/null || true
  done
}
trap cleanup EXIT

rm -rf "$EVID"
docker compose "${COMPOSE_FILES[@]}" --profile wave-b --profile wave-c down --remove-orphans 2>/dev/null || true

"$AMBERCTL_BIN" init

for svc in "${WAVE_B[@]}"; do
  echo "==> up $svc"
  "$AMBERCTL_BIN" up "$svc"
done

sleep 4
"$AMBERCTL_BIN" drill http
"$AMBERCTL_BIN" drill mysql
"$AMBERCTL_BIN" drill postgres

# HTTP trap path + evidence
curl -sf "http://127.0.0.1:${AMBER_HTTP_HOST_PORT}/wp-login.php" >/dev/null || true
curl -sf "http://127.0.0.1:${AMBER_HTTP_HOST_PORT}/" >/dev/null

for svc in "${WAVE_C[@]}"; do
  echo "==> up $svc"
  "$AMBERCTL_BIN" up "$svc"
  sleep "$([[ "$svc" == elastic ]] && echo 25 || echo 5)"
  "$AMBERCTL_BIN" drill "$svc"
done

# Evidence checks (subset — raw flows + at least one JSONL line per started svc)
for svc in "${WAVE_B[@]}" "${WAVE_C[@]}"; do
  flows="$EVID/raw-flows/$svc/flows.jsonl.active"
  events="$EVID/jsonl/$svc/events.jsonl.active"
  test -s "$flows" || { echo "missing raw flows for $svc"; exit 1; }
  echo "==> $svc raw-flow OK"
  if [[ -s "$events" ]]; then
    echo "==> $svc jsonl OK"
  else
    echo "==> $svc jsonl empty (tcp-only drill OK on lab)"
  fi
done

echo "==> Stage-6 Wave B+C smoke OK (lab; G1–G11 not claimed on Darwin)"
