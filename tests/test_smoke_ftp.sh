#!/usr/bin/env bash
# Stage-0B FTP smoke: LISTEN, PASV, Active Mode reject, evidence, sample AI decision.
# Lab path (Compose published ports). Production uses nftables (see nftables/).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EVID="${AMBER_EVIDENCE_ROOT:-$ROOT/.ambercell-smoke}"
HOST_PORT="${AMBER_FTP_HOST_PORT:-2121}"
PASV_ADDR="${AMBER_FTP_PASV_ADDRESS:-127.0.0.1}"
FTP_PROVIDER="${AMBER_FTP_PROVIDER:-vsftpd}"
export AMBER_EVIDENCE_ROOT="$EVID"
export AMBER_FTP_HOST_PORT="$HOST_PORT"
export AMBER_FTP_PASV_ADDRESS="$PASV_ADDR"
export AMBER_FTP_PROVIDER="$FTP_PROVIDER"
export COMPOSE_PROFILES="${COMPOSE_PROFILES:-lab,core}"
export AMBER_ROOT="$ROOT"
COMPOSE_FILES=(-f "$ROOT/compose.yaml" -f "$ROOT/compose.lab.yaml")

PROVIDER_DIR="$ROOT/services/ftp/providers/${FTP_PROVIDER}"
if [[ ! -f "$PROVIDER_DIR/Dockerfile" ]]; then
  echo "FAIL: unknown AMBER_FTP_PROVIDER=${FTP_PROVIDER} (no Dockerfile at ${PROVIDER_DIR})" >&2
  exit 1
fi
echo "==> FTP provider: ${FTP_PROVIDER}"

AMBERCTL_BIN="${AMBERCTL_BIN:-}"
if [[ -z "$AMBERCTL_BIN" ]]; then
  if [[ -x "$ROOT/amberctl/amberctl" ]]; then
    AMBERCTL_BIN="$ROOT/amberctl/amberctl"
  else
    echo "==> building amberctl"
    (cd "$ROOT/amberctl" && go build -o amberctl .)
    AMBERCTL_BIN="$ROOT/amberctl/amberctl"
  fi
fi

cleanup() {
  set +e
  "$AMBERCTL_BIN" down ftp 2>/dev/null || true
  docker compose "${COMPOSE_FILES[@]}" --profile core rm -f ftp-hi ftp-collector 2>/dev/null || true
}
trap cleanup EXIT

echo "==> evidence root: $EVID"
rm -rf "$EVID"
"$AMBERCTL_BIN" init

echo "==> building collector base + bringing up ftp cell"
"$AMBERCTL_BIN" up ftp

echo "==> waiting for FTP LISTEN on 127.0.0.1:${HOST_PORT}"
ready=0
for _ in $(seq 1 60); do
  if (echo >"/dev/tcp/127.0.0.1/${HOST_PORT}") >/dev/null 2>&1; then
    ready=1
    break
  fi
  # bash /dev/tcp may be unavailable; fall back to nc/python
  if command -v nc >/dev/null 2>&1; then
    if nc -z 127.0.0.1 "$HOST_PORT" 2>/dev/null; then
      ready=1
      break
    fi
  elif python3 -c "import socket;s=socket.create_connection(('127.0.0.1',int('${HOST_PORT}')),1);s.close()" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" != "1" ]]; then
  echo "FAIL: FTP not listening on ${HOST_PORT}" >&2
  docker compose "${COMPOSE_FILES[@]}" --profile core logs --tail=80 ftp-collector ftp-hi || true
  exit 1
fi
echo "OK: LISTEN"

echo "==> FTP dialogue (anonymous + PASV + Active Mode reject)"
SMOKE_OUT="$(mktemp)"
python3 - "$HOST_PORT" "$PASV_ADDR" <<'PY' | tee "$SMOKE_OUT"
import socket, sys, re, time

host = "127.0.0.1"
port = int(sys.argv[1])
expect_pasv_ip = sys.argv[2]

def read_resp(s):
    buf = b""
    s.settimeout(10)
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
        if b"\r\n" in buf:
            # multi-line 220- / single line
            lines = buf.split(b"\r\n")
            # wait until a non-continuation completion line
            text = buf.decode("utf-8", "replace")
            for line in text.split("\r\n"):
                if len(line) >= 4 and line[3] == " " and line[:3].isdigit():
                    return text
    return buf.decode("utf-8", "replace")

def cmd(s, line):
    s.sendall((line + "\r\n").encode())
    return read_resp(s)

s = socket.create_connection((host, port), timeout=10)
banner = read_resp(s)
print("BANNER", banner.splitlines()[0] if banner else "")
assert banner.startswith("220"), banner

r = cmd(s, "USER anonymous")
print("USER", r.splitlines()[0] if r else "")
assert "331" in r or "230" in r, r
if "331" in r:
    r = cmd(s, "PASS anonymous@")
    print("PASS", r.splitlines()[0] if r else "")
    assert "230" in r, r

r = cmd(s, "PASV")
print("PASV", r.splitlines()[0] if r else "")
assert "227" in r, r
m = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", r)
assert m, r
ip = ".".join(m.group(i) for i in range(1, 5))
pport = int(m.group(5)) * 256 + int(m.group(6))
print("PASV_ADDR", ip, "PASV_PORT", pport)
assert ip == expect_pasv_ip, (ip, expect_pasv_ip)
assert 30000 <= pport <= 30049, pport

# Open passive data channel (LIST)
ds = socket.create_connection((host, pport), timeout=10)
r = cmd(s, "LIST")
print("LIST", r.splitlines()[0] if r else "")
# drain data
try:
    ds.settimeout(5)
    data = b""
    while True:
        chunk = ds.recv(4096)
        if not chunk:
            break
        data += chunk
except Exception:
    pass
ds.close()
print("LIST_DATA_BYTES", len(data))
# final 226 may follow
time.sleep(0.3)
try:
    s.settimeout(2)
    extra = s.recv(4096).decode("utf-8", "replace")
    if extra.strip():
        print("LIST_DONE", extra.splitlines()[0])
except Exception:
    pass

# Active Mode must be rejected
r = cmd(s, "PORT 127,0,0,1,20,20")
print("PORT", r.splitlines()[0] if r else "")
assert "5" == r[:1] or "500" in r or "502" in r or "550" in r or "425" in r, r

r = cmd(s, "QUIT")
print("QUIT", r.splitlines()[0] if r else "")
s.close()
print("FTP_OK")
PY

grep -q "FTP_OK" "$SMOKE_OUT"
echo "OK: PASV + Active Mode rejected"

echo "==> waiting for collector evidence"
found_events=0
found_flows=0
for _ in $(seq 1 45); do
  if [[ -f "$EVID/jsonl/ftp/events.jsonl" ]] && grep -q '"schema_version":"event.v1"' "$EVID/jsonl/ftp/events.jsonl" 2>/dev/null; then
    found_events=1
  fi
  if [[ -f "$EVID/raw-flows/ftp/flows.jsonl" ]] && grep -q '"schema_version":"rawflow.v1"' "$EVID/raw-flows/ftp/flows.jsonl" 2>/dev/null; then
    found_flows=1
  fi
  if [[ "$found_events" == "1" && "$found_flows" == "1" ]]; then
    break
  fi
  sleep 1
done

if [[ ! -f "$EVID/state/ftp.json" ]]; then
  echo "FAIL: missing state/ftp.json" >&2
  exit 1
fi
grep -q '"provider_id"' "$EVID/state/ftp.json"
if ! grep -q "\"provider_id\": \"${FTP_PROVIDER}\"" "$EVID/state/ftp.json"; then
  echo "FAIL: state/ftp.json provider_id != ${FTP_PROVIDER}" >&2
  cat "$EVID/state/ftp.json" >&2
  exit 1
fi
# Digests must be real image ids, not the placeholder "local".
if grep -q '"image_digest": "local"' "$EVID/state/ftp.json" || grep -q '"image_digest": ""' "$EVID/state/ftp.json"; then
  echo "FAIL: state/ftp.json missing real image_digest" >&2
  cat "$EVID/state/ftp.json" >&2
  exit 1
fi
echo "OK: state/ftp.json (provider_id=${FTP_PROVIDER})"

if [[ "$found_events" != "1" ]]; then
  echo "FAIL: no event.v1 JSONL under $EVID/jsonl/ftp/" >&2
  docker compose "${COMPOSE_FILES[@]}" --profile core logs --tail=100 ftp-collector || true
  ls -laR "$EVID" || true
  exit 1
fi
echo "OK: JSONL events"

if [[ "$found_flows" != "1" ]]; then
  echo "WARN: raw-flow not closed yet; emitting session may still be open — checking pcap + forcing wait"
  sleep 5
  if [[ -f "$EVID/raw-flows/ftp/flows.jsonl" ]] && grep -q rawflow.v1 "$EVID/raw-flows/ftp/flows.jsonl"; then
    found_flows=1
  fi
fi
if [[ "$found_flows" != "1" ]]; then
  echo "FAIL: no rawflow.v1 under $EVID/raw-flows/ftp/" >&2
  docker compose "${COMPOSE_FILES[@]}" --profile core logs --tail=100 ftp-collector || true
  exit 1
fi
echo "OK: raw-flow"

if ! ls "$EVID/pcap/ftp/ring/"capture.pcap* >/dev/null 2>&1; then
  echo "FAIL: no pcap ring segments" >&2
  exit 1
fi
echo "OK: pcap ring"

echo "==> sample AI decision (evidence only)"
DEC_PATH="$(python3 "$ROOT/manager/sample_decision.py")"
test -f "$DEC_PATH"
grep -q '"schema_version": "decision.v1"' "$DEC_PATH"
grep -q '"evidence_refs"' "$DEC_PATH"
echo "OK: decision at $DEC_PATH"

echo "==> amberctl status + drill ftp"
"$AMBERCTL_BIN" status || true
"$AMBERCTL_BIN" drill ftp
echo "OK: drill ftp"

echo "==> port_denied evidence (PORT in smoke dialogue)"
if ! grep -q '"event":"port_denied"' "$EVID/jsonl/ftp/events.jsonl" 2>/dev/null; then
  echo "WARN: port_denied event not yet in JSONL (collector may lag); waiting"
  for _ in $(seq 1 15); do
    if grep -q '"event":"port_denied"' "$EVID/jsonl/ftp/events.jsonl" 2>/dev/null; then
      break
    fi
    sleep 1
  done
fi
grep -q '"event":"port_denied"' "$EVID/jsonl/ftp/events.jsonl"
echo "OK: port_denied event"

echo
echo "PASS: test_smoke_ftp.sh"
