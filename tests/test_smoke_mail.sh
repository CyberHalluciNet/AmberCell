#!/usr/bin/env bash
# Stage-2 mail smoke: SMTP dialogue + POP3 auth/RETR + evidence + sample decision.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EVID="${AMBER_EVIDENCE_ROOT:-$ROOT/.ambercell-mail-smoke}"

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

SMTP_PORT="${AMBER_SMTP_HOST_PORT:-}"
POP3_PORT="${AMBER_POP3_HOST_PORT:-}"
if [[ -z "$SMTP_PORT" ]]; then SMTP_PORT="$(pick_free_port 2525)"; fi
if [[ -z "$POP3_PORT" ]]; then POP3_PORT="$(pick_free_port 1110)"; fi
export AMBER_EVIDENCE_ROOT="$EVID"
export AMBER_SMTP_HOST_PORT="$SMTP_PORT"
export AMBER_POP3_HOST_PORT="$POP3_PORT"
export COMPOSE_PROFILES="${COMPOSE_PROFILES:-lab,core}"
export AMBER_ROOT="$ROOT"
COMPOSE_FILES=(-f "$ROOT/compose.yaml" -f "$ROOT/compose.lab.yaml")

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
  "$AMBERCTL_BIN" down smtp 2>/dev/null || true
  "$AMBERCTL_BIN" down pop3 2>/dev/null || true
  docker compose "${COMPOSE_FILES[@]}" --profile core rm -f smtp-hi smtp-collector pop3-hi pop3-collector 2>/dev/null || true
}
trap cleanup EXIT

echo "==> evidence root: $EVID"
rm -rf "$EVID"
"$AMBERCTL_BIN" init

echo "==> up smtp + pop3"
"$AMBERCTL_BIN" up smtp
"$AMBERCTL_BIN" up pop3

wait_port() {
  local port=$1
  local label=$2
  for _ in $(seq 1 90); do
    if python3 -c "import socket;s=socket.create_connection(('127.0.0.1',int('${port}')),2);s.close()" 2>/dev/null; then
      echo "OK: $label LISTEN $port"
      return 0
    fi
    sleep 1
  done
  echo "FAIL: $label not listening on $port" >&2
  docker compose "${COMPOSE_FILES[@]}" --profile core logs --tail=60 smtp-collector smtp-hi pop3-collector pop3-hi || true
  exit 1
}

wait_port "$SMTP_PORT" SMTP
wait_port "$POP3_PORT" POP3

python3 - "$SMTP_PORT" "$POP3_PORT" <<'PY'
import socket, sys

smtp_p, pop3_p = int(sys.argv[1]), int(sys.argv[2])

def banner(port, timeout=5):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    data = s.recv(4096).decode("utf-8", "replace")
    s.close()
    return data

smtp_b = banner(smtp_p)
assert smtp_b.startswith("220") and "mail.corp.example.net" in smtp_b, smtp_b
pop3_b = banner(pop3_p)
assert pop3_b.startswith("+OK") and "Debian" not in pop3_b, pop3_b
print(f"OK: banners smtp={smtp_p} pop3={pop3_p}")
PY

sleep 3

echo "==> SMTP dialogue"
python3 - "$SMTP_PORT" <<'PY'
import socket, sys, time

port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=15)

def rd():
    s.settimeout(10)
    data = b""
    while b"\n" not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode("utf-8", "replace")

def wr(line):
    s.sendall((line + "\r\n").encode())

banner = rd()
assert banner.startswith("220"), banner
wr("EHLO smoke.client")
resp = rd()
assert "250" in resp, resp
wr("MAIL FROM:<attacker@evil.example>")
assert "250" in rd(), "mail from"
wr("RCPT TO:<finance@corp.example.net>")
assert "250" in rd(), "rcpt sinkhole"
wr("DATA")
assert "354" in rd(), "data start"
wr("Subject: smoke")
wr("")
wr("Stage-2 SMTP smoke body.")
wr(".")
assert "250" in rd(), "data end"
wr("MAIL FROM:<attacker@evil.example>")
wr("RCPT TO:<relay@victim.example>")
resp = rd()
assert "554" in resp or "550" in resp or "553" in resp or "Relay access denied" in resp, resp
wr("QUIT")
s.close()
print("SMTP_OK")
PY

echo "==> POP3 auth + RETR"
python3 - "$POP3_PORT" <<'PY'
import socket, sys

port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=15)

def rd():
    s.settimeout(10)
    return s.recv(4096).decode("utf-8", "replace")

def wr(line):
    s.sendall((line + "\r\n").encode())

assert rd().startswith("+OK"), "banner"
wr("USER finance")
assert "+OK" in rd(), "user"
wr("PASS finance123")
assert "+OK" in rd(), "pass"
wr("STAT")
stat_resp = rd()
assert "+OK" in stat_resp, f"stat: {stat_resp!r}"
wr("RETR 1")
resp = rd()
assert resp.startswith("+OK"), resp
body = []
if ".\r\n" not in resp:
    resp += rd()
for part in resp.split("\r\n"):
    if part in (".", "+OK 123 octets", "+OK") or part.startswith("+OK "):
        continue
    if part:
        body.append(part)
assert body, f"empty retr: {resp!r}"
wr("QUIT")
s.close()
print("POP3_OK")
PY

wait_evidence() {
  local svc=$1
  for _ in $(seq 1 90); do
    if [[ -f "$EVID/jsonl/${svc}/events.jsonl" ]] && grep -q '"schema_version":"event.v1"' "$EVID/jsonl/${svc}/events.jsonl" 2>/dev/null; then
      if [[ -f "$EVID/raw-flows/${svc}/flows.jsonl" ]] && grep -q '"schema_version":"rawflow.v1"' "$EVID/raw-flows/${svc}/flows.jsonl" 2>/dev/null; then
        return 0
      fi
    fi
    sleep 1
  done
  return 1
}

echo "==> waiting for evidence"
sleep 2
wait_evidence smtp || { echo "FAIL smtp evidence" >&2; exit 1; }
wait_evidence pop3 || { echo "FAIL pop3 evidence" >&2; exit 1; }
echo "OK: JSONL + raw-flow"

grep -q '"event":"ehlo"' "$EVID/jsonl/smtp/events.jsonl" || grep -q '"event": "ehlo"' "$EVID/jsonl/smtp/events.jsonl"
grep -q '"event":"data"' "$EVID/jsonl/smtp/events.jsonl" || grep -q '"event": "data"' "$EVID/jsonl/smtp/events.jsonl"
grep -q '"event":"retr"' "$EVID/jsonl/pop3/events.jsonl" || grep -q '"event": "retr"' "$EVID/jsonl/pop3/events.jsonl"

echo "==> sample decisions"
DEC_SMTP="$(AMBER_EVIDENCE_ROOT="$EVID" python3 "$ROOT/manager/sample_decision.py" --svc smtp)"
DEC_POP3="$(AMBER_EVIDENCE_ROOT="$EVID" python3 "$ROOT/manager/sample_decision.py" --svc pop3)"
test -f "$DEC_SMTP"
test -f "$DEC_POP3"
grep -q '"schema_version": "decision.v1"' "$DEC_SMTP"

echo "==> drills"
"$AMBERCTL_BIN" drill smtp
"$AMBERCTL_BIN" drill pop3

echo
echo "PASS: test_smoke_mail.sh"
