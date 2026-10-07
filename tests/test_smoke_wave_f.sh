#!/usr/bin/env bash
# Wave F smoke — DNS cell (coredns default provider) on lab published ports (Darwin/Linux).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EVID="${AMBER_EVIDENCE_ROOT:-$ROOT/.ambercell-wave-f-smoke}"

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
export COMPOSE_PROFILES="${COMPOSE_PROFILES:-lab,core,wave-f}"
export AMBER_DNS_HOST_PORT="${AMBER_DNS_HOST_PORT:-$(pick_free_port 10530)}"
echo "==> lab dns port udp/tcp $AMBER_DNS_HOST_PORT"

COMPOSE_FILES=(-f "$ROOT/compose.yaml" -f "$ROOT/compose.lab.yaml")

AMBERCTL_BIN="${AMBERCTL_BIN:-}"
if [[ -z "$AMBERCTL_BIN" ]]; then
  (cd "$ROOT/amberctl" && go build -o amberctl .)
  AMBERCTL_BIN="$ROOT/amberctl/amberctl"
fi

cleanup() {
  set +e
  "$AMBERCTL_BIN" down dns 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$EVID"
"$AMBERCTL_BIN" down dns 2>/dev/null || true
docker compose "${COMPOSE_FILES[@]}" --profile wave-f down --remove-orphans 2>/dev/null || true

# Scripts/CI: non-interactive init (TTY would launch the provider wizard).
"$AMBERCTL_BIN" init --yes

echo "==> up dns"
"$AMBERCTL_BIN" up dns
sleep 3

echo "==> drill dns (lure-zone UDP query via amberctl)"
"$AMBERCTL_BIN" drill dns

echo "==> protocol probes (lure A, NXDOMAIN, REFUSED, CHAOS, AXFR)"
AMBER_DNS_HOST_PORT="$AMBER_DNS_HOST_PORT" python3 - <<'PY'
import os, socket, struct, sys

port = int(os.environ["AMBER_DNS_HOST_PORT"])
addr = ("127.0.0.1", port)

def query(name, qtype, qclass=1, rd=1):
    qid = 0x4100 + (qtype % 64)
    hdr = struct.pack(">HHHHHH", qid, 0x0100 if rd else 0, 1, 0, 0, 0)
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    return qid, hdr + q + struct.pack(">HH", qtype, qclass)

def send(qid, pkt):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(pkt, addr)
    data, _ = s.recvfrom(2048)
    s.close()
    rid, flags = struct.unpack(">HH", data[:4])
    assert rid == qid, f"qid mismatch {rid} != {qid}"
    rcode = flags & 0xF
    return rcode, data

# 1) lure zone A → NOERROR
rc, _ = send(*query("www.ambercell.lab", 1))
assert rc == 0, f"lure A rcode {rc} != 0"
print("OK: lure A → NOERROR")

# 2) unknown name inside lure zone → NXDOMAIN (authoritative, not recursion)
rc, _ = send(*query("does-not-exist.ambercell.lab", 1))
assert rc == 3, f"unknown lure name rcode {rc} != 3 (NXDOMAIN)"
print("OK: unknown lure name → NXDOMAIN")

# 3) outside lure zones → REFUSED (no recursion — G13)
rc, _ = send(*query("bank.example", 1))
assert rc == 5, f"off-zone rcode {rc} != 5 (REFUSED)"
print("OK: off-zone → REFUSED (no recursion)")

# 4) CHAOS version.bind (qclass=3) → answered with persona string
rc, data = send(*query("version.bind", 16, qclass=3))
assert rc == 0, f"CHAOS rcode {rc} != 0"
print("OK: CHAOS version.bind answered")

# 5) AXFR attempt (qtype=252) — denied server-side but must produce evidence
rc, _ = send(*query("corp.example.net", 252, rd=0))
print(f"OK: AXFR attempt sent (rcode {rc})")

print("protocol probes PASS")
PY

sleep 6

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
evidence_nonempty "$EVID/raw-flows/dns/flows.jsonl" || fail=1
evidence_nonempty "$EVID/jsonl/dns/events.jsonl" || fail=1
for f in "$EVID/state/dns.json"; do
  if [[ -s "$f" ]]; then echo "OK: evidence $f"; else echo "FAIL: $f" >&2; fail=1; fi
done

if ! grep -q '"event":"dns.query"' "$EVID/jsonl/dns/events.jsonl" "$EVID/jsonl/dns/events.jsonl.active" 2>/dev/null; then
  echo "FAIL: no dns.query event" >&2; fail=1
fi
if ! grep -q '"event":"dns.chaos_probe"' "$EVID/jsonl/dns/events.jsonl" "$EVID/jsonl/dns/events.jsonl.active" 2>/dev/null; then
  echo "FAIL: no dns.chaos_probe event" >&2; fail=1
fi
if ! grep -q '"event":"dns.axfr_attempt"' "$EVID/jsonl/dns/events.jsonl" "$EVID/jsonl/dns/events.jsonl.active" 2>/dev/null; then
  echo "FAIL: no dns.axfr_attempt event" >&2; fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  docker compose "${COMPOSE_FILES[@]}" --profile wave-f logs --tail=40 dns-collector dns-hi || true
  exit 1
fi

echo "==> Wave F smoke PASS (lab; G1–G13 not claimed on Darwin)"
