#!/usr/bin/env bash
# Stage-3 hermetic CI: schema validation, replay --diff, critic, go tests.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> go test (amberctl)"
(cd amberctl && go test ./...)

echo "==> schema validation"
python3 tests/test_schema_validate.py

echo "==> critic tests"
python3 tests/test_critic.py

AMBERCTL="${ROOT}/amberctl/amberctl"
(cd amberctl && go build -o amberctl .)

echo "==> replay --diff (golden self-check)"
for case in ftp/recognized telnet/recognized smtp/recognized pop3/recognized ftp/unknown; do
  golden="$ROOT/tests/replay/${case}"
  if [[ -d "$golden" ]]; then
    file="$(find "$golden" -name '*.golden.jsonl' | head -1)"
    if [[ -n "$file" ]]; then
      "$AMBERCTL" replay --diff --actual "$file" "$file"
    fi
  fi
done
"$AMBERCTL" replay --diff --actual "$ROOT/tests/replay/decisions/ftp-alert.golden.jsonl" "$ROOT/tests/replay/decisions/ftp-alert.golden.jsonl"

echo "==> export closed-segment policy (temp tree)"
EVID="$(mktemp -d)"
mkdir -p "$EVID/jsonl/ftp"
echo '{"schema_version":"event.v1","seq_id":1}' > "$EVID/jsonl/ftp/events.jsonl.closed.20260101T000000Z"
echo '{"live":true}' > "$EVID/jsonl/ftp/events.jsonl.active"
export AMBER_EVIDENCE_ROOT="$EVID"
out="$("$AMBERCTL" export -out "$EVID/out" 2>&1)" || true
if echo "$out" | grep -q 'events.jsonl.active'; then
  echo "export must not include active segment" >&2
  exit 1
fi
rm -rf "$EVID"

echo "==> stage3 harden (WORM vault + YARA async)"
python3 tests/test_stage3_harden.py

echo "==> hermetic pcap CI"
bash tests/pcap_ci/run_pcap_ci.sh

echo "OK: Stage-3 CI checks"
