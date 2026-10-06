#!/usr/bin/env bash
# Stage-4 lab CI: publish, webhook breaker, CLI surface (no fake production G bars).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> go test (webhook + publish + review)"
(cd amberctl && go test ./...)

AMBERCTL="${ROOT}/amberctl/amberctl"
(cd amberctl && go build -o amberctl .)

EVID="$(mktemp -d)"
export AMBER_EVIDENCE_ROOT="$EVID"
"$AMBERCTL" init >/dev/null

mkdir -p "$EVID/decisions/ftp" "$EVID/enrichment/ftp" "$EVID/raw-flows/ftp" "$EVID/jsonl/ftp"
echo '{"schema_version":"decision.v1","decision_id":"dec_ci1","decision_type":"alert","confidence":"low"}' \
  > "$EVID/decisions/ftp/dec_ci1.json"
echo '{"schema_version":"enrichment.v1","event_id":"evt_1"}' > "$EVID/enrichment/ftp/e1.json"
echo '{"schema_version":"rawflow.v1","seq_id":1,"svc":"ftp"}' > "$EVID/raw-flows/ftp/flows.jsonl.closed.test"
echo '{"schema_version":"event.v1","seq_id":1,"event":"auth","user":"admin","password":"secret"}' \
  > "$EVID/jsonl/ftp/events.jsonl.closed.test"

bundle="$("$AMBERCTL" publish 2>/dev/null | sed -n 's/^published dead drop bundle: //p')"
test -f "$bundle/manifest.json"

if grep -q '"secret"' "$bundle/jsonl/ftp/events.jsonl.closed.test" 2>/dev/null; then
  echo "summary publish must redact secrets" >&2
  exit 1
fi
if ! grep -q redacted "$bundle/jsonl/ftp/events.jsonl.closed.test" 2>/dev/null; then
  echo "expected redacted password in summary bundle" >&2
  exit 1
fi

echo "==> webhook spill"
export AMBER_WEBHOOK_URL="http://127.0.0.1:65530/"
AMBER_DECISION_ID=dec_x AMBER_SESSION_ID=fp_x \
  "$AMBERCTL" execute-decision --decision alert --svc ftp >/dev/null
sleep 3
count="$(find "$EVID/alerts/failed" -name '*.json' 2>/dev/null | wc -l | tr -d ' ')"
if [[ "$count" -lt 1 ]]; then
  echo "expected failed alert spill" >&2
  exit 1
fi

echo "==> review queue scan"
python3 manager/review_queue.py --scan --svc ftp >/dev/null
test -f "$EVID/state/review/pending/dec_ci1.json"

echo "==> compose must not mount deaddrop"
deaddrop_mounts="$(grep -R "deaddrop" compose.yaml compose.lab.yaml compose.containment.yaml 2>/dev/null | grep -v '#' || true)"
if [[ -n "$deaddrop_mounts" ]]; then
  echo "deaddrop must not appear in compose bind mounts" >&2
  exit 1
fi

echo "OK: Stage-4 lab CI"
