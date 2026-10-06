#!/usr/bin/env bash
# Verify rebuild teardown order documented in rebuild_reset.go (static contract).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
file="$ROOT/amberctl/internal/cli/rebuild_reset.go"
content="$(cat "$file")"
for step in "StopHI" "flushEvidenceSegment" "FlushCell" "StopCollector" "cosign.VerifyDigest" "UpCell"; do
  if ! grep -q "$step" <<< "$content"; then
    echo "rebuild contract missing step: $step" >&2
    exit 1
  fi
done
# Order: hi before flush before conntrack before collector
python3 - <<'PY' "$file"
import sys
text = open(sys.argv[1]).read()
order = ["StopHI", "flushEvidenceSegment", "FlushCell", "StopCollector", "VerifyDigest"]
pos = [text.index(s) for s in order]
if pos != sorted(pos):
    raise SystemExit("rebuild step order incorrect")
print("rebuild contract order: OK")
PY
echo "OK: rebuild contract"
