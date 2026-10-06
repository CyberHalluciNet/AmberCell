#!/usr/bin/env python3
"""Stage-4 webhook router: map canary/decision triggers → session/cell IDs.

Delivery uses amberctl's async circuit breaker (Go). This module builds alert
payloads and prints JSON for operators or pipes to ``amberctl execute-decision``.
Never blocks rebuild — run out-of-band from the executor path.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone


def build_alert(
    *,
    kind: str,
    svc: str,
    session_id: str = "",
    cell_id: str = "",
    decision_id: str = "",
    summary: str,
) -> dict:
    return {
        "schema_version": "alert.v1",
        "alert_id": f"oob-{kind}-{svc}-{int(datetime.now(timezone.utc).timestamp())}",
        "ts": datetime.now(timezone.utc).isoformat(),
        "kind": kind,
        "svc": svc,
        "session_id": session_id,
        "cell_id": cell_id or f"{svc}-cell-01",
        "decision_id": decision_id,
        "summary": summary,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build webhook alert JSON (Stage-4)")
    parser.add_argument("--kind", default="canary_touch", help="canary_touch|decision_alert")
    parser.add_argument("--svc", required=True)
    parser.add_argument("--session-id", default="")
    parser.add_argument("--decision-id", default="")
    parser.add_argument("--summary", required=True)
    args = parser.parse_args()
    payload = build_alert(
        kind=args.kind,
        svc=args.svc,
        session_id=args.session_id,
        decision_id=args.decision_id,
        summary=args.summary,
    )
    print(json.dumps(payload, indent=2))
    # Operator sets AMBER_WEBHOOK_URL then: amberctl execute-decision --decision alert --svc SVC
    if os.environ.get("AMBER_WEBHOOK_URL"):
        print(
            "# hint: export AMBER_DECISION_ID / AMBER_SESSION_ID then "
            "amberctl execute-decision --decision alert --svc",
            args.svc,
            file=os.sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
