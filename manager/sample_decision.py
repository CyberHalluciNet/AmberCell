#!/usr/bin/env python3
"""
Stage-1 AI manager path: read FTP/Telnet evidence, emit one decision.v1 file.

Reads ONLY under AMBER_EVIDENCE_ROOT. Never mutates collectors' JSONL, pcaps,
or cell containers (G6). Writes a new JSON file under decisions/<svc>/ only.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from manager.dwell_time import should_defer_rebuild  # noqa: E402

DEFAULT_EVIDENCE_ROOT = "/var/ambercell"
DEFAULT_SVC = "ftp"
DECISION_VERSION = os.environ.get("AMBER_DECISION_VERSION", "2026-10-06.1")

_EXEC_SUFFIXES = (".sh", ".exe", ".elf", ".bin", ".py", ".pl", ".rb", ".js")


def repo_root() -> Path:
    override = os.environ.get("AMBER_ROOT")
    if override:
        return Path(override)
    return Path(__file__).resolve().parent.parent


def policy_id_from_yaml(path: Path) -> str | None:
    if not path.is_file():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("policy_id:"):
            value = stripped.split(":", 1)[1].strip()
            return value.strip("\"'")
    return None


def policy_refs_for_svc(svc: str) -> list[str]:
    refs = [f"{svc}-smoke.v1"]
    policies_dir = repo_root() / "manager" / "policies"
    alert_path = policies_dir / f"{svc}-alert.yaml"
    policy_id = policy_id_from_yaml(alert_path)
    if policy_id and policy_id not in refs:
        refs.append(policy_id)
    return refs


def evidence_root() -> Path:
    return Path(os.environ.get("AMBER_EVIDENCE_ROOT", DEFAULT_EVIDENCE_ROOT))


def decisions_dir(root: Path, svc: str) -> Path:
    override = os.environ.get("AMBER_DECISIONS_DIR")
    if override:
        return Path(override) / svc
    return root / "decisions" / svc


def utc_now_rfc3339_nano() -> str:
    import time

    now = datetime.now(timezone.utc)
    base = now.strftime("%Y-%m-%dT%H:%M:%S")
    nanos = time.time_ns() % 1_000_000_000
    return f"{base}.{nanos:09d}Z"


def new_decision_id(prefix: str = "dec") -> str:
    return f"{prefix}_{secrets.token_hex(4)}"


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
            if isinstance(obj, dict):
                records.append(obj)
    return records


def load_cell_id(root: Path, svc: str, events: list[dict[str, Any]]) -> str:
    for ev in events:
        cid = ev.get("cell_id")
        if isinstance(cid, str) and cid:
            return cid
    state_path = root / "state" / f"{svc}.json"
    if state_path.is_file():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            cid = state.get("cell_id")
            if isinstance(cid, str) and cid:
                return cid
        except json.JSONDecodeError:
            pass
    return f"{svc}-cell-01"


def pick_target_session(events: list[dict[str, Any]]) -> str:
    for ev in events:
        sid = ev.get("session_id")
        if isinstance(sid, str) and sid:
            return sid
    return "unknown-session"


def _path_looks_executable(path: str) -> bool:
    lower = path.lower()
    return any(lower.endswith(sfx) for sfx in _EXEC_SUFFIXES)


def _maybe_defer_rebuild(
    root: Path,
    svc: str,
    decision_type: str,
    reason: str,
    refs: list[str],
    severity: str = "high",
) -> tuple[str, str, list[str], str, str]:
    defer, detail = should_defer_rebuild(root, svc)
    if defer:
        return (
            "annotate",
            f"{svc}: defer rebuild recommendation — {detail}",
            refs[:3] or refs[-1:],
            "annotate",
            "low",
        )
    return decision_type, reason, refs, decision_type, severity


def choose_decision(
    svc: str, events: list[dict[str, Any]], root: Path | None = None
) -> tuple[str, str, list[str], str, str]:
    """Return decision_type, reason, evidence_refs, recommended_action, severity."""
    refs: list[str] = []
    for ev in events:
        eid = ev.get("event_id")
        if isinstance(eid, str) and eid:
            refs.append(eid)

    if not refs:
        raise ValueError(f"no event_id values found in jsonl/{svc}/events.jsonl")

    ev_root = root or evidence_root()

    if svc == "smtp":
        relay = [ev for ev in events if ev.get("event") == "relay_denied"]
        if relay:
            rr = [ev["event_id"] for ev in relay if isinstance(ev.get("event_id"), str)][:3]
            return (
                "alert",
                "SMTP relay probe / unauthorized relay attempt",
                rr or refs[-1:],
                "alert",
                "high",
            )
        auth_fails = [
            ev for ev in events if ev.get("event") == "auth" and ev.get("ok") is False
        ]
        if len(auth_fails) >= 3:
            ar = [ev["event_id"] for ev in auth_fails[:3]]
            return (
                "alert",
                "SMTP AUTH brute-force pattern (>=3 failures)",
                ar,
                "alert",
                "high",
            )
        data_ev = [ev for ev in events if ev.get("event") == "data"]
        if data_ev:
            dr = [ev["event_id"] for ev in data_ev if isinstance(ev.get("event_id"), str)][:3]
            rcpt = data_ev[-1].get("rcpt_to") or data_ev[-1].get("to") or "recipient"
            return (
                "alert",
                f"SMTP message captured for {rcpt}",
                dr,
                "alert",
                "medium",
            )

    if svc == "pop3":
        high_retr = [
            ev
            for ev in events
            if ev.get("event") == "retr" and ev.get("high_value_mailbox") is True
        ]
        if high_retr:
            hr = [ev["event_id"] for ev in high_retr if isinstance(ev.get("event_id"), str)][:3]
            user = high_retr[-1].get("user") or "mailbox"
            return (
                "alert",
                f"High-value POP3 mailbox RETR for user {user}",
                hr,
                "alert",
                "high",
            )
        dele = [ev for ev in events if ev.get("event") == "dele"]
        if dele:
            dr = [ev["event_id"] for ev in dele if isinstance(ev.get("event_id"), str)][:3]
            return (
                "alert",
                f"POP3 message deletion (DELE) by {dele[-1].get('user') or 'user'}",
                dr,
                "alert",
                "medium",
            )

    # 1) Egress staging → rebuild recommendation
    egress = [ev for ev in events if ev.get("event") == "egress_staging"]
    if egress:
        er = [ev["event_id"] for ev in egress if isinstance(ev.get("event_id"), str)][:3]
        return _maybe_defer_rebuild(
            ev_root,
            svc,
            "snapshot_then_rebuild",
            f"{svc}: egress staging / download-execute cluster",
            er or refs[-1:],
        )

    # 2) Executable upload (FTP STOR)
    uploads = [
        ev
        for ev in events
        if ev.get("event") == "stor" and _path_looks_executable(str(ev.get("path") or ""))
    ]
    if uploads:
        ur = [ev["event_id"] for ev in uploads if isinstance(ev.get("event_id"), str)][:3]
        path = uploads[-1].get("path") or "upload"
        return (
            "alert",
            f"FTP executable/script upload observed ({path})",
            ur,
            "alert",
            "high",
        )

    # 3) Shell login (telnet auth ok) or FTP auth failure
    if svc == "telnet":
        logins = [
            ev
            for ev in events
            if ev.get("event") == "auth" and ev.get("ok") is True
        ]
        if logins:
            lr = [ev["event_id"] for ev in logins if isinstance(ev.get("event_id"), str)][:3]
            user = logins[-1].get("user") or "unknown"
            return (
                "alert",
                f"Telnet shell login for user {user}",
                lr,
                "alert",
                "medium",
            )

    auth_failures = [
        ev
        for ev in events
        if ev.get("event") == "auth"
        and ev.get("ok") is False
        and isinstance(ev.get("event_id"), str)
    ]
    if auth_failures:
        fail_refs = [ev["event_id"] for ev in auth_failures[:3]]
        user = auth_failures[-1].get("user") or "unknown"
        return (
            "alert",
            f"{svc} auth failure for user {user}",
            fail_refs,
            "alert",
            "medium",
        )

    # 4) cmd events (telnet) → alert
    cmds = [ev for ev in events if ev.get("event") == "cmd"]
    if cmds:
        cr = [ev["event_id"] for ev in cmds if isinstance(ev.get("event_id"), str)][:3]
        return (
            "alert",
            f"Telnet command activity ({cmds[-1].get('command') or 'cmd'})",
            cr or refs[-1:],
            "alert",
            "medium",
        )

    primary = refs[-1]
    return (
        "annotate",
        f"{svc} session activity observed; annotate for smoke / replay baseline",
        [primary],
        "annotate",
        "low",
    )


def build_decision(
    root: Path,
    svc: str,
    events: list[dict[str, Any]],
    flow_count: int,
) -> dict[str, Any]:
    decision_type, reason_summary, evidence_refs, recommended, severity = choose_decision(
        svc, events, root
    )
    cell_id = load_cell_id(root, svc, events)
    target_id = pick_target_session(events)
    if target_id == "unknown-session" and flow_count:
        reason_summary = f"{reason_summary} (events={len(events)}, flows={flow_count})"

    return {
        "schema_version": "decision.v1",
        "decision_id": new_decision_id(),
        "ts": utc_now_rfc3339_nano(),
        "scope": "session",
        "target_id": target_id,
        "cell_id": cell_id,
        "decision_type": decision_type,
        "confidence": "medium",
        "severity": severity,
        "reason_summary": reason_summary,
        "evidence_refs": evidence_refs,
        "policy_refs": policy_refs_for_svc(svc),
        "recommended_action": recommended,
        "executor_status": "pending",
        "decision_version": DECISION_VERSION,
        "source": "deterministic_rule",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Emit one decision.v1 from cell evidence")
    parser.add_argument("--svc", default=DEFAULT_SVC, help="service name (ftp|telnet|smtp|pop3)")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print decision JSON to stdout; do not write under decisions/",
    )
    args = parser.parse_args(argv)

    root = evidence_root()
    svc = args.svc
    events_path = root / "jsonl" / svc / "events.jsonl"
    flows_path = root / "raw-flows" / svc / "flows.jsonl"

    if not root.is_dir():
        print(f"evidence root missing: {root}", file=sys.stderr)
        return 1

    events = read_jsonl(events_path)
    flows = read_jsonl(flows_path)

    if not events and not flows:
        print(
            f"no evidence under {root}/jsonl/{svc}/ or {root}/raw-flows/{svc}/",
            file=sys.stderr,
        )
        return 1

    if not events:
        print(
            f"{events_path} has no events; need event_id values for evidence_refs",
            file=sys.stderr,
        )
        return 1

    try:
        decision = build_decision(root, svc, events, len(flows))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    payload = json.dumps(decision, indent=2, sort_keys=True) + "\n"
    if args.dry_run:
        sys.stdout.write(payload)
        return 0

    out_dir = decisions_dir(root, svc)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{decision['decision_id']}.json"
    out_path.write_text(payload, encoding="utf-8")
    print(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
