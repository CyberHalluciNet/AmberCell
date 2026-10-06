# AI manager (Stage-0B sample)

The full bounded AI manager runs on `ambermgmt` and emits decisions executed only via `amberctl` (later stages). Stage-0B ships a **deterministic sample path** that proves read-only evidence access and `decision.v1` output without touching cells or collector JSONL (**G6**).

## Sample decision script

[`sample_decision.py`](sample_decision.py) reads evidence **only** from `AMBER_EVIDENCE_ROOT` (default `/var/ambercell`):

| Input (read-only) | Path |
|-------------------|------|
| Normalized events | `jsonl/ftp/events.jsonl` |
| Raw flows (context) | `raw-flows/ftp/flows.jsonl` |
| Cell metadata | `state/ftp.json` (optional) |

It **never** writes to `jsonl/`, `raw-flows/`, `pcap/`, or container state. It writes one new file:

`$AMBER_EVIDENCE_ROOT/decisions/ftp/<decision_id>.json`

Schema: [`docs/schemas/decision.v1.schema.json`](../docs/schemas/decision.v1.schema.json). Example: [`docs/schemas/examples/decision.example.json`](../docs/schemas/examples/decision.example.json).

### Policy (ftp-smoke.v1)

- **`alert`** when an `auth` event has `ok: false` — `evidence_refs` list real `event_id` values from evidence.
- **`annotate`** otherwise — references the latest event’s `event_id`.
- Fixed fields: `policy_refs` includes `ftp-smoke.v1` plus optional Stage-1 stubs from [`policies/`](policies/) when present (e.g. `ftp-alert.v1` from `ftp-alert.yaml`), `source: "deterministic_rule"`, `executor_status: "pending"`.

### Stage-1 policy stubs

| File | `policy_id` | Purpose |
|------|-------------|---------|
| [`policies/ftp-alert.yaml`](policies/ftp-alert.yaml) | `ftp-alert.v1` | Auth failure, upload, login alert triggers (documentation stub) |
| [`policies/telnet-alert.yaml`](policies/telnet-alert.yaml) | `telnet-alert.v1` | Telnet shell/auth alert triggers (documentation stub) |

The full manager loads and evaluates these in later stages; `sample_decision.py` only appends `policy_id` values to `policy_refs` when the YAML files exist.

### Run

After FTP smoke has produced events (see [`collectors/README.md`](../collectors/README.md)):

```bash
export AMBER_EVIDENCE_ROOT=/tmp/ambercell-evidence   # or /var/ambercell on a host
python3 manager/sample_decision.py
# prints path to decisions/ftp/dec_*.json

python3 manager/sample_decision.py --dry-run   # stdout only, no write
```

| Variable | Default | Description |
|----------|---------|-------------|
| `AMBER_EVIDENCE_ROOT` | `/var/ambercell` | Evidence read root |
| `AMBER_DECISIONS_DIR` | *(unset)* | If set, decisions go here instead of `<root>/decisions/` |
| `AMBER_DECISION_VERSION` | `2026-10-06.1` | Pin for replay / critic (see plan.md) |

Exit `1` if no events with `event_id` exist (flows alone are insufficient for `evidence_refs`).

## Later stages

- Enrichment under `enrichment/<svc>/` may cite the same `event_id` values; decisions stay under `decisions/<svc>/` unless export/dead-drop copies them.
- Deterministic critic + `amberctl ai approve` execute approved decisions only; this script always leaves `executor_status: pending`.
