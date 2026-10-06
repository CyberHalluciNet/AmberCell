# AmberCell collectors (Stage-0B)

Protocol collectors capture traffic in the **cell network namespace** without opening TCP/UDP listeners. Evidence is append-only under `/var/ambercell/`.

## Layout

| Path | Purpose |
|------|---------|
| `collectors/base/` | Shared Python library + base image (`ambercell-collector-base`) |
| `collectors/ftp/` | FTP collector entrypoint (control + PASV data) |

### Evidence directories (per service `<svc>`)

- `/var/ambercell/raw-flows/<svc>/` — raw-flow JSONL (`schema_version=rawflow.v1`)
- `/var/ambercell/jsonl/<svc>/` — normalized events (`schema_version=event.v1`)
- `/var/ambercell/pcap/<svc>/ring/` — rotating pcaps via `tcpdump -G/-W`
- `/var/ambercell/state/<svc>.json` — cell/collector state snapshot

Records use monotonic `seq_id` per collector process and UTC RFC3339 timestamps (nanoseconds when the platform allows).

## Build (Docker Desktop / lab)

Build from the **repository root** so schemas are copied into the base image:

```bash
cd /path/to/AmberCell

docker build -t ambercell-collector-base -f collectors/base/Dockerfile .
docker build -t ambercell-ftp-collector -f collectors/ftp/Dockerfile .
```

## Run FTP collector (smoke)

The collector needs packet capture capabilities and a mount for evidence:

```bash
EVID=/tmp/ambercell-evidence
mkdir -p "$EVID"

docker run --rm -it \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$EVID:/var/ambercell" \
  -e AMBER_IMAGE_DIGEST=sha256:lab \
  -e AMBER_CELL_INSTANCE_ID=smoke-1 \
  -e AMBER_FTP_PROVIDER=vsftpd \
  -e AMBER_DEBUG_SCHEMA_VALIDATE=1 \
  ambercell-ftp-collector
```

Generate FTP traffic against a reachable target on the same L2/L3 path the container can see (full stack smoke uses Compose + `ftp-hi` on `172.30.30.10`; for a quick local check you can point a lab vsftpd at the host and use `--network host` on Linux, or attach the collector to the same Docker network as `ftp-hi` once Stage-0B compose is wired).

Example client (from a client container on `ambernet`):

```bash
ftp -n 172.30.30.10 <<EOF
user anonymous guest@example.com
quit
EOF
```

## Verify evidence

After at least one control session (port 21):

```bash
# State
cat "$EVID/state/ftp.json"

# Normalized events (expect session_open, auth, and/or pasv_open)
tail -n 20 "$EVID/jsonl/ftp/events.jsonl" | python3 -m json.tool

# Raw flows (control session closes on FIN/RST)
tail -n 20 "$EVID/raw-flows/ftp/flows.jsonl" | python3 -m json.tool

# Pcap ring segments
ls -la "$EVID/pcap/ftp/ring/"
```

Required JSON fields match `docs/schemas/rawflow.v1.schema.json` and `docs/schemas/event.v1.schema.json`.

### PASV correlation

When the control channel sends `227 Entering Passive Mode (...)` (or EPSV `229`), the advertised port is mapped to the parent control `session_id`. Subsequent inbound TCP to `172.30.30.10` on that port in `30000-30049` is stamped with the same `session_id` in raw-flow records.

## Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `AMBER_EVIDENCE_ROOT` | `/var/ambercell` | Evidence root |
| `AMBER_FTP_PROVIDER` | `vsftpd` | `provider_id` on records |
| `AMBER_FTP_CELL_IP` | `172.30.30.10` | Cell address |
| `AMBER_FTP_CELL_ID` | `ftp-cell-01` | `cell_id` |
| `AMBER_FTP_COLLECTOR_ID` | `ftp-collector-a` | `collector_id` |
| `AMBER_IMAGE_DIGEST` | *(empty)* | Written to `state/ftp.json` |
| `AMBER_CELL_INSTANCE_ID` | `HOSTNAME` | Written to `state/ftp.json` |
| `AMBER_CAPTURE_IF` | `any` | `tcpdump -i` |
| `AMBER_DEBUG_SCHEMA_VALIDATE` | off | Reject writes if schema validation fails |
| `AMBER_SCHEMA_DIR` | `/opt/ambercell/schemas` | JSON Schema directory in images |

## Local development (no Docker)

```bash
cd collectors/base && pip install -e ".[validate]"
export PYTHONPATH="$PWD/../ftp:$PYTHONPATH"
export AMBER_EVIDENCE_ROOT=/tmp/ambercell-evidence
export AMBER_SCHEMA_DIR=/path/to/AmberCell/docs/schemas
python3 -m ftp_collector.main
```

Requires `tcpdump` on the PATH and appropriate capture permissions on the host.
