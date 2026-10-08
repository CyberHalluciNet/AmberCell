# AmberCell collectors (Stage-0B)

Protocol collectors capture traffic in the **cell network namespace** without opening TCP/UDP listeners. Evidence is append-only under `/var/ambercell/`.

## Layout

| Path | Purpose |
|------|---------|
| `collectors/base/` | Shared Python library + base image (`ambercell-collector-base`) |
| `collectors/ftp/` | FTP collector entrypoint (control + PASV data) |
| `collectors/dns/` | DNS collector entrypoint (udp/tcp 53; parses tcpdump's native DNS decode — no payload dump) |
| `collectors/tftp/` | TFTP collector (udp/69 RRQ/WRQ/ERROR decode) |
| `collectors/snmp/` | SNMP collector (udp+tcp/161; -v PDU/reqid/OID decode) |
| `collectors/ntp/` | NTP collector **(beta)** (udp/123; flows+state guaranteed; `ntp.packet` events need a tcpdump build that prints the NTP summary at this verbosity) |
| `collectors/syslog/` | Syslog collector **(beta)** (tcp+udp/514; SYN-gated flows; `syslog.message` events from -A payload PRI lines when visible) |
| `collectors/sip/` | SIP collector (tcp+udp/5060; -A payload, request/response/header parse) |
| `collectors/imap/` | IMAP collector (tcp/143; -A LOGIN creds/commands/banner events) |
| `collectors/memcached/` | memcached collector (tcp+udp/11211; -A text-command events) |
| `collectors/rdp/` | RDP collector (tcp/3389; SYN-gated flows + `rdp.connect` events) |
| `collectors/vnc/` | VNC collector (tcp/5900; `vnc.banner` RFB version events) |
| `collectors/netbios/` | NetBIOS collector (udp/137; -x NBNS hex-decode: names/suffixes) |
| `collectors/ldap/` | LDAP collector **(beta)** (tcp/389; SYN-gated flows; op events when the tcpdump build prints LDAP decode — Alpine's tcpdump does not, so flows+drill are the guarantee there) |

Per-service collectors live under `collectors/<svc>/<svc>_collector/` and share the base library (emitters, pcap ring, flow tracking, FIFO log reader).

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

## hi→collector log FIFO (provider entrypoint contract)

The `*-hi` container tees daemon stdout into `$AMBER_<SVC>_LOG_FIFO` for tertiary evidence. **Keep one writer attached to the FIFO for the process lifetime** (e.g. `{ tail -f /dev/null >"$FIFO" & }` before starting the daemon, and `|| true` on per-line appends):

- Each `printf >> "$FIFO"` opens/closes the FIFO, so the collector's reader hits EOF between lines, closes, and reconnects every ~0.5 s.
- If the reader closes mid-append, the writer gets SIGPIPE — fatal under `set -e`, and near-certain for daemons with high-volume startup logging (BIND 9.18 died this way; fixed in the DNS providers, still latent in the older mqtt/ollama provider entrypoints).

The FIFO is tertiary: raw pcap and normalized JSONL from the collector are the primary evidence and never depend on it.

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
