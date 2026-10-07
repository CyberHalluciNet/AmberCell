# Dead Drop & Sensor Deployment

**Status:** Stage-4 implementation — local drop, publish classes, manifest, optional S3 mirror are live in `amberctl`. Items marked **[hardening wave]** (at-rest `age` encryption, `status.v1` status bulletin, `amberctl deaddrop rotate-keys`) are specified in [`../plan.md`](../plan.md) (§ Dead-drop hardening) and are **not yet implemented**; this page describes them so consumers can build against the target contract.

This page covers three things:

1. How the dead drop works (one-way intelligence handoff).
2. How a consumer retrieves, verifies, and (once the hardening wave lands) decrypts published data.
3. How to launch new AmberCell **sensors** — one AmberCell deployment per host — and configure them so central/remote systems can launch and monitor them unattended.

---

## 1. How the dead drop works

### What it is

The dead drop is a **one-way handoff directory**. External systems — SIEM, SOC dashboards, peer honeypots — take intelligence from the drop; they never SSH to the sensor, never join `ambernet`, never read live JSONL, and never mount `/var/ambercell` except the drop itself. The honeypot opens no health-check or query port for consumers.

```text
collectors + AI manager  -->  /var/ambercell/   (authoritative, host-only)
amberctl publish         -->  /var/ambercell/deaddrop/  (copies only)
                         \->  $AMBER_DEADDROP_S3_URI/<bundle>/   (optional mirror)
analyst / SIEM / peer system  pulls the drop or S3 only
```

- **Authoritative store** `/var/ambercell/` (or `$AMBER_EVIDENCE_ROOT`) is host-only; the publisher never moves or rewrites files under `raw-flows/`, `jsonl/`, `pcap/`, `artifacts/`, `transcripts/`, `enrichment/` — it only copies.
- Drop directory: `/var/ambercell/deaddrop/`, mode `0750`, owner `root`, group `amber-drop`. The `amberdrop` account (see [`../ops/amberdrop-user.sh`](../ops/amberdrop-user.sh)) has read-only access to this directory and nothing else (no shell, no docker socket, no cell state) — that is kill bar **G11**.
- Cells never see this path; no container bind-mount includes `deaddrop/`.

### Publish classes

`amberctl publish [--class summary|full] [--pcap] [--svc SVC]`

| Class | Contents |
| --- | --- |
| `summary` *(default)* | `decisions/`, `enrichment/`, `alerts/` trees; closed `raw-flows/`; **closed `jsonl/` with sensitive keys redacted** |
| `full` *(explicit flag)* | Everything in summary **unredacted**, plus `transcripts/`, `artifacts/`, closed `jsonl/` with credential fields |
| `--pcap` *(explicit flag)* | Adds closed `pcap/` slices (size-heavy; keep opt-in) |

Redaction in `summary` rewrites the keys `password`, `pass`, `body`, `body_preview`, `transcript`, `data`, `raw` to `"[redacted]"` while streaming. Uploaded files and captured credentials are confidential operator data (often third-party content) — class `full` and pcap publication stay operator decisions.

### Closed-segments rule

The publisher copies **closed material only** — it skips `*.jsonl.active` files, any `*.jsonl` with a `.active` sidecar, and `.lock` files. A publish never tears a live JSONL line; the same rule `amberctl export` follows.

### Bundle layout and manifest

Each run creates one bundle:

```text
/var/ambercell/deaddrop/publish-<class>-<YYYYMMDDThhmmssZ>/
├── manifest.json
├── raw-flows/<svc>/…jsonl
├── jsonl/<svc>/…jsonl          # redacted in summary
├── decisions/…  enrichment/…  alerts/…
└── (full: transcripts/…, artifacts/…   --pcap: pcap/…)
```

`manifest.json` (`deaddrop-manifest.v1`) is the integrity contract — every entry carries path, sha256, schema version, size:

```json
{
  "schema_version": "deaddrop-manifest.v1",
  "publish_class": "summary",
  "published_at": "2026-10-07T09:15:00.512345678Z",
  "bundle_id": "publish-summary-20261007T091500Z",
  "entries": [
    {
      "path": "raw-flows/ftp/20261007T0912.jsonl",
      "sha256": "9f2c…",
      "schema_version": "rawflow.v1",
      "size_bytes": 20414
    }
  ]
}
```

**[hardening wave]** adds: a minimal plaintext envelope `manifest.json` (ciphertext hashes, algorithm, key fingerprint) plus an encrypted `manifest.enc.json` with plaintext details; every payload file `age`-encrypted before it is written, so plaintext never exists inside the drop.

### Optional S3 mirror

Set `AMBER_DEADDROP_S3_URI=s3://bucket/prefix` (plus standard `AWS_*` credentials) and `amberctl publish` mirrors the bundle to `<URI>/<bundle_id>/` via `aws s3 sync --sse AES256`. The upload is asynchronous and best-effort (one logged retry) — it never blocks capture, evidence flush, or rebuild. Server-side encryption stays on as defense in depth; **[hardening wave]** makes the upload ciphertext-only.

### Publishing cadence

`amberctl publish` is invoked manually, from a cron/systemd timer (§ 4.2), and after lifecycle events. **[hardening wave]** makes every publish also emit the `status.v1` bulletin on a 60 s timer + lifecycle events, so remote monitoring works even between evidence publishes.

---

## 2. Retrieving published data

### Where consumers pull from

| Channel | Who | How |
| --- | --- | --- |
| Local drop | Host-side agents running as `amberdrop` (read-only) | Read `/var/ambercell/deaddrop/` directly |
| S3 (preferred for remote) | Central SIEM / SOC / peers | `aws s3 sync s3://bucket/prefix/ ./drops/` with a **read-only role** |

Consumers never log into the honeypot to browse evidence and never receive S3 write keys.

### Pull + verify

```bash
# S3
aws s3 sync s3://amber-drops/prod-edge-01/ ./drops/prod-edge-01/
cd drops/prod-edge-01/publish-summary-20261007T091500Z

# verify every entry against the manifest (integrity before use)
jq -r '.entries[] | "\(.sha256)  \(.path)"' manifest.json | sha256sum -c -
```

Then ingest: raw flows carry `schema_version: rawflow.v1`, events `event.v1`, decisions `decision.v1` — validate against [`docs/schemas/`](schemas/) before storage, and reject bundles mixing incompatible schema major versions.

### Decrypt **[hardening wave]**

Once the hardening wave lands, drop files are `age`-encrypted to recipient public keys provisioned by `amberctl init` from the startup config. Consumers hold the matching private key (never stored on the sensor):

```bash
age --decrypt -i consumer.key publish-summary-….tar.age > bundle.tar
```

`manifest.json` records the key fingerprint per file; during a rotation window both old and new fingerprints appear. Rotation is `amberctl deaddrop rotate-keys` (add recipient → overlap window → retire fingerprint).

### Remote monitoring via the status bulletin **[hardening wave]**

Every publish writes an encrypted `status.v1` bulletin — a metadata-only health note. Per service cell it reports `state` (`running|failed|quarantined|stopped|rebuilding`), liveness result, `started_at`/`uptime_seconds`, `first_event_ts`/`last_event_ts`, collection counters (raw flows, events, sessions, artifacts, bytes), `provider_id`, drift and quarantine flags. Fleet level: `generated_at`, monotonic `publish_seq`, `host_id`, profile, overall health, optional `operator_note`. It carries no credentials, transcripts, or artifact bytes — decrypt and render or forward to SIEM. Monitor `publish_seq` for gaps: a stalled sequence means the sensor stopped publishing.

---

## 3. Launching a new sensor

A **sensor** is one AmberCell deployment on one host. Support matrix: Ubuntu 22.04 / Debian 12 for production; Docker Desktop is fine for lab smoke.

### Prerequisites

- Docker 24+ with Compose v2; Go 1.2x to build `amberctl`; Linux + root for production containment (nftables, AppArmor).
- A host you accept exposing: production sensors are meant to receive Internet scanner traffic on their published ports.

### Bootstrap (lab)

```bash
git clone <repo> AmberCell && cd AmberCell
cp .env.example .env                  # edit providers/ports locally; never commit it
cd amberctl && go build -o amberctl . && cd ..

export COMPOSE_PROFILES=lab,core
export AMBER_EVIDENCE_ROOT="${PWD}/.ambercell-lab"
export AMBER_FTP_PASV_ADDRESS=127.0.0.1

./amberctl/amberctl init --yes        # headless: evidence tree only
./amberctl/amberctl up ftp && ./amberctl/amberctl drill ftp
./amberctl/amberctl status
```

On a TTY, plain `amberctl init` runs the provider wizard and writes `AMBER_<SVC>_PROVIDER` (and optional own-Docker keys) into repo-root `.env` — see [`docs/providers.md`](providers.md).

### Bootstrap (production)

```bash
export COMPOSE_PROFILES=production,core
export AMBER_EVIDENCE_ROOT=/var/ambercell
export AMBER_ROOT=/opt/AmberCell            # repo root with compose.yaml
export AMBER_FTP_PASV_ADDRESS=198.51.100.10 # sensor public IPv4 — required, not 127.0.0.1
export AMBER_ENFORCE_CONTAINMENT=1          # layer in compose.containment.yaml (seccomp/AppArmor)

sudo apparmor_parser -r apparmor/ftp.profile apparmor/telnet.profile
./amberctl/amberctl init --yes
for c in ftp telnet smtp pop3; do ./amberctl/amberctl up $c; done
# nft apply runs automatically after production `up` (skip: AMBER_SKIP_NFT_APPLY=1);
# nftables/ingress.nft + egress.nft need WAN_IFACE / AMBERNET_IFACE set — see ops/RUNBOOK.md
```

Host prep for production (`userns-remap`, sysctls, `amber`/`amber-drop` groups, DNS sinkhole network): [`ops/RUNBOOK.md`](../ops/RUNBOOK.md).

### Choose the service set

`COMPOSE_PROFILES` selects cells: `core` (smtp, pop3, ftp, telnet), `wave-a` (ssh, redis, mqtt), `wave-b`/`wave-c` (http, mysql, postgres / smb, mongo, elastic), `wave-d`/`wave-e` (dockerapi, kubelet traps / ollama). A minimal edge sensor can run `production,core` only.

### Verify before exposing

```bash
./amberctl/amberctl drill ftp telnet smtp pop3   # banner probes per cell
./amberctl/amberctl status --drift               # compose/nft/seed/policy hashes + provider/digest
./amberctl/amberctl liveness --once              # TCP+banner probes (30s loop mode: amberctl liveness)
```

---

## 4. Configuring sensors for remote systems that launch them

### 4.1 Headless provisioning contract

Everything a launcher needs is environment/file-driven — no interactive steps:

| Input | Purpose |
| --- | --- |
| Pre-seeded `.env` (from `.env.example`) | Providers (`AMBER_<SVC>_PROVIDER`), own-Docker overrides (`AMBER_<SVC>_HI_IMAGE` / `AMBER_<SVC>_PROVIDER_CONTEXT`), lab ports, `AMBER_FTP_PASV_ADDRESS`, `AMBER_DEADDROP_S3_URI`, `AMBER_WEBHOOK_URL` |
| `AMBER_INIT_NONINTERACTIVE=1` or `init --yes` | Skip the wizard (evidence tree only) |
| `COMPOSE_PROFILES` | Service set + exposure (`lab` vs `production`) |
| `AMBER_ROOT`, `AMBER_EVIDENCE_ROOT` | Where compose.yaml and the evidence tree live |

Per-sensor secrets (S3 write keys, webhook token, optional `AMBER_AI_API_KEY`) live in `/etc/ambercell/` mode `0600` on the sensor — never in the repo, never in the drop, never in cell images.

### 4.2 Keep it running: systemd units

`/etc/systemd/system/ambercell-liveness.service` — watchdog, independent of the AI manager:

```ini
[Unit]
Description=AmberCell liveness probes (TCP+banner, 30s)
After=docker.service
[Service]
Environment=AMBER_ROOT=/opt/AmberCell
Environment=AMBER_EVIDENCE_ROOT=/var/ambercell
ExecStart=/usr/local/bin/amberctl liveness
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
```

`ambercell-publish.service` + `.timer` — dead-drop publisher:

```ini
# .service: Type=oneshot, same Environment= lines, ExecStart=/usr/local/bin/amberctl publish
# .timer:   OnCalendar=*:0/10  (every 10 min), Persistent=true, [Install] WantedBy=timers.target
```

`systemctl enable --now ambercell-liveness.service ambercell-publish.timer`

### 4.3 Remote launch from a central system

A central launcher provisions sensors over its **management network**, using a dedicated deploy account — never the public `tcp/22` (the honeypot ssh-cell owns public 22 in production; admin SSH lives on an allowlisted alternate port — kill bar **G9**):

```bash
# one-shot provisioning, run from the fleet manager
ssh -p 22022 deploy@sensor-edge-01 'bash -s' <<'EOF'
set -euo pipefail
cd /opt/AmberCell && git pull --ff-only
cd amberctl && go build -o /usr/local/bin/amberctl . && cd ..
set -a; source /etc/ambercell/sensor.env; set +a   # pre-seeded per-sensor config
amberctl init --yes
for c in ftp telnet smtp pop3; do amberctl up $c; done
amberctl status --drift
EOF
```

Keep `amberctl` **local-only**: it is the containment executor (rebuild, quarantine, nft) and must never be exposed over the network. Remote systems launch and observe; the sensor's own guardrail FSM + `flock` + cooldown (exit 6 on concurrent rebuild, exit 5 over cooldown) protect against two launchers racing.

### 4.4 Central-side wiring

- **Per-sensor identity:** give each sensor its own S3 prefix (`s3://amber-drops/<sensor-id>/`) and consume each prefix separately — the bundle `manifest.json` + `published_at` timestamps are the per-sensor record. **[hardening wave]** adds `host_id` and `publish_seq` to the bulletin for fleet dashboards.
- **Push path:** optionally set `AMBER_WEBHOOK_URL` (+ `AMBER_WEBHOOK_TOKEN`) per sensor so alerts reach the SIEM directly; the webhook circuit breaker degrades gracefully (spills to `alerts/failed/`, never blocks rebuild) when the SIEM is slow or down.
- **Pull path:** a fleet collector syncs every sensor prefix on its own cadence, verifies manifests, and ingests. Fleet health = latest bulletin per sensor **[hardening wave]**; until then, latest `published_at` per prefix is the liveness signal.

### 4.5 Fleet security rules

- One key pair per sensor for dead-drop encryption **[hardening wave]** — a compromised sensor must not expose other sensors' traffic.
- S3 write credentials are per-sensor and write-only from the sensor's perspective; consumers use a separate read-only role. Bucket: public access blocked, SSE on, versioning/object-lock recommended.
- Rotation: rotate sensor S3 keys and dead-drop recipients (`deaddrop rotate-keys`) on the same schedule as canary/credential rotation in [`ops/RUNBOOK.md`](../ops/RUNBOOK.md).
- The drop is confidential: `summary` already redacts credential/transcript fields, and encryption **[hardening wave]** is on by default; `production` will refuse plaintext publication (kill bar **G12**).

---

## Related

- Architecture: [`DESIGN.md`](DESIGN.md) · Plan + kill bars: [`../plan.md`](../plan.md) (§ Dead drop, § Dead-drop hardening)
- Operator guide: [`RUNBOOK.md`](RUNBOOK.md) · Production host ops: [`../ops/RUNBOOK.md`](../ops/RUNBOOK.md)
- Providers: [`providers.md`](providers.md) · Schemas: [`schemas/`](schemas/)
- `amberdrop` account setup: [`../ops/amberdrop-user.sh`](../ops/amberdrop-user.sh)
