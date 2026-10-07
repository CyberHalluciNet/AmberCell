# AmberCell Production Host Ops Runbook

**Status:** Stage-4 — core four (SMTP/POP3/FTP/Telnet) operator path.  
Narrative companion: [`../docs/RUNBOOK.md`](../docs/RUNBOOK.md). Normative design: [`../docs/DESIGN.md`](../docs/DESIGN.md).

## Support matrix

| OS | Role |
| --- | --- |
| Ubuntu 22.04 LTS | Supported production |
| Debian 12 | Supported production |
| macOS (Darwin) | **Lab only** — does not satisfy kill bars G1–G11 |

Production kill bars are verified on Linux with `tests/test_stage4_verify.sh` and `AMBER_RUN_PRODUCTION_VERIFY=1`. Darwin and default CI **SKIP** G1–G11 honestly; lab runs smoke/replay/publish subset only.

---

## 1. Install

### 1.1 Packages

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin nftables apparmor-utils \
  conntrack curl ca-certificates
sudo systemctl enable --now docker
```

Docker **24+** and Compose **v2** required.

### 1.2 Host baseline

1. Apply sysctl draft (review before production):

   ```bash
   sudo cp ops/sysctl.conf /etc/sysctl.d/99-ambercell.conf
   sudo sysctl --system
   ```

   Includes IPv6 disable on ambernet-facing interfaces, `ip_forward`, `rp_filter`, raised inotify limits, and notes on scoped core dumps (see [`coredump-scoped.md`](coredump-scoped.md) — **do not** point host-wide `kernel.core_pattern` at evidence).

2. Docker `daemon.json` (userns-remap, log rotation):

   ```bash
   sudo cp ops/daemon.json /etc/docker/daemon.json
   sudo systemctl restart docker
   ```

3. Evidence and dead drop:

   ```bash
   sudo groupadd -f amber
   sudo groupadd -f amber-drop
   sudo mkdir -p /var/ambercell/deaddrop
   sudo chown root:amber /var/ambercell
   sudo chmod 0750 /var/ambercell
   sudo chown root:amber-drop /var/ambercell/deaddrop
   sudo chmod 0750 /var/ambercell/deaddrop
   ```

4. Read-only consumer account (G11):

   ```bash
   sudo bash ops/amberdrop-user.sh
   ```

   `amberdrop` may read `/var/ambercell/deaddrop/` only — no shell elsewhere, no docker socket, no cell networks.

5. Secrets (`/etc/ambercell/`, mode **0600**): webhooks, optional S3 write keys. **Never** in Compose env for cells or inside the drop.

6. Build CLI and init:

   ```bash
   cd /opt/ambercell   # git checkout
   cd amberctl && go build -o amberctl .
   sudo AMBER_EVIDENCE_ROOT=/var/ambercell ./amberctl init
   ```

### 1.3 AppArmor

Load per-cell profiles before `production` profile:

```bash
sudo apparmor_parser -r apparmor/ftp.profile apparmor/telnet.profile
# smtp/pop3 profiles when present on host
```

Enforce mode required for production.

### 1.4 Compose profiles

```bash
export COMPOSE_PROFILES=production,core
export AMBER_ENFORCE_CONTAINMENT=1
export AMBER_FTP_PASV_ADDRESS=<PUBLIC_IPV4>
```

No Compose `ports:` on honeypot services in production — exposure is **nftables DNAT only**.

### 1.5 nftables

1. Edit `nftables/ingress.nft` placeholders: `WAN_IFACE`, `AMBERNET_IFACE` (docker bridge for `ambernet`).
2. Set **`AMBER_FTP_PASV_ADDRESS=<PUBLIC_IPV4>`** before bringing up FTP (required in production; `127.0.0.1` refused by `amberctl up`).
3. Apply ingress + egress via CLI (preferred) or manually:

   ```bash
   export COMPOSE_PROFILES=production,core
   export AMBER_ENFORCE_CONTAINMENT=1
   export AMBER_FTP_PASV_ADDRESS=<PUBLIC_IPV4>
   sudo -E ./amberctl/amberctl up ftp   # applies nft after cell is up
   # or explicitly:
   sudo ./amberctl/amberctl nft apply
   ```

   Manual equivalent: `sudo nft -f nftables/ingress.nft && sudo nft -f nftables/egress.nft`.

4. Unload FTP conntrack helper: `sudo modprobe -r nf_conntrack_ftp` (or blacklist). `amberctl nft apply` attempts this automatically.
5. Quarantine set `amber_quarantine` — `amberctl execute-decision quarantine_then_rebuild` inserts the **cell IP** (post-DNAT filter); removed after healthy rebuild.

### 1.6 DNS sinkhole (ambermgmt)

Cells must not resolve external DNS directly. Host DNAT sends cell UDP/53 to sinkhole on `172.31.10.53` (`dns-sinkhole` service). See [`dns-sinkhole/README.md`](dns-sinkhole/README.md).

### 1.7 Optional hardening (host capability gated)

| Feature | When | Notes |
| --- | --- | --- |
| gVisor | Stage-3+ optional | Shell cells (telnet/ssh); runc fallback documented |
| Tetragon/eBPF | Stage-3+ optional | Additive telemetry; collectors own evidence |
| Cosign on rebuild | `AMBER_ENFORCE_COSIGN=1` | Refuses unverified digests |

Not required for lab green; document if unavailable on host.

### 1.8 Admin SSH vs honeypot tcp/22 (G9)

**Production (kill bar G9):** honeypot `ssh-cell` owns public **tcp/22** via [`nftables/ingress.nft`](../nftables/ingress.nft) DNAT → `172.30.50.10`. Operator admin SSH **must not** listen on public 22.

1. Move `sshd` to a non-standard port (example **22222**) and restrict with firewall allowlist / VPN only.
2. Verify: from the Internet, `tcp/22` reaches the honeypot cell only; admin login uses the alternate port or out-of-band console.
3. Lab profile: honeypot SSH is published as `127.0.0.1:${AMBER_SSH_HOST_PORT:-2222}` — this is **not** a substitute for G9 on a production host.

**Wave A ingress (production):** DNAT **22** → ssh, **6379** → redis, **1883** → mqtt (same file). Apply only with `COMPOSE_PROFILES=production,wave-a` (no Compose `ports:` on WAN).

**Wave B ingress (production):** DNAT **80/443** → http (`172.30.80.10`), **3306** → mysql, **5432** → postgres. Profiles: `production,wave-b`.

**Wave C ingress (production):** DNAT **445** → smb, **27017** → mongo, **9200** → elastic. Profiles: `production,wave-c`.

**Ingress ≠ egress:** Honeypot **ingress** DNAT (above) exposes lure services on the public IP. Cell **egress** from `ambernet` remains capped by [`nftables/egress.nft`](../nftables/egress.nft) (~2 Mbps, tcp/80+443 only, no outbound tcp/25). Do not conflate WAN-facing http-cell ports with outbound browsing from cells.

**SMB containment:** Production applies strict seccomp (`seccomp/smb.json`) via `compose.containment.yaml`; **gVisor** runtime is preferred when the host supports it (optional; runc fallback documented).

**Elastic lab note:** `elastic-cell` defaults to **2g** mem / **512** pids; skip in laptop smoke with `AMBER_SMOKE_SKIP_ELASTIC=1`.

---

## 2. Operate

### 2.1 Bring up core fleet

```bash
for svc in smtp pop3 ftp telnet; do
  ./amberctl/amberctl up "$svc"
done
./amberctl/amberctl status --drift
```

### 2.2 Drills

```bash
./amberctl/amberctl drill smtp
./amberctl/amberctl drill pop3
./amberctl/amberctl drill ftp
./amberctl/amberctl drill telnet
# Wave A (after COMPOSE_PROFILES includes wave-a):
./amberctl/amberctl drill ssh
./amberctl/amberctl drill redis
./amberctl/amberctl drill mqtt
# Wave B/C (COMPOSE_PROFILES includes wave-b / wave-c):
./amberctl/amberctl drill http
./amberctl/amberctl drill mysql
./amberctl/amberctl drill postgres
./amberctl/amberctl drill smb
./amberctl/amberctl drill mongo
./amberctl/amberctl drill elastic
```

Wave A lab smoke: `./tests/test_smoke_wave_a.sh` · Wave B+C: `./tests/test_smoke_wave_bc.sh` · Wave D+E: `./tests/test_smoke_wave_de.sh` (Darwin/Linux; does **not** claim G1–G11 green).

**Wave D ingress (production):** DNAT **2375** → dockerapi trap (`172.30.140.10`), **10250** → kubelet trap (`172.30.150.10`). Profiles: `production,wave-d`. These cells are **API mocks only** — never mount host `docker.sock`, never run `dockerd`, never schedule pods on a real cluster (**G4/G8**). Static checks: `./tests/test_g4_g8_wave_d.sh`.

**Wave E ingress (production):** DNAT **11434** → ollama mock (`172.30.160.10`). Profile: `production,wave-e`. Default provider is CPU **mock** with stub model tags; model pulls are recorded, not executed against the public internet from the cell.

### 2.3 Logs

```bash
./amberctl/amberctl logs ftp
```

### 2.4 Rebuild / reset (never blocked by webhooks)

Order: **flock** → stop hi → wait → evidence flush → **conntrack flush** → stop collector → canaries → up.

```bash
./amberctl/amberctl rebuild ftp
```

Concurrent rebuild exits **6**. Cooldown violations exit **5**.

Webhooks use async circuit breaker (`AMBER_WEBHOOK_URL`); failures spill to `/var/ambercell/alerts/failed/` and do **not** stall rebuild.

### 2.5 AI decisions and review

```bash
./amberctl/amberctl ai decisions --svc ftp
python3 manager/review_queue.py --scan
./amberctl/amberctl ai review
./amberctl/amberctl ai approve dec_01K --note "expected lure use"
```

Preference pairs log under `state/preferences/`.

### 2.6 Dead drop publish

Default class **summary** (no passwords, transcript bodies, artifact bytes, pcaps):

```bash
./amberctl/amberctl publish
# explicit full (operator responsibility):
./amberctl/amberctl publish --class full
# large opt-in:
./amberctl/amberctl publish --class summary --pcap
```

Optional S3 mirror after local success: `AMBER_DEADDROP_S3_URI=s3://bucket/prefix/` (SSE, block public access; write keys only in `/etc/ambercell/`).

Consumers pull drop or S3 only — **never** ambernet, live JSONL mounts, or honeypot shell. Publish only reads closed segments — an active `*.jsonl.active` file is never copied into a bundle, so no bundle contains a partially written record.

### 2.7 Canary monitor + webhooks

```bash
python3 manager/canary_monitor.py --json
python3 manager/webhook_router.py --svc ftp --summary "canary token seen in STOR"
export AMBER_WEBHOOK_URL=https://hooks.example/...
export AMBER_DECISION_ID=dec_x AMBER_SESSION_ID=fp_x
./amberctl/amberctl execute-decision --decision alert --svc ftp
```

---

## 3. Rotate

| Asset | Action |
| --- | --- |
| Pcap rings | Rotate first under disk watermark; never delete JSONL/transcripts/artifacts for space |
| JSONL | Collectors close `*.jsonl.active` → timestamped segments; optional `vault/` archive (append-only) |
| Canaries | Regenerated on `rebuild`/`reset`; correlate via `state/<svc>.seed_manifest.json` |
| Webhook/S3 creds | Rotate in `/etc/ambercell/` only |
| Dead drop | New bundle per `publish`; consumers verify `manifest.json` sha256 |

---

## 4. Evidence / WORM handling

- Authoritative tree: `/var/ambercell/{raw-flows,jsonl,pcap,artifacts,transcripts,enrichment,state,decisions}` — collectors only; cells **no** host evidence mount.
- Closed segments are append-only; export and publish read closed/rotated files only (unless `export --live` debug).
- Core dumps: scoped pipe handler → `artifacts/cores/` (see [`coredump-scoped.md`](coredump-scoped.md)).

---

## 5. Teardown

1. `amberctl down <svc>` — hi first, then collector (do not reverse manually).
2. Production: flush conntrack for cell IP on rebuild/down when recreating netns.
3. Preserve `/var/ambercell` unless legal/policy requires wipe; dead drop may retain published copies separately.

---

## 6. Verify kill bars

```bash
# Lab / Darwin — subset only; G1–G11 reported SKIP
bash tests/test_stage4_verify.sh

# Dedicated Linux production host
AMBER_RUN_PRODUCTION_VERIFY=1 COMPOSE_PROFILES=production,core bash tests/test_stage4_verify.sh
```

See [`../tests/test_stage4_verify.sh`](../tests/test_stage4_verify.sh) for G1–G11 mapping. **G4/G8** (no host orchestration) apply when trap cells exist (Stage-7). **G9** documented above for ssh wave.

---

## 7. Anti-drift ops checklist

- [ ] `amberctl status --drift` clean before rotate
- [ ] `amberctl replay --diff` green in CI
- [ ] Provider id + digest match lockfile
- [ ] nft / AppArmor / policy hashes match git
- [ ] Compose `core` profile matches DESIGN catalog

---

## 8. License

AmberCell is under the [AmberCell Public Source License](../LICENSE) v1.0.
See [`../NOTICE`](../NOTICE) and [`../COMMERCIAL.md`](../COMMERCIAL.md).
