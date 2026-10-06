# AmberCell Runbook

**Status:** Stage-7 — core four + Waves A–E lab paths; production host ops in [`../ops/RUNBOOK.md`](../ops/RUNBOOK.md).  
Darwin lab **does not** satisfy G1–G11 (`tests/test_stage4_verify.sh` reports SKIP).

## Install (lab)

- Support matrix: Ubuntu 22.04 / Debian 12 for production; Docker Desktop OK for **lab** smoke.
- Clone repo; copy `.env.example` → `.env`.
- Build CLI: `cd amberctl && go build -o amberctl .`
- Init evidence tree: `AMBER_EVIDENCE_ROOT=./.ambercell-data ./amberctl/amberctl init`
  - Creates mode `0750` dirs; writes `state/permissions.notes` (prod: `root:amber`).
  - Generates `AMBERCANARY_*` values + `state/<svc>.seed_manifest.json`.
- Bring up cells (lab, localhost ports):

  ```bash
  export COMPOSE_PROFILES=lab,core
  export AMBER_FTP_HOST_PORT=2121
  export AMBER_TELNET_HOST_PORT=2323
  export AMBER_FTP_PASV_ADDRESS=127.0.0.1
  ./amberctl/amberctl up ftp
  ./amberctl/amberctl up telnet
  ./amberctl/amberctl up smtp
  ./amberctl/amberctl up pop3
  ```

- Lab mail ports (defaults; auto-picked if busy in smoke): SMTP `127.0.0.1:${AMBER_SMTP_HOST_PORT:-2525}`, POP3 `127.0.0.1:${AMBER_POP3_HOST_PORT:-1110}`.
- Wave A (optional): `export COMPOSE_PROFILES=lab,core,wave-a` then `amberctl up ssh|redis|mqtt`
  - Lab honeypot SSH: `127.0.0.1:${AMBER_SSH_HOST_PORT:-2222}` — **not** operator admin SSH (**G9**).
  - Redis `127.0.0.1:6379`, MQTT `127.0.0.1:1883` (override with `AMBER_*_HOST_PORT`).
- Wave B/C (Stage-6): `export COMPOSE_PROFILES=lab,wave-b,wave-c` then `amberctl up http|mysql|postgres|smb|mongo|elastic`
  - Lab ports: HTTP `${AMBER_HTTP_HOST_PORT:-8080}`, MySQL `13306`, Postgres `15432`, SMB `1445`, Mongo `27018`, Elastic `19200` (auto-picked in smoke).
  - **Ingress vs egress:** WAN DNAT to tcp/80/443 on the http-cell is attacker **ingress**; cell **egress** to the internet remains the global tcp/80/443 allowlist in `nftables/egress.nft`.
- Wave D/E (Stage-7): `export COMPOSE_PROFILES=lab,wave-d,wave-e` then `amberctl up dockerapi|kubelet|ollama`
  - Trap cells (**G4/G8**): dockerapi/kubelet are HTTP mocks only — no host engine socket, no real cluster.
  - Lab ports: Docker API `${AMBER_DOCKERAPI_HOST_PORT:-2375}`, kubelet `10250`, Ollama mock `11434`.
- Drill: `amberctl drill …` includes `http|mysql|postgres|smb|mongo|elastic|dockerapi|kubelet|ollama`
- Smoke: `AMBER_FTP_HOST_PORT=2121 ./tests/test_smoke_ftp.sh`; mail: `./tests/test_smoke_mail.sh`; Wave A: `./tests/test_smoke_wave_a.sh`; Wave B+C: `./tests/test_smoke_wave_bc.sh`; Wave D+E: `./tests/test_smoke_wave_de.sh` · G4/G8 static: `./tests/test_g4_g8_wave_d.sh` (`AMBER_SMOKE_SKIP_ELASTIC=1` if RAM constrained)
- Liveness (optional): `amberctl liveness --once` or long-running `amberctl liveness`
- Drift: `amberctl status --drift` (compose/nft/seed/policy hashes + per-cell provider/digest)
- Replay CI: `./tests/test_stage3_ci.sh` · Stage-4: `./tests/test_stage4_ci.sh`
- Publish dead drop: `amberctl publish` (class `summary` default) → `/var/ambercell/deaddrop/`
- Review queue: `python3 manager/review_queue.py --scan` · `amberctl ai review` · `amberctl ai approve ID`
- Webhooks: `AMBER_WEBHOOK_URL` + async breaker; spills to `alerts/failed/`; never blocks rebuild
- Replay: `amberctl replay --diff --actual GOLDEN GOLDEN`
- Critic: `python3 manager/critic.py path/to/decision.json` · `amberctl critic --decision PATH`
- Export: closed JSONL segments only (skips `*.jsonl.active` and symlinks); `--live` for debug
- AI sample: `AMBER_EVIDENCE_ROOT=… python3 manager/sample_decision.py --svc ftp|telnet|smtp|pop3`

## Production exposure (Linux)

- `COMPOSE_PROFILES=production,core` with `compose.yaml` (+ `compose.containment.yaml` or `AMBER_ENFORCE_CONTAINMENT=1`).
- Load AppArmor: `sudo apparmor_parser -r apparmor/ftp.profile apparmor/telnet.profile`
- Apply [`nftables/ingress.nft`](../nftables/ingress.nft) + [`nftables/egress.nft`](../nftables/egress.nft).
  - Set `WAN_IFACE`, `AMBERNET_IFACE` (docker ambernet bridge), public `AMBER_FTP_PASV_ADDRESS`.
  - Unload `nf_conntrack_ftp`.
- DNS: cells cannot use external udp/53; host DNAT → `172.31.10.53` on ambermgmt.
- **Darwin lab does not satisfy G1–G11.** Verify kill bars only on a Linux production host.

## Rotate

- JSONL: collectors write `*.jsonl.active`; rebuild flush closes segments into timestamped closed files + optional `vault/` archive (append-only).
- Rotate pcap rings under disk watermark; never delete JSONL/transcripts/artifacts to free space.
- Core dumps: scoped pipe handler only — see [`../ops/coredump-scoped.md`](../ops/coredump-scoped.md).
- Regenerate dynamic canaries on `amberctl rebuild` / `reset`; seed map on host.
- Credential/webhook secrets live only under `/etc/ambercell/` (mode `0600`).

## Drill / rebuild / reset

- `amberctl drill ftp|telnet|smtp|pop3|ssh|redis|mqtt` — TCP + banner (SSH `SSH-` / Redis PING / MQTT TCP).
- `amberctl rebuild|reset ftp|telnet|smtp|pop3|ssh|redis|mqtt` — flock → stop hi → wait → conntrack flush → stop collector → canaries → up.
- Concurrent lock holders exit **6**.
- Rebuild cooldown: 15m gap, max 3/hour (exit **5** when exceeded).
- `amberctl execute-decision --decision snapshot_then_rebuild --svc ftp` respects FSM + cooldown.
- Quarantine: executor logs `nft add element … amber_quarantine` (applied on Linux).

## Teardown

- Order: SIGTERM `*-hi` first → wait → flush evidence → conntrack flush (production) → stop collector.
- `amberctl down ftp|telnet|smtp|pop3` stops hi before collector.
- Preserve `/var/ambercell` unless operator explicitly wipes.

## Providers

- Contract + catalog: [`providers.md`](providers.md)
- Wizard: `amberctl init` (TTY) or `init --wizard`; scripts use `init --yes`
- Switch premade: `AMBER_<SVC>_PROVIDER=<name>` then `amberctl up <svc>`
- Own Docker: `AMBER_<SVC>_HI_IMAGE` or `AMBER_<SVC>_PROVIDER_CONTEXT` (see providers.md)

## Related

- Architecture: [`DESIGN.md`](DESIGN.md)
- Threats: [`THREAT-MODEL.md`](THREAT-MODEL.md)
- Plan: [`../plan.md`](../plan.md)
- License: [`../LICENSE`](../LICENSE) (AmberCell Public Source License), [`../COMMERCIAL.md`](../COMMERCIAL.md)
