# amberctl

Go operator CLI for AmberCell. It manages evidence initialization, Compose
lifecycle, provider selection, drift/status reporting, export and publish,
service drills, bounded AI review/approval, and guarded rebuild/reset flows.

## Build

```bash
go build -o amberctl .
```

Requires Go 1.22+ and `docker` / `docker compose` on `PATH` for lifecycle
commands.

## Environment

| Variable | Default | Purpose |
|----------|---------|---------|
| `AMBER_EVIDENCE_ROOT` | `/var/ambercell` | Evidence tree (production expects `0750` and `root:amber`) |
| `AMBER_ROOT` | *(walk up from cwd)* | Repo root containing `compose.yaml` |
| `COMPOSE_PROFILES` | `lab,core` | Service set and exposure mode |
| `AMBER_INIT_NONINTERACTIVE` | unset | `1` skips the init wizard (`init --yes`) |
| `AMBER_ENFORCE_CONTAINMENT` | unset | `1` layers `compose.containment.yaml` |
| `AMBER_FTP_PASV_ADDRESS` | unset | Required public IPv4 for production FTP |
| `AMBER_SKIP_NFT_APPLY` | unset | `1` skips automatic `nft apply` after production `up` |
| `AMBER_LAB_BIND` | `127.0.0.1` | Lab publish address (`0.0.0.0` only for controlled remote labs) |
| `AMBER_<SVC>_PROVIDER` | catalog default | Premade provider under `services/<svc>/providers/` |
| `AMBER_<SVC>_HI_IMAGE` | unset | Prebuilt hi image; skips hi-image build |
| `AMBER_<SVC>_PROVIDER_CONTEXT` | builtin path | Custom Docker build context |
| `AMBER_<SVC>_HOST_PORT` | service-specific | Lab drill/liveness port override for that cell |

### Init wizard

```bash
./amberctl init --yes                 # evidence only (CI/scripts)
./amberctl init                       # TTY → wizard
./amberctl init --wizard --cells ftp  # force wizard for one cell
```

See [`../docs/providers.md`](../docs/providers.md) for `provider_contract.v1`,
supported provider catalogs, and own-Docker precedence
(`HI_IMAGE` > `PROVIDER_CONTEXT` > premade).

## Service coverage

`amberctl` supports the full service catalog currently shipped in
`compose.yaml`:

- Core: `ftp`, `telnet`, `smtp`, `pop3`
- Wave A: `ssh`, `redis`, `mqtt`
- Wave B/C: `http`, `mysql`, `postgres`, `smb`, `mongo`, `elastic`
- Wave D/E: `dockerapi`, `kubelet`, `ollama`
- Wave F: `dns`
- Wave G: `tftp`, `snmp`, `ntp`, `syslog`, `sip`, `ldap`
- Wave H: `imap`, `memcached`, `rdp`, `vnc`, `netbios`

Profile selection happens through `COMPOSE_PROFILES`, for example:

```bash
export COMPOSE_PROFILES=lab,core
export COMPOSE_PROFILES=lab,core,wave-a
export COMPOSE_PROFILES=production,core
```

## Commands

| Command | Description |
|---------|-------------|
| `init [--yes\|--wizard] [--cells ...]` | Create the evidence tree, generate canaries/seeds, optionally write provider choices to `.env` |
| `up <svc>` | Resolve provider/image/context, regenerate canaries, bring up collector + hi pair, and apply `nft` automatically in production |
| `down <svc>` | Stop hi before collector for a clean evidence flush |
| `status [--drift]` | Show compose state and, with `--drift`, compare provider/seed/policy state to expectations |
| `logs [svc]` | Show service logs (`docker compose logs`) |
| `export [-out DIR] [--live]` | Export JSONL evidence; default is closed segments only |
| `publish [--class summary\|full] [--pcap] [--svc SVC]` | Build a dead-drop bundle and optionally mirror to S3 |
| `drill <svc>` | Run a protocol-appropriate health probe against the service |
| `liveness [--once] [svc]` | Run probes every 30s; after 3 failures trigger `snapshot_then_rebuild` |
| `replay [--diff] [--actual PATH] <golden.jsonl\|case>` | Replay goldens for regression checks |
| `reset <svc>` / `rebuild <svc>` | Exclusive lock, stop hi, flush evidence, conntrack cleanup, regenerate canaries, then start clean |
| `ai decisions [--svc SVC]` | List pending bounded AI decisions |
| `ai review [--svc SVC]` | Show review queue details |
| `ai approve ID` | Approve a queued action |
| `critic --decision PATH` | Run the decision critic locally |
| `execute-decision --decision <action> [--svc <svc>]` | Execute allowed FSM actions such as `alert`, `snapshot_then_rebuild`, or `quarantine_then_rebuild` |
| `nft apply\|status` | Apply or inspect nftables state |

## Lifecycle guarantees

- `rebuild` is gated by a dwell-time check; if recent activity suggests the cell
  should stay up longer, the command exits **4** unless
  `AMBER_FORCE_REBUILD=1` is set.
- Concurrent `reset`/`rebuild` calls are serialized with `flock`; a busy lock
  exits **6**.
- Rebuild cooldown violations exit **5**.
- In production, `up ftp` refuses `AMBER_FTP_PASV_ADDRESS=127.0.0.1` and
  requires a real public IPv4.

### Rebuild order

lock → stop hi → wait → evidence flush → **conntrack flush** → stop collector →
canaries → up → unlock.

On **Darwin**, conntrack and nft quarantine are logged as would-run stubs. That
path is useful for lab workflows, not for production kill-bar claims.

## Recommended operator flows

Lab smoke:

```bash
export COMPOSE_PROFILES=lab,core
export AMBER_EVIDENCE_ROOT="${PWD}/.ambercell-lab"
export AMBER_FTP_PASV_ADDRESS=127.0.0.1

./amberctl init --yes
./amberctl up ftp
./amberctl drill ftp
./amberctl status --drift
```

Production baseline:

```bash
export COMPOSE_PROFILES=production,core
export AMBER_EVIDENCE_ROOT=/var/ambercell
export AMBER_ENFORCE_CONTAINMENT=1
export AMBER_FTP_PASV_ADDRESS=<PUBLIC_IPV4>

./amberctl init --yes
./amberctl up ftp
./amberctl nft status
./amberctl status --drift
```

For full operator guidance, use [`../docs/RUNBOOK.md`](../docs/RUNBOOK.md) and
[`../ops/RUNBOOK.md`](../ops/RUNBOOK.md).

## Module

```
github.com/CyberHalluciNet/AmberCell/amberctl
```

## License

AmberCell Public Source License v1.0 — see [`../LICENSE`](../LICENSE),
[`../NOTICE`](../NOTICE), and [`../COMMERCIAL.md`](../COMMERCIAL.md).
Go sources use `SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0`.
