# amberctl

Go operator CLI for AmberCell (**Stage-1 FTP + Telnet**). Manages evidence layout, Compose lifecycle, status/drift, export, drill, liveness, and locked rebuild/reset.

## Build

```bash
go build -o amberctl .
```

Requires Go 1.22+ and `docker` / `docker compose` on `PATH` for lifecycle commands.

## Environment

| Variable | Default | Purpose |
|----------|---------|---------|
| `AMBER_EVIDENCE_ROOT` | `/var/ambercell` | Evidence tree (prod: `0750` `root:amber`) |
| `AMBER_ROOT` | *(walk up from cwd)* | Repo root containing `compose.yaml` |
| `COMPOSE_PROFILES` | `lab,core` | Compose profiles |
| `AMBER_ENFORCE_CONTAINMENT` | unset | `1` loads `compose.containment.yaml` |
| `AMBER_LAB_BIND` | `127.0.0.1` | Lab publish address (`0.0.0.0` for remote/Spot; lock SG) |
| `AMBER_LAB_EXPOSE` | unset | `1` also loads `compose.lab.expose.yaml` |
| `AMBER_FTP_HOST_PORT` | `21` | Lab FTP port for drill/liveness |
| `AMBER_TELNET_HOST_PORT` | `2323` | Lab Telnet port for drill/liveness |
| `AMBER_FTP_CELL_IP` / `AMBER_TELNET_CELL_IP` | catalog IPs | Conntrack flush targets |

## Commands

| Command | Description |
|---------|-------------|
| `init` | Evidence dirs mode `0750`; canaries + `seed_manifest.json`; permissions notes |
| `up ftp\|telnet` | Build/up collector+hi (+ dns-sinkhole); regenerate canaries |
| `down ftp\|telnet` | Stop **hi** first, wait, then **collector** |
| `status [--drift]` | Compose ps + state; drift checks provider/seed/nft hashes |
| `export [-out DIR]` | Closed JSONL segments only |
| `drill ftp\|telnet` | TCP + banner (FTP `220` / Telnet any read) |
| `liveness [--once] [svc]` | Every 30s; 3 fails → `snapshot_then_rebuild` |
| `reset\|rebuild ftp\|telnet` | flock → hi-stop → conntrack → collector-stop → canaries → up |
| `execute-decision --decision … [--svc …]` | FSM: alert/annotate OK; rebuild/quarantine with cooldown |

Rebuild lock busy → exit **6**. Cooldown exceeded → exit **5**.

### Rebuild order

lock → stop hi → wait → **conntrack flush** → stop collector → canaries → up → unlock.

On **Darwin**, conntrack and nft quarantine are logged as would-run stubs (lab gap — not production G1–G11 green).

## Module

```
github.com/CyberHalluciNet/AmberCell/amberctl
```

## License

AmberCell Public Source License v1.0 — see [`../LICENSE`](../LICENSE),
[`../NOTICE`](../NOTICE), and [`../COMMERCIAL.md`](../COMMERCIAL.md).
Go sources use `SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0`.
