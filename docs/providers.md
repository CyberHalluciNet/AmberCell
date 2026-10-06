# Provider contract v1 (`provider_contract.v1`)

AmberCell protocol cells run **real** daemons under a shared containment contract.
Premade providers and **own Docker** images (prebuilt `HI_IMAGE` or build
`PROVIDER_CONTEXT`) are both supported. Own images that ignore this contract are
**allowed but unsupported** — operators accept drift, PASV/SSRF, and containment
gaps.

## Selection and precedence

| Mode | Env | Notes |
| --- | --- | --- |
| Premade | `AMBER_<SVC>_PROVIDER=<builtin>` | Build from `services/<svc>/providers/<name>/` |
| Own prebuilt | `AMBER_<SVC>_HI_IMAGE=<ref>` | Skip hi image build; prefer digest pins |
| Own Dockerfile | `AMBER_<SVC>_PROVIDER_CONTEXT=<dir>` | Directory must contain `Dockerfile` |

**Precedence:** `HI_IMAGE` > `PROVIDER_CONTEXT` > builtin path from `PROVIDER`.

`amberctl up` fully resolves and exports `AMBER_<SVC>_PROVIDER`,
`AMBER_<SVC>_HI_IMAGE`, and `AMBER_<SVC>_PROVIDER_CONTEXT` before Compose
(no nested Compose defaults required). Interactive setup:
`amberctl init` (TTY) or `amberctl init --wizard` — see README.

## Checklist (supported own images)

Own / alternate images are **supported** only when they meet all of the following.

### Containment and process

- [ ] Runs under Compose cell settings: `read_only` (or documented writable paths only via tmpfs), `cap_drop: ALL` plus the **minimum** `cap_add` the daemon needs, `security_opt: no-new-privileges:true`, `init: true`, matched `mem_limit` / `memswap_limit`, `pids_limit`.
- [ ] No `docker.sock`, Kubernetes API, or cluster credentials mounted or reachable from the hi container.
- [ ] No privileged mode, no host PID/network/IPC namespace, no extra host path binds beyond the cell’s declared volumes (uploads / shared FIFOs as designed for that protocol).
- [ ] IPv6 disabled in-cell (Compose sysctls or equivalent); no reliance on host IPv6.

### Protocol-specific (FTP)

- [ ] **Active Mode off** — reject or ignore `PORT` / `EPRT`; PASV (or EPSV) only.
- [ ] PASV data ports stay within the cell’s published / nft-mapped range (FTP: `30000–30049` unless the operator remaps host nft consistently).
- [ ] `AMBER_FTP_PASV_ADDRESS` (or daemon equivalent) advertises the correct public or lab address — never a surprise internal IP to the attacker path in production.

### Seeds and surface

- [ ] Seed / bait layout is local to the provider image or the cell’s shared upload volume — not host evidence under `/var/ambercell` (evidence mounts stay on the **collector** only).
- [ ] Default credentials and banners are intentional honeypot bait, not production secrets.

### Evidence stability

- [ ] Switching providers must **not** rename collector event fields. Record product identity as attributes: `provider_id`, `server_product`, `server_version` (and similar), not by changing the event schema.
- [ ] Stable families remain protocol-scoped (`ftp.*`, `smtp.*`, …) so nft, AI policies, and enrichment stay bound to the **protocol cell**, not the product name.

### Image hygiene

- [ ] Prefer digest-pinned refs (`repo@sha256:…`) over floating tags; avoid `:latest` in production.
- [ ] Pin **provider id + image digest** in cell state; `amberctl status --drift` fails if live ≠ configured.

## Unsupported (explicit)

- Auto-hardening arbitrary Hub images.
- Nested container engines or real kubelets (orchestration cells are **traps** only).
- Replacing high-interaction daemons with generative fake shells as the primary path.

## Premade layout

```text
services/<svc>/providers/<name>/
  README.md
  Dockerfile
  config/    # optional
  seeds/     # optional
```

## Premade catalog (≥3 OSS Dockerfiles per cell)

| Cell | Default | Providers |
| --- | --- | --- |
| ftp | `vsftpd` | `vsftpd`, `proftpd`, `pure-ftpd` |
| smtp | `postfix` | `postfix`, `exim`, `opensmtpd` |
| pop3 | `dovecot` | `dovecot`, `cyrus`, `courier` |
| telnet | `busybox-telnetd` | `busybox-telnetd`, `inetutils-telnetd`, `netkit-telnetd` |
| ssh | `openssh` | `openssh`, `dropbear`, `tinyssh` |
| redis | `redis-server` | `redis-server`, `valkey`, `keydb` |
| mqtt | `mosquitto` | `mosquitto`, `nanomq`, `emqx` |
| http | `nginx` | `nginx`, `httpd`, `caddy` |
| mysql | `mariadb` | `mariadb`, `percona`, `mysql` |
| postgres | `postgresql` | `postgresql`, `pgvector`, `timescaledb` |
| smb | `samba` | `samba`, `samba-ad`, `samba-shares` |
| mongo | `mongodb` | `ferretdb`, `mock`, `mongodb` |
| elastic | `elasticsearch` | `opensearch`, `zincsearch`, `elasticsearch` |
| dockerapi | `trap` | `trap`, `trap-v1.41`, `trap-swarm` |
| kubelet | `trap` | `trap`, `trap-unauth`, `trap-exec` |
| ollama | `mock` | `mock`, `ollama`, `localai` |

Architecture notes and ports: [`DESIGN.md`](DESIGN.md) §5–6 (local draft; may be gitignored).
Wizard menus list only providers that currently ship a `Dockerfile`.

### Switch example

```bash
export AMBER_FTP_PROVIDER=proftpd   # or pure-ftpd
./amberctl/amberctl up ftp
AMBER_FTP_PROVIDER=proftpd ./tests/test_smoke_ftp.sh
```
