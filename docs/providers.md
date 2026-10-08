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
(no nested Compose defaults required). Setting `AMBER_<SVC>_HI_IMAGE` skips the
local hi-image build, while the collector and dns-sinkhole images still build.
Interactive setup: `amberctl init` (TTY) or `amberctl init --wizard` — see README.

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

Beta cells (ntp/syslog/ldap): protocol, drills, and raw flows are verified; event decode is
best-effort (tcpdump-printer dependent on the current Alpine build).

## Remote tunnel provider (`remote`)

Every Wave F/G cell ships a `remote` provider: instead of a local daemon, an
L4 `socat` relay forwards cell traffic to **your own existing server** — the
backend address is freely configurable and does **not** need to be localhost:

```bash
export AMBER_LDAP_PROVIDER=remote
export AMBER_LDAP_REMOTE_ADDR=ldap.corp.example:389   # any reachable host:port
export AMBER_LDAP_REMOTE_TRANSPORT=tcp                 # tcp | udp | both (default both)
./amberctl/amberctl up ldap
```

- The collector still captures all traffic at the cell front-end (pcap + raw
  flows + events); the relay is L4 and never inspects or rewrites bytes.
- The backend must be reachable from the cell network — add it to the
  operator-managed remote-backend egress allowlist (`nftables/egress.nft`);
  relays may not widen the general egress allowlist (**G14**).
- UDP relays are per-datagram request/response: fine for SNMP/NTP/syslog/DNS;
  **TFTP data channels negotiate new ports** and only the udp/69 control
  channel is relayed — full TFTP transfers need a local daemon provider.

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
| dns | `coredns` | `coredns`, `bind9`, `unbound` |
| tftp | `dnsmasq` | `dnsmasq` (fixed transfer range 30050–30089), `tftpd-hpa`, `atftpd` (random transfer ports — NAT caveat), `remote` |
| snmp | `snmpd` | `snmpd`, `snmpd-debian`, `remote` (both premade are net-snmp builds) |
| ntp *(beta)* | `chrony` | `chrony`, `openntpd`, `ntp-classic`, `remote` |
| syslog *(beta)* | `rsyslog` | `rsyslog`, `syslog-ng`, `remote` |
| sip | `kamailio` | `kamailio`, `opensips`, `remote` |
| ldap *(beta)* | `openldap` | `openldap` (slapd), `glauth`, `remote` |
| imap | `dovecot` | `dovecot`, `remote` |
| memcached | `memcached` | `memcached` (official image; empty answers only), `remote` |
| rdp | `xrdp` | `xrdp`, `remote` |
| vnc | `tigervnc` | `tigervnc` (Xvnc), `remote` |
| netbios | `nmbd` | `nmbd` (samba), `remote` |

Architecture notes and ports: [`DESIGN.md`](DESIGN.md) §5–6 (local draft; may be gitignored).
Wizard menus list only providers that currently ship a `Dockerfile`.

### Protocol-specific (DNS)

- [ ] **Authoritative-only** — no recursion, no forwarders, no open-resolver mode; every non-lure query is REFUSED (kill bar **G13**).
- [ ] Lure zones consistent with the persona (default: `ambercell.lab`, `corp.example.net`); zone data hashes go into the seed manifest.
- [ ] Stable CHAOS `version.bind`/identity string per provider, recorded in evidence (`server_product`).
- [ ] Listens on `udp/53` **and** `tcp/53` (AXFR/IXFR probes arrive over TCP; they must be denied and captured).
- [ ] The daemon's working/scratch directory must be a **tmpfs** (e.g. `/tmp`) — the compose baseline mounts the rootfs `read_only`, and BIND 9.18 drops privileges *before* parsing config, so a root-owned image path as `directory` is a fatal `permission denied`. Reference zone files by absolute read-only path.
- [ ] Hold one persistent writer on the log FIFO (see [`../collectors/README.md`](../collectors/README.md) § hi→collector log FIFO) — per-line open/close can SIGPIPE the entrypoint under high-volume startup logging.

### Switch example

```bash
export AMBER_FTP_PROVIDER=proftpd   # or pure-ftpd
./amberctl/amberctl up ftp
AMBER_FTP_PROVIDER=proftpd ./tests/test_smoke_ftp.sh
```
