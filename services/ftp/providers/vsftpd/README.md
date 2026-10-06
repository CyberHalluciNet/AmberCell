# FTP provider: vsftpd (default)

**Protocol cell:** `ftp`  
**Provider id:** `vsftpd`  
**Select:** `AMBER_FTP_PROVIDER=vsftpd`

Real [vsftpd](https://security.appspot.com/vsftpd.html) on Alpine 3.20. Stage-1: anonymous + weak local accounts, seeded tree under `/var/ftp/pub`, writable upload path `/var/ftp/incoming`, `LIST`, PASV/EPSV on `30000–30049`, Active Mode disabled.

## Contract

- Real FTP daemon under cell containment (`read_only`, caps, seccomp/AppArmor, `memswap_limit` = `mem_limit`).
- **Active Mode disabled** (`port_enable=NO`, `connect_from_port_20=NO`). PASV/EPSV only on `30000–30049`.
- **`pasv_address`** rendered at start from **`AMBER_FTP_PASV_ADDRESS`** (public IP or operator override). Without it, the entrypoint falls back to `127.0.0.1` and logs a warning (lab/CI only).
- **`listen_ipv6=NO`** — IPv4 control listener only.
- Evidence field names are protocol-stable; set `provider_id=vsftpd` on flows/events.
- Image digest pinned in compose/lockfile at deploy (Stage-0B compose todo). This Dockerfile pins **`alpine:3.20` by tag** with a TODO to record the base digest in the lock workflow.

## Build

From repo root:

```bash
docker build -t ambercell/ftp-vsftpd:local services/ftp/providers/vsftpd
```

## Runtime env

| Variable | Required | Purpose |
| --- | --- | --- |
| `AMBER_FTP_PASV_ADDRESS` | Production yes | Replaces `@PASV_ADDRESS@` in `vsftpd.conf.template` |

## Smoke accounts (lab only)

| Account | Password | Notes |
| --- | --- | --- |
| `anonymous` | (none) | Root `/var/ftp` — read `pub/`, upload to `incoming/` |
| `ftpuser` | `ftpuser` | Chroot under `/home/ftpuser/ftp` |
| `upload` | `upload` | Chroot under `/home/upload/ftp` (weak lure) |

Do not expose these credentials on the public Internet outside a honeypot context.

## Seed layout (Stage-1)

| Path | Mode | Purpose |
| --- | --- | --- |
| `/var/ftp/pub/README.txt` | read-only | Banner file for anonymous listings |
| `/var/ftp/pub/docs/about.txt` | read-only | Sample doc in seeded tree |
| `/var/ftp/pub/samples/data.csv` | read-only | Sample data file |
| `/var/ftp/incoming/` | `1733`, owner `ftp` | Anonymous/local STOR landing (tmpfs in compose for runtime writes) |
| `/home/ftpuser/ftp/files/` | local chroot | Weak account listing smoke |
| `/home/upload/ftp/files/welcome.txt` | local chroot | Second weak account |

## `read_only` rootfs and tmpfs

When `ftp-hi` uses `read_only: true`, mount **tmpfs** (or writable volumes) for paths vsftpd must mutate at runtime:

| Mount | Mode (suggested) | Why |
| --- | --- | --- |
| `/var/run/vsftpd` | tmpfs | `secure_chroot_dir`, runtime state |
| `/tmp` | tmpfs | session scratch |
| `/var/log` | tmpfs | only if file logging is enabled later |

Image content (`/var/ftp/pub`, `/home/ftpuser/ftp`, `/home/upload/ftp`, `/etc/vsftpd/*`) stays on the read-only layer. Compose mounts **tmpfs** on `/var/ftp/incoming` so STOR uploads survive `read_only: true` on the hi-cell.

## Compose containment (reference — wired in Stage-0B compose)

- **`privileged: false`**, no **`/var/run/docker.sock`** mount.
- **`cap_drop: ALL`**, **`cap_add: NET_BIND_SERVICE`** (control port 21).
- **`init: true`**, IPv6 sysctls off, `mem_limit` / matching `memswap_limit`.
- Provider image built from this directory; not a third-party vsftpd image.

## Config layout

| File | Role |
| --- | --- |
| `vsftpd.conf.template` | Static policy; `@PASV_ADDRESS@` placeholder |
| `entrypoint.sh` | Substitutes `AMBER_FTP_PASV_ADDRESS`, ensures `secure_chroot_dir`, exec vsftpd |
| `user_list` | Deny-list entry `ftp` blocks direct `USER ftp` while anonymous (same uid) stays allowed; local smoke uses `ftpuser` |

## Stage-0B smoke checklist

- Control: `21/tcp`
- Passive range: `30000–30049/tcp` advertised with injected `pasv_address`
- `PORT` / Active Mode rejected by daemon (`port_enable=NO`)
- Anonymous `LIST` on `/var/ftp/pub`
