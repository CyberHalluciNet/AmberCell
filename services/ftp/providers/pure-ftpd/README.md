# FTP provider: pure-ftpd (alternate)

**Protocol cell:** `ftp`  
**Provider id:** `pure-ftpd`  
**Select:** `AMBER_FTP_PROVIDER=pure-ftpd`

Real [Pure-FTPd](https://www.pureftpd.org/) **1.0.51** built on Alpine 3.20 (same digest pin as [`../vsftpd/`](../vsftpd/)). Same Stage-1 contract: anonymous + weak local accounts, seeded tree under `/var/ftp/pub`, writable upload path `/var/ftp/incoming`, `LIST`, PASV/EPSV on `30000–30049`, Active Mode disabled.

## Contract

- Real FTP daemon under cell containment (`read_only`, caps, seccomp/AppArmor, `memswap_limit` = `mem_limit`).
- **Active Mode disabled:** upstream Pure-FTPd has no `port_enable=NO` equivalent. This image rebuilds 1.0.51 with [`disable-active-mode.patch`](disable-active-mode.patch) so `PORT`/`EPRT` return `502 Active mode is disabled`. PASV/EPSV only on `30000–30049`.
- **`ForcePassiveIP` (`-P`)** rendered at start from **`AMBER_FTP_PASV_ADDRESS`**. Without it, the entrypoint falls back to `127.0.0.1` and logs a warning (lab/CI only).
- **IPv4 only** (`-4`).
- Evidence field names are protocol-stable; set `provider_id=pure-ftpd` on flows/events.
- Base image pinned by digest (same Alpine index as vsftpd).

## Build

From repo root:

```bash
docker build -t ambercell/ftp-pure-ftpd:local services/ftp/providers/pure-ftpd
```

## Runtime env

| Variable | Required | Purpose |
| --- | --- | --- |
| `AMBER_FTP_PASV_ADDRESS` | Production yes | Replaces `@PASV_ADDRESS@` in `pure-ftpd.flags.template` |

## Smoke accounts (lab only)

| Account | Password | Notes |
| --- | --- | --- |
| `anonymous` | (none) | Root `/var/ftp` — read `pub/`, upload to `incoming/` |
| `ftpuser` | `ftpuser` | Chroot under `/home/ftpuser` |
| `upload` | `upload` | Chroot under `/home/upload` (weak lure) |

Do not expose these credentials on the public Internet outside a honeypot context.

## Seed layout (Stage-1)

| Path | Mode | Purpose |
| --- | --- | --- |
| `/var/ftp/pub/README.txt` | read-only | Banner file for anonymous listings |
| `/var/ftp/pub/docs/about.txt` | read-only | Sample doc in seeded tree |
| `/var/ftp/pub/samples/data.csv` | read-only | Sample data file |
| `/var/ftp/incoming/` | `1733`, owner `ftp` | Anonymous/local STOR landing (tmpfs/volume in compose) |
| `/home/ftpuser/ftp/files/` | local chroot | Weak account listing smoke |
| `/home/upload/ftp/files/welcome.txt` | local chroot | Second weak account |

## `read_only` rootfs and tmpfs

| Mount | Mode (suggested) | Why |
| --- | --- | --- |
| `/tmp` | tmpfs | Rendered flags, PID file |
| `/var/ftp/incoming` | volume (compose) | STOR uploads |

## Compose containment (reference — wired in Stage-0B compose)

- **`privileged: false`**, no **`/var/run/docker.sock`** mount.
- **`cap_drop: ALL`**, **`cap_add`** bind/chroot/setuid set (same as vsftpd).
- Provider image built from this directory; select with `AMBER_FTP_PROVIDER=pure-ftpd`.

## Config layout

| File | Role |
| --- | --- |
| `pure-ftpd.flags.template` | CLI argv template (`@PASV_ADDRESS@`); listens on `:21` |
| `disable-active-mode.patch` | Rejects PORT/EPRT inside the daemon |
| `entrypoint.sh` | Substitutes PASV address, exec `pure-ftpd` in foreground |

## Stage-0B smoke checklist

- Control: `21/tcp`
- Passive range: `30000–30049/tcp` advertised with injected `ForcePassiveIP`
- `PORT` / Active Mode rejected by daemon (`502`)
- Anonymous `LIST` on `/var/ftp/pub`

## Switch provider

```bash
export AMBER_FTP_PROVIDER=pure-ftpd
export AMBER_FTP_PASV_ADDRESS=127.0.0.1   # lab
./amberctl/amberctl up ftp
# or: AMBER_FTP_PROVIDER=pure-ftpd AMBER_FTP_HOST_PORT=2121 ./tests/test_smoke_ftp.sh
```
