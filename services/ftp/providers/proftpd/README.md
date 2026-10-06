# FTP provider: proftpd (alternate)

**Protocol cell:** `ftp`  
**Provider id:** `proftpd`  
**Select:** `AMBER_FTP_PROVIDER=proftpd`

Real [ProFTPD](http://www.proftpd.org/) on Alpine 3.20 (same digest pin as [`../vsftpd/`](../vsftpd/)). Same Stage-1 contract: anonymous + weak local accounts, seeded tree under `/var/ftp/pub`, writable upload path `/var/ftp/incoming`, `LIST`, PASV/EPSV on `30000–30049`, Active Mode disabled.

## Contract

- Real FTP daemon under cell containment (`read_only`, caps, seccomp/AppArmor, `memswap_limit` = `mem_limit`).
- **Active Mode disabled** (`<Limit PORT EPRT LPRT> DenyAll`). PASV/EPSV only on `30000–30049`.
- **`MasqueradeAddress`** rendered at start from **`AMBER_FTP_PASV_ADDRESS`** (public IP or operator override). Without it, the entrypoint falls back to `127.0.0.1` and logs a warning (lab/CI only).
- **`UseIPv6 off`** — IPv4 control listener only.
- Evidence field names are protocol-stable; set `provider_id=proftpd` on flows/events.
- Base image pinned by digest (same Alpine index as vsftpd).

## Build

From repo root:

```bash
docker build -t ambercell/ftp-proftpd:local services/ftp/providers/proftpd
```

## Runtime env

| Variable | Required | Purpose |
| --- | --- | --- |
| `AMBER_FTP_PASV_ADDRESS` | Production yes | Replaces `@PASV_ADDRESS@` in `proftpd.conf.template` |

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

When `ftp-hi` uses `read_only: true`, runtime state is written under **`/tmp`** (compose tmpfs):

| Mount | Mode (suggested) | Why |
| --- | --- | --- |
| `/tmp` | tmpfs | Rendered conf, PidFile, ScoreboardFile, DelayTable |
| `/var/ftp/incoming` | volume (compose) | STOR uploads |

Image content (`/var/ftp/pub`, `/home/ftpuser/ftp`, `/home/upload/ftp`, config template) stays on the read-only layer.

## Compose containment (reference — wired in Stage-0B compose)

- **`privileged: false`**, no **`/var/run/docker.sock`** mount.
- **`cap_drop: ALL`**, **`cap_add`** bind/chroot/setuid set (same as vsftpd).
- Provider image built from this directory; select with `AMBER_FTP_PROVIDER=proftpd`.

## Config layout

| File | Role |
| --- | --- |
| `proftpd.conf.template` | Static policy; `@PASV_ADDRESS@` placeholder; Active Mode Limit |
| `entrypoint.sh` | Substitutes `AMBER_FTP_PASV_ADDRESS`, ensures runtime dirs, exec `proftpd -n` |

## Stage-0B smoke checklist

- Control: `21/tcp`
- Passive range: `30000–30049/tcp` advertised with injected masquerade address
- `PORT` / Active Mode rejected by daemon (`DenyAll` on PORT/EPRT)
- Anonymous `LIST` on `/var/ftp/pub`

## Switch provider

```bash
export AMBER_FTP_PROVIDER=proftpd
export AMBER_FTP_PASV_ADDRESS=127.0.0.1   # lab
./amberctl/amberctl up ftp
# or: AMBER_FTP_PROVIDER=proftpd AMBER_FTP_HOST_PORT=2121 ./tests/test_smoke_ftp.sh
```
