# Telnet provider: busybox-telnetd (default)

**Protocol cell:** `telnet`  
**Provider id:** `busybox-telnetd`  
**Select:** `AMBER_TELNET_PROVIDER=busybox-telnetd`

Real BusyBox `telnetd` on Alpine 3.20. Stage-1 scaffold: custom login wrapper logs credentials to **stdout**, disposable `/jail` tree, interactive `/bin/sh`. Full PTY transcript and normalized `auth` events are **collector-owned** (pcap + `transcripts/telnet/`).

## Contract

- Real telnetd under cell containment (`read_only`, caps, `memswap_limit` = `mem_limit`, `init: true` on `telnet-hi`).
- **IPv4 listener only** — `telnetd -b 0.0.0.0`; IPv6 disabled on the shared collector netns via Compose sysctls.
- Evidence field names are protocol-stable; set `provider_id=busybox-telnetd` on flows/events.
- Image base pinned by digest (same Alpine index as `vsftpd` provider).

## Build

From repo root:

```bash
docker build -t ambercell/telnet-busybox-telnetd:local services/telnet/providers/busybox-telnetd
```

## Runtime env

| Variable | Default | Purpose |
| --- | --- | --- |
| `AMBER_TELNET_PORT` | `23` | Listen port |
| `AMBER_TELNET_BIND` | `0.0.0.0` | IPv4 bind address (not `::`) |
| `AMBER_TELNET_JAIL` | `/jail` | Fake FS root for sessions |
| `AMBER_TELNET_RUN_DIR` | `/var/run/telnetd` | Runtime state (tmpfs in compose) |

## Login wrapper

`/usr/sbin/amber-login` (invoked by `telnetd -l`) prompts for username/password, prints:

```text
amber-auth: user=<name> pass=<secret>
```

to stdout, then execs an interactive shell. Do not rely on container logs alone in production — the telnet collector captures cleartext on `tcp/23` and writes transcript files under `/var/ambercell/transcripts/telnet/`.

## `read_only` rootfs and tmpfs

When `telnet-hi` uses `read_only: true`, mount **tmpfs** for paths that must be writable at runtime:

| Mount | Mode (suggested) | Why |
| --- | --- | --- |
| `/tmp` | tmpfs | general scratch |
| `/var/run/telnetd` | tmpfs | telnetd runtime |
| `/jail/tmp` | tmpfs (optional) | session writes in jail |

Image content (`/jail` skeleton except session tmp) stays on the read-only layer.

## Compose containment (reference)

- **`privileged: false`**, no **`/var/run/docker.sock`** mount.
- **`cap_drop: ALL`**, **`cap_add: NET_BIND_SERVICE`** (and minimal set if the runtime requires it for telnetd/login).
- **`network_mode: service:telnet-collector`** — no evidence mount on `telnet-hi`.
- Provider image built from this directory.

## Alternate providers

| Provider | Status |
| --- | --- |
| `inetutils-telnetd` | Documented slot (not implemented) |

## Stage-1 smoke checklist

- Control: `23/tcp` LISTEN on collector netns
- Login wrapper emits `amber-auth` on stdout
- Collector emits `session_open` + `auth` JSONL and a transcript file per session
