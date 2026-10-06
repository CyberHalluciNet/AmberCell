# Telnet provider: inetutils-telnetd (alternate)

**Protocol cell:** `telnet`  
**Provider id:** `inetutils-telnetd`  
**Select:** `AMBER_TELNET_PROVIDER=inetutils-telnetd`

GNU inetutils `telnetd` on Debian bookworm-slim, accepted via `tcpserver` (IPv4-only).
Same `amber-login` wrapper and `/jail` pattern as `busybox-telnetd`.

## Contract

- Real telnetd under cell containment (`read_only`, caps, `memswap_limit` = `mem_limit`, `init: true`).
- **IPv4 listener only** — `tcpserver` bind `0.0.0.0`.
- Evidence field names protocol-stable; `provider_id=inetutils-telnetd`.

## Build

```bash
docker build -t ambercell/telnet-inetutils-telnetd:local services/telnet/providers/inetutils-telnetd
```

## Runtime env

| Variable | Default | Purpose |
| --- | --- | --- |
| `AMBER_TELNET_PORT` | `23` | Listen port |
| `AMBER_TELNET_BIND` | `0.0.0.0` | IPv4 bind address |
| `AMBER_TELNET_JAIL` | `/jail` | Fake FS root for sessions |
| `AMBER_TELNET_RUN_DIR` | `/var/run/telnetd` | Runtime state (tmpfs in compose) |

## Compose note

Same `telnet-hi` containment as the default provider. No compose change required.
