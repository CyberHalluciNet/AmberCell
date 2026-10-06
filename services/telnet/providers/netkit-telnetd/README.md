# Telnet provider: netkit-telnetd (alternate)

**Protocol cell:** `telnet`  
**Provider id:** `netkit-telnetd`  
**Select:** `AMBER_TELNET_PROVIDER=netkit-telnetd`

Classic **netkit-telnetd 0.17** (built from Debian orig tarball, SHA-256 pinned) on Debian bookworm-slim.
Accepted via `tcpserver` (IPv4-only). Same `amber-login` + `/jail` pattern as `busybox-telnetd`.

## Contract

- Real telnetd under cell containment.
- **IPv4 listener only**.
- `provider_id=netkit-telnetd` on evidence.

## Build

```bash
docker build -t ambercell/telnet-netkit-telnetd:local services/telnet/providers/netkit-telnetd
```

## Runtime env

Same as `busybox-telnetd` / `inetutils-telnetd` (`AMBER_TELNET_PORT`, `BIND`, `JAIL`, `RUN_DIR`).

## Compose note

Same `telnet-hi` containment as the default provider. No compose change required.
