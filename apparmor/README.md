# AppArmor (Stage-1)

Per-cell AppArmor profiles for Linux production hosts.

| File | Profile name | Cell |
|------|----------------|------|
| [`ftp.profile`](ftp.profile) | `ambercell-ftp-hi` | `ftp-hi` |
| [`telnet.profile`](telnet.profile) | `ambercell-telnet-hi` | `telnet-hi` |

## Load + apply

```bash
sudo apparmor_parser -r -W apparmor/ftp.profile apparmor/telnet.profile
export AMBER_ROOT=/path/to/AmberCell
export AMBER_ENFORCE_CONTAINMENT=1
COMPOSE_PROFILES=production,core docker compose \
  -f compose.yaml -f compose.containment.yaml up -d --build
```

Smoke: `amberctl drill ftp` and `amberctl drill telnet` after load. Provider-specific deltas belong under `services/<svc>/providers/<name>/` and must be reflected in the profile hash for drift checks.

**Lab / Darwin / CI:** skip AppArmor.
