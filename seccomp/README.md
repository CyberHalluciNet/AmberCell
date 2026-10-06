# seccomp (Stage-1)

Per-cell seccomp JSON profiles. Included in `amberctl status --drift` (file hashes) and applied via [`compose.containment.yaml`](../compose.containment.yaml) on Linux production.

| File | Cell | Notes |
|------|------|--------|
| [`ftp.json`](ftp.json) | `ftp-hi` | Minimal allowlist for vsftpd socket/file syscalls |
| [`telnet.json`](telnet.json) | `telnet-hi` | busybox-telnetd + jail shell |

## Apply (Linux production)

```bash
export AMBER_ROOT=/path/to/AmberCell
export AMBER_ENFORCE_CONTAINMENT=1
# or COMPOSE_PROFILES=production,core (loads compose.containment.yaml)
docker compose -f compose.yaml -f compose.containment.yaml config
```

Smoke: after `amberctl up ftp` with containment, confirm `ftp-hi` is running and `amberctl drill ftp` returns a 220 banner. If the profile is too tight, the hi-cell will crash-loop — widen the allowlist under `providers/<name>/` deltas and retest.

**Lab / Darwin:** skip containment overlay; default `compose.yaml` uses `no-new-privileges` only.
