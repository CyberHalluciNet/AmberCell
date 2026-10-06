# Scoped core dumps → `/var/ambercell/artifacts/cores/`

**Do not** set host-wide `kernel.core_pattern` to a directory under `/var/ambercell`.
That would capture unrelated host processes and widen data retention risk.

## Recommended pattern (Linux production)

1. Create `/var/ambercell/artifacts/cores/` mode `0750` root:amber.
2. Install the scoped pipe handler from this repo:

   ```bash
   install -m 0755 ops/libexec/ambercell-coredump /usr/local/libexec/ambercell-coredump
   ```

   The handler drains the kernel pipe, accepts only AmberCell-looking `comm` /
   cgroup names, and writes `{base}.core` + `{base}.json` metadata under
   `/var/ambercell/artifacts/cores/` (override with `AMBER_CORE_DIR`).
3. Example sysctl line:

   ```text
   kernel.core_pattern = |/usr/local/libexec/ambercell-coredump %p %s %c %d %P
   ```

## Lab / Darwin

Leave the OS default core pattern. Cell crashes are diagnosed via container logs and
`amberctl liveness` failures; core capture is production-only.

See also [`sysctl.conf`](sysctl.conf) commentary and [`../docs/RUNBOOK.md`](../docs/RUNBOOK.md).
