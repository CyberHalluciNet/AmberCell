# POP3 provider: courier (alternate)

**Protocol cell:** `pop3`  
**Provider id:** `courier`  
**Select:** `AMBER_POP3_PROVIDER=courier`

## Contract

- Real POP3 against **seeded Maildir mailboxes only**.
- Capture auth + RETR/DELE; `provider_id=courier`.
- Same lure users/passwords as dovecot (`exec`, `finance`, `hr`, `it`, `canary`).

## Implementation

Debian Courier POP3 + authdaemond (PAM). Seeds from `/opt/amber-seeds/*.mbox` into `~/Maildir/new`.
Listens on `0.0.0.0:110` via `couriertcpd`.

## Build

```bash
docker build -t ambercell/pop3-courier:local services/pop3/providers/courier
```

## Compose note

`pop3-hi` is `read_only: false`; Courier uses `/run/courier` and home Maildirs on the writable rootfs. Default dovecot tmpfs mounts are unused but harmless. No compose change required for lab.
