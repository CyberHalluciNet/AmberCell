# POP3 provider: cyrus (alternate)

**Protocol cell:** `pop3`  
**Provider id:** `cyrus`  
**Select:** `AMBER_POP3_PROVIDER=cyrus`

## Contract

- Real POP3 against **seeded mailboxes only**.
- Capture auth + RETR/DELE; `provider_id=cyrus`.
- Same lure users/passwords as dovecot (`exec`, `finance`, `hr`, `it`, `canary`).

## Implementation

Debian Cyrus IMAP/POP3 with sasldb auth. POP3 on `:110`; IMAP bound to `127.0.0.1:143` only for mailbox create/seed. Seeds injected over LMTP from `/opt/amber-seeds/*.mbox`.

## Build

```bash
docker build -t ambercell/pop3-cyrus:local services/pop3/providers/cyrus
```

## Compose note

`pop3-hi` is `read_only: false`; Cyrus uses `/var/lib/cyrus`, `/var/spool/cyrus`, `/run/cyrus` on the writable rootfs. Default dovecot tmpfs mounts are unused but harmless. No compose change required for lab.
