# POP3 provider: dovecot (default)

**Protocol cell:** `pop3`  
**Provider id:** `dovecot`  
**Select:** `AMBER_POP3_PROVIDER=dovecot`

## Contract

- Real POP3 against **seeded mailboxes only**.
- Capture auth + RETR/DELE; artifacts hashed; `provider_id=dovecot`.

## Implementation status

**Stage-2 (lab):** Dockerfile + passwd-file lure users (`exec`, `finance`, `hr`, `it`, `canary`) with seeded mboxes; POP3 on `172.30.20.10:110` via `network_mode: service:pop3-collector`.
