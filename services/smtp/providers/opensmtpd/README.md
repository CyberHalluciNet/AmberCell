# SMTP provider: opensmtpd (alternate)

**Protocol cell:** `smtp`  
**Provider id:** `opensmtpd`  
**Select:** `AMBER_SMTP_PROVIDER=opensmtpd`

## Contract

- Real MTA configured as **sinkhole only** — no real relay.
- Capture dialogue + message artifacts; `provider_id=opensmtpd` on evidence.
- Banner hostname `mail.corp.example.net`.

## Implementation

Alpine OpenSMTPD accepting only `@corp.example.net` aliases (`hr`, `finance`, `admin`, `support`).
External recipients rejected. Shares network with `smtp-collector` on `172.30.10.10:25`.

## Build

```bash
docker build -t ambercell/smtp-opensmtpd:local services/smtp/providers/opensmtpd
```

## Compose note

Uses `/var/spool/smtpd` on writable rootfs (`smtp-hi` is `read_only: false`). No compose change required for lab.
