# SMTP provider: exim (alternate)

**Protocol cell:** `smtp`  
**Provider id:** `exim`  
**Select:** `AMBER_SMTP_PROVIDER=exim`

## Contract

- Real MTA configured as **sinkhole only** — no real relay (egress tcp/25 dropped globally).
- Capture dialogue + message artifacts; `provider_id=exim` on evidence.
- Banner `mail.corp.example.net` / Exim (AmberCell sinkhole).

## Implementation

Alpine Exim accepting only `hr|finance|admin|support@corp.example.net`; external relay denied.
Shares network with `smtp-collector` on `172.30.10.10:25`.

## Build

```bash
docker build -t ambercell/smtp-exim:local services/smtp/providers/exim
```

## Compose note

Default `smtp-hi` tmpfs paths target Postfix spool; Exim uses `/var/spool/exim` on the writable rootfs (`read_only: false`). No compose change required for lab.
