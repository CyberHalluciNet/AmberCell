# SMTP provider: postfix (default)

**Protocol cell:** `smtp`  
**Provider id:** `postfix`  
**Select:** `AMBER_SMTP_PROVIDER=postfix`

## Contract

- Real MTA configured as **sinkhole only** — no real relay (egress tcp/25 dropped globally).
- Capture dialogue + message artifacts; `provider_id=postfix` on evidence.
- Stable banner recorded in seed manifest (persona anti-drift).

## Implementation status

**Stage-2 (lab):** Dockerfile + `main.cf` sinkhole for `@corp.example.net` virtual aliases (`hr`, `finance`, `admin`, `support`); relay to external domains rejected; banner `mail.corp.example.net`; shares network with `smtp-collector` on `172.30.10.10:25`.
