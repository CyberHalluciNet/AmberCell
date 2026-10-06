# Canaries (Stage-1)

Decoy credentials, tokens, and filesystem markers for engagement and exfil detection. **Never** use real secrets.

## Naming

All synthetic canary values use the prefix **`AMBERCANARY_`** so operators and automation can distinguish honeypot bait from production material (e.g. `AMBERCANARY_ftp_upload_token`).

## Generation

`amberctl init`, `amberctl up`, and `amberctl rebuild|reset` call the canary generator:

- Writes values under `$AMBER_EVIDENCE_ROOT/state/canaries/<svc>/`
- Writes **`state/<svc>.seed_manifest.json`** with path → sha256 entries
- Notes production ownership: `/var/ambercell` mode **0750**, owner **root:amber**

Lab trees inherit the invoking uid; apply `chown root:amber` / `chmod 0750` on Linux production hosts.
