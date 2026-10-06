# SMB provider: samba-ad

**Provider id:** `samba-ad`  
**Select:** `AMBER_SMB_PROVIDER=samba-ad`

**Honest label:** attempts an in-container Samba **AD DC** provision (`samba-tool domain provision`). If provision fails under lab constraints, falls back to an AD-lookalike file server (`netlogon`/`sysvol` shares). Not a production Active Directory deployment.

Default realm: `AMBERCELL.LAB` / domain `AMBERCELL` (override via `AMBER_SMB_AD_*`).
