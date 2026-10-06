# Security Policy

## Supported versions

AmberCell is under active development. Report issues against the default branch unless a release branch is named in a GitHub Security Advisory.

## Reporting a vulnerability

**Do not** open a public issue for containment failures, privilege escalations, evidence-plane leaks, or other security defects before a fix is available.

Prefer a private channel:

1. GitHub Security Advisories / private vulnerability reporting on this repository, or
2. Email the maintainers listed in the repository’s security contact (if configured).

Include: affected commit or tag, host OS, Compose profile (`lab` / `production`), reproduction steps, and impact (egress, lateral reach, host namespace, dead-drop write, evidence mutation, etc.).

Containment and kill-bar bugs (**G1–G11**) are not discussed with full exploit detail in public issue comments until a patch or mitigating release exists.

## Captured data and operator law

Honeypot captures may include credentials, uploaded files, and other third-party content. Operators are responsible for lawful collection, retention, and sharing under local law. Default dead-drop publish class is `summary` (metadata and decisions without passwords, transcript bodies, artifact bytes, or pcaps). Class `full` and pcap publication require an explicit operator flag.

## Safe defaults

- `lab` is the default Compose profile; CI must not open public honeypot ports or pull live malware.
- Canary secrets use an obviously fake documented prefix — never live cloud credentials.
- Consumers pull from the dead drop (or optional S3); they do not SSH to the host or join `ambernet`.
