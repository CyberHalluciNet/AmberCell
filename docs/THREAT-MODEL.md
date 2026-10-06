# AmberCell Threat Model

**Status:** Draft  
**Aligned with:** kill bars G1–G11 in [`DESIGN.md`](DESIGN.md) / [`plan.md`](../plan.md)

## In scope

Single-host Docker Compose honeypot exposed (in production) via host nftables DNAT to protocol cells on `ambernet`. Evidence written by collectors to `/var/ambercell`. Optional dead-drop publication. Bounded AI manager on `ambermgmt` recommending actions executed only through `amberctl`.

## Adversary classes

### A1 — Internet scanner / opportunistic attacker

Interacts with published protocol ports (SMTP/POP3/FTP/Telnet/…), uploads files, attempts auth abuse, probes banners.

**Assumptions:** Contained by cell isolation, egress allowlist, Active Mode off (FTP), rate limits. Evidence must still emit on unknown/malformed sessions (**G5**).

### A2 — Credential and lure abuser

Uses seeded accounts, canaries, or stolen-looking secrets to test authenticity or pivot.

**Assumptions:** Canaries use fake documented prefixes; seeded material is content-addressed; dead-drop default omits credentials (**G11** privacy + operator law).

### A3 — Containment breaker (breakout / SSRF / lateral)

Attempts container escape, Active FTP PORT/EPRT as SSRF, ICC lateral moves, metadata/cloud SSRF, IPv6 bypass of IPv4 nft rules, outbound SMTP relay.

**Must fail closed against:** G1 (egress), G2 (ICC), G3 (host/metadata), G10 (tcp/25), edge cases 1.1–1.3.

### A4 — Orchestration abuser

Targets dockerapi/kubelet trap surfaces seeking privileged container create, mount host paths, or cluster exec.

**Must fail closed against:** G4, G8 — traps never control host dockerd/docker.sock or a real cluster.

### A5 — Evidence / control-plane abuser

Tries to wipe or rewrite evidence, stall rebuilds via slow webhooks, race concurrent rebuilds, or coerce the AI manager into unbounded remediation.

**Must fail closed against:** G5 (no silent drop on parse fail), G6 (AI never mutates evidence), G7 (bounded remediation), edge cases 4.1–4.2 (webhook breaker, flock).

### A6 — Dead-drop / consumer abuser

Tries to write the drop, read live authoritative evidence through the drop account, or obtain honeypot write keys via S3 misconfig.

**Must fail closed against:** G11.

### A7 — Operator / admin conflict

Admin SSH left on public `tcp/22` while honeypot ssh-cell claims that port.

**Must fail closed against:** G9 — documented split (non-standard admin port or OOB console).

## Out of model (explicit)

| Out of model | Why |
| --- | --- |
| Multi-host / K8s orchestration of AmberCell itself | Design is single-host Compose |
| Compromised host kernel / privileged host operator | Host compromise is outside cell containment |
| Physical access / supply-chain of upstream distro | Document digests/Cosign; not a full SBOM substitute for OS |
| Legal interception beyond operator’s jurisdiction | Operator law is out of band (`SECURITY.md`) |
| Cloud LLM as a required dependency | Kill bars must green without cloud AI |
| Generative fake shells replacing real daemons | Conflicts with high-interaction definition |
| Inline TLS/L7 proxy terminating attacker sessions | Violates no-proxy-on-path principle |
| Nested real container engines in honeypot cells | Forbidden by G4/G8 |

## Trust boundaries

```text
Internet  --nft DNAT-->  ambernet cells  --collectors-->  /var/ambercell
                              |                              |
                              x no route to ambermgmt        +--publish--> deaddrop / optional S3
ambermgmt: DNS sinkhole + AI manager (read evidence, emit decisions)
amberctl: sole executor of rebuild/quarantine/export/publish
```

## Residual risks (accepted for Draft)

- Real daemons increase attack surface vs mock HI; mitigated by seccomp/AppArmor/budgets/rebuild.
- Lab profile publishes ports — operators must not expose lab to the Internet expecting production kill bars.
- Optional gVisor/Tetragon/Cosign improve posture but are not required for green bars on unsupported hosts.

## License

AmberCell Public Source License — see [`../LICENSE`](../LICENSE) and [`../COMMERCIAL.md`](../COMMERCIAL.md).
