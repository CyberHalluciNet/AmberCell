# AmberCell

Single-host Docker Compose honeypot: protocol cells with pluggable real servers, collector-owned capture, host nftables containment, JSONL + pcap evidence, ATT&CK/Engage enrichment, a bounded AI manager, and Go CLI `amberctl`.

**Status:** Stage-4 core Submit (SMTP, POP3, FTP, Telnet). See [`plan.md`](plan.md).

## Quickstart (lab, `profile=core`, ~30s)

```bash
cd amberctl && go build -o amberctl . && cd ..
export COMPOSE_PROFILES=lab,core
export AMBER_EVIDENCE_ROOT="${PWD}/.ambercell-lab"
export AMBER_FTP_PASV_ADDRESS=127.0.0.1
./amberctl/amberctl init
./amberctl/amberctl up ftp && ./amberctl/amberctl drill ftp
./amberctl/amberctl status
```

Mail cells: `./amberctl/amberctl up smtp && ./amberctl/amberctl drill smtp` (ports `2525` / `1110` on localhost by default).

CI: `./tests/test_stage3_ci.sh` · Stage-4 lab: `./tests/test_stage4_ci.sh` · Production kill bars (Linux only): `AMBER_RUN_PRODUCTION_VERIFY=1 ./tests/test_stage4_verify.sh`

## Purpose

- High-interaction protocol surfaces using **real** daemons under a shared containment contract.
- Raw-first evidence: pcaps and flows before normalized events, enrichment, and AI decisions.
- Dead-drop intelligence handoff (`amberctl publish` → `/var/ambercell/deaddrop/`) so consumers never join the honeypot network.

## Non-goals

- Not an offensive toolkit, exploit framework, or credential-stuffing wordlist repo.
- Not nested container orchestration: Docker API / kubelet cells are **traps**, never host control planes.
- AI and TLS proxies stay **off** the attacker packet path.
- Cloud LLMs are not required for green kill bars.

## Lab vs production

| Profile | Exposure | Expectation |
| --- | --- | --- |
| `lab` (default) | Compose published ports for laptop/CI | Smoke, schema, replay, publish lab tests |
| `production` | Host nftables DNAT only | Must meet kill bars G1–G11 on a dedicated Linux host |

**Darwin / laptop lab does not satisfy G1–G11.** `test_stage4_verify.sh` reports SKIP for production bars and runs the lab subset only.

## amberctl surface (Stage-4)

`init` · `up` · `down` · `status [--drift]` · `logs` · `export` · `publish` · `drill` · `replay [--diff]` · `reset` · `rebuild` · `ai decisions|approve|review` · `critic` · `liveness` · `execute-decision`

## Support matrix

| Host | Status |
| --- | --- |
| Ubuntu 22.04 LTS | Supported (production) |
| Debian 12 | Supported (production) |

Requires Docker 24+ and Compose v2. Production: [`ops/RUNBOOK.md`](ops/RUNBOOK.md) (nftables, AppArmor, sysctl, dead drop, webhooks).

## Docs

- [`plan.md`](plan.md) — normative stage plan and tracked todos
- [`docs/DESIGN.md`](docs/DESIGN.md) — architecture (Status: Draft)
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — adversary model
- [`docs/RUNBOOK.md`](docs/RUNBOOK.md) — operator guide
- [`ops/RUNBOOK.md`](ops/RUNBOOK.md) — production host ops
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting
- [`LICENSE`](LICENSE) / [`COMMERCIAL.md`](COMMERCIAL.md) — Public Source License + OEM
- [`docs/schemas/`](docs/schemas/) — JSON Schema drafts + examples

## License

AmberCell project code is under the [AmberCell Public Source License](LICENSE)
(source-available; not OSI open source). Third-party image licenses: see
[`NOTICE`](NOTICE). Commercial / OEM licensing: see [`COMMERCIAL.md`](COMMERCIAL.md).
