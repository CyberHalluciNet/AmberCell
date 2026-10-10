# AmberCell

Single-host Docker Compose honeypot: protocol cells with pluggable real servers, collector-owned capture, host nftables containment, JSONL + pcap evidence, ATT&CK/Engage enrichment, a bounded AI manager, and Go CLI `amberctl`.

**Status:** Current tree includes the core cells plus Waves A-H, provider
selection, dead-drop publish/export, and the bounded `amberctl` operator path.
See [`CHANGELOG.md`](CHANGELOG.md) for shipped deltas and [`plan.md`](plan.md)
for local planning detail.

**Site:** static landing in [`site/`](site/) — GitHub Pages
<https://cyberhallucinet.github.io/AmberCell/>

## Quickstart (lab, `profile=core`, ~30s)

```bash
cd amberctl && go build -o amberctl . && cd ..
export COMPOSE_PROFILES=lab,core
export AMBER_EVIDENCE_ROOT="${PWD}/.ambercell-lab"
export AMBER_FTP_PASV_ADDRESS=127.0.0.1
./amberctl/amberctl init --yes          # scripts/CI: evidence tree only
# Humans: ./amberctl/amberctl init      # TTY → provider wizard → .env
#         ./amberctl/amberctl init --wizard --cells ftp
./amberctl/amberctl up ftp && ./amberctl/amberctl drill ftp
./amberctl/amberctl status
```

### Init wizard (premade vs own Docker)

| Invocation | Behavior |
| --- | --- |
| `init --yes` / `AMBER_INIT_NONINTERACTIVE=1` / non-TTY | Evidence dirs only (no prompts) |
| `init` on a TTY | Evidence dirs, then textual provider wizard |
| `init --wizard` | Force wizard (needs stdin; works with piped answers) |
| `init --wizard --cells ftp,smtp` | Limit wizard to named cells |

Wizard writes `AMBER_<SVC>_PROVIDER` and optionally `AMBER_<SVC>_HI_IMAGE` or
`AMBER_<SVC>_PROVIDER_CONTEXT` into repo-root `.env` (see
[`docs/providers.md`](docs/providers.md)).

**Own Docker precedence:** `HI_IMAGE` > `PROVIDER_CONTEXT` > builtin
`services/<svc>/providers/<name>/`. When `HI_IMAGE` is set, `amberctl up`
skips the hi image build (still builds collector + dns-sinkhole).

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

## amberctl surface

`init [--yes|--wizard] [--cells …]` · `up` · `down` · `status [--drift]` · `logs` · `export` · `publish` · `drill` · `replay [--diff]` · `reset` · `rebuild` · `ai decisions|approve|review` · `critic` · `liveness` · `execute-decision`

Providers: premade `AMBER_<SVC>_PROVIDER` (see [`docs/providers.md`](docs/providers.md)) or own Docker via `AMBER_<SVC>_HI_IMAGE` / `AMBER_<SVC>_PROVIDER_CONTEXT`.

## Support matrix

| Host | Status |
| --- | --- |
| Ubuntu 22.04 LTS | Supported (production) |
| Debian 12 | Supported (production) |

Requires Docker 24+ and Compose v2. Production: [`ops/RUNBOOK.md`](ops/RUNBOOK.md) (nftables, AppArmor, sysctl, dead drop, webhooks).

## Docs

- [`CHANGELOG.md`](CHANGELOG.md) — shipped changes and release-facing deltas
- [`plan.md`](plan.md) — local planning detail and tracked todos
- [`docs/DESIGN.md`](docs/DESIGN.md) — architecture
- [`docs/providers.md`](docs/providers.md) — provider_contract.v1 + own Docker
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — adversary model
- [`docs/RUNBOOK.md`](docs/RUNBOOK.md) — operator guide
- [`docs/DEADDROP.md`](docs/DEADDROP.md) — dead drop (publish/consume) + sensor deployment for remote launchers
- [`ops/RUNBOOK.md`](ops/RUNBOOK.md) — production host ops
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting
- [`LICENSE`](LICENSE) / [`COMMERCIAL.md`](COMMERCIAL.md) — Public Source License + OEM
- [`docs/schemas/`](docs/schemas/) — JSON Schema drafts + examples

## License

AmberCell project code is under the [AmberCell Public Source License](LICENSE)
(source-available; not OSI open source). Third-party image licenses: see
[`NOTICE`](NOTICE). Commercial / OEM licensing: see [`COMMERCIAL.md`](COMMERCIAL.md).
