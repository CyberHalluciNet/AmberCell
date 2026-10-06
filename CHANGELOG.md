# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for **application / `amberctl` releases**.

Evidence and API payload versions use a separate `schema_version` field
(e.g. `rawflow.v1`, `event.v1`). Schema majors are independent of app semver;
bumping a schema does not imply an app major bump, and vice versa.

## [Unreleased]

### Added

- Stage-0A scaffold: project OSS files, JSON Schema drafts + examples,
  ops/sysctl and daemon stubs, compose networks, provider contract directories.
- Stage-0B–4 core cells: FTP, Telnet, SMTP, POP3 with collector + hi pair,
  JSONL/pcap evidence, lab Compose published ports, production nftables path.
- Wave A–E cells (SSH, Redis, MQTT, HTTP, MySQL, Postgres, SMB, Mongo,
  Elastic, Docker API / kubelet / Ollama traps) behind compose profiles.
- `amberctl` operator CLI: `init`, `up`/`down`, `status`, `logs`, `export`,
  `publish`, `drill`, `replay`, `reset`/`rebuild`, `liveness`,
  `execute-decision`, `ai`, `critic`, `nft`.
- Bounded AI manager path: deterministic `sample_decision`, critic,
  policy stubs, review queue, webhook/campaign helpers (no cloud LLM required).
- Lab remote expose: `AMBER_LAB_BIND` (default `127.0.0.1`; `0.0.0.0` for Spot)
  and optional `AMBER_LAB_EXPOSE=1` overlay marker.
- Containment overlay (`compose.containment.yaml`), AppArmor/seccomp stubs,
  dns-sinkhole on `ambermgmt`, dead-drop publish layout.
- CI/smoke: Stage-3/4 scripts, replay goldens, hermetic pcap CI, production
  kill-bar verify (Linux; Darwin SKIP).

### Changed

- Relicensed project code from MIT to the AmberCell Public Source License
  v1.0 (source-available; see `LICENSE`, `NOTICE`, `COMMERCIAL.md`).
- dns-sinkhole gains `SETUID`/`SETGID` so dnsmasq can drop privileges under
  `cap_drop: ALL`.
- Lab SMTP/POP3/SSH publish address is configurable via `AMBER_LAB_BIND`
  (Compose port lists are not replaced by overlays).

### Fixed

- Production wiring: post-DNAT quarantine against cell IPs, real nft quarantine
  on Linux, PASV address not defaulting to `127.0.0.1` in base compose,
  production liveness probes cell IPs, `amberctl nft apply` after production up.

### Notes

- `plan.md` and `docs/DESIGN.md` are local-only (gitignored); not shipped in
  the remote tree.
- Darwin/lab path does not satisfy production kill bars G1–G11.
