# Lab CI (Stage-3)

Active workflow: [`ci.yml`](ci.yml)

- Pins GitHub Actions by commit SHA
- Runs on Ubuntu 22.04 with `lab,core` compose config only
- `go test ./...`, schema validation, `amberctl replay --diff`, critic, harden (WORM/YARA), hermetic pcap CI
- Does not open public honeypot ports or pull live malware
