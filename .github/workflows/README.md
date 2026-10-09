# Workflows

## Lab CI (Stage-3)

Active workflow: [`ci.yml`](ci.yml)

- Pins GitHub Actions by commit SHA
- Runs on Ubuntu 22.04 with `lab,core` compose config only
- `go test ./...`, schema validation, `amberctl replay --diff`, critic, harden (WORM/YARA), hermetic pcap CI
- Does not open public honeypot ports or pull live malware

## GitHub Pages

Active workflow: [`pages.yml`](pages.yml)

- Deploys the static marketing site from [`site/`](../../site/) (GitHub’s
  branch source only allows `/` or `/docs`, so Pages is driven by Actions)
- Triggers on pushes that touch `site/**` or the workflow file, plus
  `workflow_dispatch`
- Public URL (project Pages): <https://cyberhallucinet.github.io/AmberCell/>
