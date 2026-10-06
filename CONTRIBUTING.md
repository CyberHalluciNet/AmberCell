# Contributing

Thank you for helping improve AmberCell. This is a defensive research project; keep PRs focused on containment, evidence integrity, and operator safety.

## License

Contributions are under the [AmberCell Public Source License](LICENSE). By
opening a pull request you assign contribution rights as described in
Section 4 of that license (including relicensing under commercial terms the
Licensor offers), unless agreed otherwise in writing before merge.

## Pull requests

1. Open a PR against the default branch. Keep changes small and stage-aligned (`plan.md`).
2. CI on the `lab` profile must pass before merge.
3. Containment diffs (nftables, seccomp, AppArmor, publisher, `amberctl` executor) need maintainer review.

## Go

- Format with `gofmt` (or `go fmt ./...`) before commit.
- Commit `go.sum` with module changes.
- Add or update tests for behavior changes.

## Schemas and goldens

- Every JSONL record carries `schema_version`. Schemas live under `docs/schemas/`.
- A schema change **must** bump the relevant version and update matching golden replay output in the **same** change.
- Do not mix incompatible schema major versions in one export bundle without an explicit flag.

## Docs

- If ports, cells, providers, or kill bars change, update `docs/DESIGN.md` and the relevant RUNBOOK in the same PR.
- Compose profiles (`core`, `wave-*`) must stay consistent with the service catalog.

## What not to land

- Exploit payloads, third-party credential-stuffing wordlists, or offensive frameworks.
- Live credentials or production secrets in examples (use `.env.example` with empty values).
- Public discussion of unpatched containment bugs (see `SECURITY.md`).

## Code of conduct

Participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
