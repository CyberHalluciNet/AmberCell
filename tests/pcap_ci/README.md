# Hermetic pcap CI (Stage-3 harden)

Validates **fixture → expected JSONL + hashes** without Docker, netns, or malware.
This is the CI-authoritative path. Live `tcpreplay` into a throwaway collector is
optional on Linux runners that install the package.

## Run (CI / laptop)

```bash
./tests/pcap_ci/run_pcap_ci.sh
# or
python3 tests/pcap_ci/run_pcap_ci.py
```

Wired from `./tests/test_stage3_ci.sh`.

## What it asserts

1. SHA-256 of committed fixtures match `expected/hashes.expected.json`.
2. Minimal classic-pcap parse of `fixtures/ftp_pasv_syn.pcap` yields the FTP-control
   5-tuple in `expected/flows.expected.jsonl` (`parser_status=unknown` SYN-only).
3. `rawflow.v1` + `artifact.v1` schema validation for the expected records / hash path
   via `ambercell.artifact_queue.sha256_file`.
4. `enrichment.v1` expected record cites the flow `session_id` / fixture path (refs only).

## Fixtures

| File | Role |
| --- | --- |
| `fixtures/ftp_pasv_syn.pcap` | Synthetic Ethernet/IPv4/TCP SYN → `172.30.30.10:21` |
| `fixtures/upload_sample.bin` | Benign upload bytes for artifact digest path |

Regenerate the pcap (stdlib only — no scapy):

```bash
python3 tests/pcap_ci/synthesize_pcap.py
# then refresh expected hashes if bytes changed
```

## Optional tcpreplay

| Env | Behavior |
| --- | --- |
| (default) | If `tcpreplay` missing, print a note and still pass hermetic asserts |
| `AMBER_PCAP_TCPREPLAY=1` | Fail when `tcpreplay` is not on `PATH` (opt-in Linux gate) |

Live replay into a collector netns remains an operator/lab drill — not required for
Stage-3 lab CI green. Never publish honeypot ports on the public internet in CI
(`lab` profile only).
