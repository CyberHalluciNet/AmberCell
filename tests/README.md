# Tests

## Stage-0B

```bash
# Lab FTP proof (Docker Desktop / Linux with Compose)
AMBER_FTP_HOST_PORT=2121 ./tests/test_smoke_ftp.sh
```

Checks: LISTEN, PASV with advertised address, Active Mode reject, raw-flow + event JSONL, pcap ring, sample AI decision, `amberctl` FSM reject.

## Replay

- Stage-3 CI: `./test_stage3_ci.sh` (schema + replay + critic + harden + pcap CI + go test)
- Golden replay: [`replay/`](replay/)
- Hermetic pcap: [`pcap_ci/`](pcap_ci/) (`./pcap_ci/run_pcap_ci.sh`)
- Isolation (Linux): `./test_isolation_linux.sh` with `AMBER_RUN_ISOLATION=1`
