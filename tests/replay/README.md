# Golden replay corpus (Stage-3)

Synthetic sessions for CI — no live malware or third-party targets.

| Path | Purpose |
| --- | --- |
| `ftp/recognized/events.golden.jsonl` | Auth + PASV events with `seq_id` + ns `ts` |
| `ftp/unknown/flows.golden.jsonl` | Unknown traffic still emits raw flow |
| `telnet/recognized/` | Telnet auth event golden |
| `smtp/recognized/` | SMTP EHLO golden |
| `pop3/recognized/` | POP3 RETR golden |
| `decisions/ftp-alert.golden.jsonl` | Decision with `policy_refs` + `decision_version` |

## CI

```bash
./tests/test_stage3_ci.sh
amberctl replay --diff --actual tests/replay/ftp/recognized/events.golden.jsonl tests/replay/ftp/recognized/events.golden.jsonl
```

Diff sorts and compares by **`seq_id`** (volatile `ts` / ids ignored). Decision replays emit
consistency metrics tagged by `policy_refs` and `decision_version`.
