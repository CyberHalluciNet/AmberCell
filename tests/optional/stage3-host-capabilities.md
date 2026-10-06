# Stage-3 optional host capabilities

These items improve containment/telemetry but are **not** required for lab CI green,
Darwin development, or checking Submit item **`3-harden`**.

Mandatory Stage-3 harden (WORM vault, async YARA stub path, scoped core pipe docs,
hermetic pcap CI) is tracked separately and does **not** depend on the rows below.

| Capability | Status | Notes |
| --- | --- | --- |
| gVisor telnet/ssh | docs only | Prefer runsc runtime in compose overlay; runc fallback documented in DESIGN / RUNBOOK |
| Tetragon eBPF | docs only | Additive host telemetry; never replaces collector-owned evidence |
| TLS ClientHello / JA3 observe | docs only | Collector netns parse only — no inline TLS proxy; enable later behind a flag |
| Egress anomaly EWMA | docs only | `AMBER_EGRESS_EWMA=1` reserved; additive alert signal only when implemented |

Production operators enable per [`ops/RUNBOOK.md`](../../ops/RUNBOOK.md) when the host
supports them. Cosign verify on rebuild is a separate Stage-3 hook
(`AMBER_COSIGN_ENFORCE=1`) and is not gated on this optional list.
