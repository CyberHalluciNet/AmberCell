# DNS sinkhole (Stage-1)

Minimal **dnsmasq** image for the control plane on `ambermgmt`. Cells must not route to this subnet; production hosts **DNAT** cell `udp/53` to `172.31.10.53` so cells **cannot use external udp/53** (see [`nftables/ingress.nft`](../../nftables/ingress.nft), [`docs/DESIGN.md`](../../docs/DESIGN.md)).

- Queries are logged to stdout (`--log-queries`).
- Default config returns **NXDOMAIN** for all names.
- Compose service `dns-sinkhole` uses profile `core`, network `ambermgmt` only (no `ambernet`).
- `amberctl up ftp|telnet` also starts `dns-sinkhole` when profiles include `core`.

Build locally:

```bash
docker build -t ambercell-dns-sinkhole:local ops/dns-sinkhole
```

**Lab / Darwin:** container may run for config smoke; host DNAT is not applied — do not claim G1 green on lab.
