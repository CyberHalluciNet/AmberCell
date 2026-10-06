# Host nftables (production profile)

On a **production** honeypot host, attacker traffic hits the public NIC and is **DNAT**’d into `ambernet` (see [`docs/DESIGN.md`](../docs/DESIGN.md)). Compose must **not** publish honeypot ports on this profile; Docker bridge ICC stays off (`enable_icc=false`).

**Lab / Darwin / CI:** skip nftables. Use Compose **`lab`** with the overlay file:

```bash
COMPOSE_PROFILES=lab,core docker compose -f compose.yaml -f compose.lab.yaml up -d
```

Ports bind to `127.0.0.1` only. macOS hosts do not run these nft rules. **Do not claim production kill bars G1–G11 green on Darwin lab.**

## Files

| File | Role |
|------|------|
| [`ingress.nft`](ingress.nft) | Prerouting DNAT: FTP `tcp/21` + PASV `30000-30049` → `172.30.30.10`; Telnet `tcp/23` → `172.30.40.10`; quarantine set `amber_quarantine`; DNS sinkhole DNAT from ambernet → `172.31.10.53` |
| [`egress.nft`](egress.nft) | Forward filter: DNS/80/443 allow; ~2 Mbit/s meter + max ~10 egress streams; metadata/RFC1918/SMTP/IPv6 drops; quarantine-friendly |

Edit placeholders (`WAN_IFACE`, `AMBERNET_IFACE`, cell IPs) before apply. Docker’s ambernet bridge is often `br-<hash>` — set `AMBERNET_IFACE` accordingly (`docker network inspect ambernet`).

## Apply (Linux production)

1. Enable forwarding and rp_filter — [`ops/sysctl.conf`](../ops/sysctl.conf).
2. Edit `WAN_IFACE` / `AMBERNET_IFACE` in `ingress.nft`.
3. Set `AMBER_FTP_PASV_ADDRESS=<PUBLIC_IPV4>` and bring cells up:

   ```bash
   export COMPOSE_PROFILES=production,core
   export AMBER_ENFORCE_CONTAINMENT=1
   export AMBER_FTP_PASV_ADDRESS=<PUBLIC_IPV4>
   sudo -E ./amberctl/amberctl up ftp   # applies nft after up
   # or: sudo ./amberctl/amberctl nft apply
   ```

4. Manual equivalent: `sudo modprobe -r nf_conntrack_ftp`; `sudo nft -f nftables/ingress.nft`; `sudo nft -f nftables/egress.nft`.
5. Verify: `sudo nft list table inet ambercell`
6. Quarantine: `amberctl execute-decision --decision quarantine_then_rebuild --svc <cell>` runs `nft add/delete element` on Linux (post-DNAT filter matches cell IPs). Non-Linux stubs log only.

## Egress shaping (Stage-1)

- **~2 Mbit/s** via nft `meter amber_bw` on tcp/80 and tcp/443 (~250 kB/s).
- **Max ~10 concurrent egress TCP streams** per source via dynamic set + `ct count over 10`.
- Inbound PASV data channels are not counted as egress.

## Related

- DNS sinkhole: [`ops/dns-sinkhole/`](../ops/dns-sinkhole/)
- Containment overlay: [`compose.containment.yaml`](../compose.containment.yaml)
- Kill bars G1–G11: [`plan.md`](../plan.md)
