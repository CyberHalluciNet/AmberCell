# FTP provider stub: proftpd (alternate)

**Provider id:** `proftpd`  
**Select:** `AMBER_FTP_PROVIDER=proftpd`

Empty alternate slot proving pluggability. Drop in `Dockerfile`, config with
**Active Mode off**, PASV `30000-30049`, and the same seed/upload layout as
[`../vsftpd/`](../vsftpd/). Collector, nftables ports, and event field names stay
unchanged; record `provider_id=proftpd` in cell state.

Not implemented in core Submit (Stages 0–4) — default remains `vsftpd`.
