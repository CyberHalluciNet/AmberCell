# HTTP provider: nginx (default)

**Protocol cell:** `http`  
**Provider id:** `nginx`  
**Select:** `AMBER_HTTP_PROVIDER=nginx`

## Contract

- Real HTTP on tcp/80 (443 reserved; lab publishes 80 only by default).
- Seeded portal + trap paths (`/wp-login.php`, `/phpmyadmin/`).
- Collector parses nginx access logs via FIFO → `http.request`, `http.post`, `http.trap_probe`.
- Ingress DNAT 80/443 (production) is **not** the same as cell **egress** allowlist to the internet.

## Alternate providers

See `services/http/providers/caddy/README.md` (stub slot).

Stage-6 Wave B — `compose.yaml` profile `wave-b`, collector `collectors/http/`.
