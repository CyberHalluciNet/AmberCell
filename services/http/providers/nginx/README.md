# HTTP provider: nginx (default)

**Protocol cell:** `http`  
**Provider id:** `nginx`  
**Select:** `AMBER_HTTP_PROVIDER=nginx`

## Contract

- Real HTTP on tcp/80 (443 reserved; lab publishes 80 only by default).
- Seeded portal + trap paths (`/wp-login.php`, `/phpmyadmin/`).
- Collector parses access logs via FIFO → `http.request`, `http.post`, `http.trap_probe`.

## Alternates

| Provider | Notes |
| --- | --- |
| `httpd` | Apache httpd |
| `caddy` | Caddy |

Stage-6 Wave B — `compose.yaml` profile `wave-b`.
