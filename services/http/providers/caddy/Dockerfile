# AmberCell HTTP hi-cell — Caddy
# Provider id: caddy — AMBER_HTTP_PROVIDER=caddy
FROM caddy:2.8-alpine

RUN mkdir -p /var/www/uploads
COPY Caddyfile /etc/caddy/Caddyfile
COPY html/ /usr/share/caddy/
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 80/tcp 443/tcp
ENTRYPOINT ["/entrypoint.sh"]
