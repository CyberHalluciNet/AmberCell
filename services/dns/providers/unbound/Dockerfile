# AmberCell DNS hi-cell provider: unbound (alternate)
# Provider id: unbound — select with AMBER_DNS_PROVIDER=unbound
#
# NLnet Labs Unbound from Alpine packages, local-data honeypot mode.
# Digests pinned (index); re-verify in CI on bump.
FROM alpine@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507

RUN apk add --no-cache unbound

COPY unbound.conf /etc/unbound/unbound.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/entrypoint.sh"]
