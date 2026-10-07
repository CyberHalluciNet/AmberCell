# AmberCell DNS hi-cell provider: bind9 (alternate)
# Provider id: bind9 — select with AMBER_DNS_PROVIDER=bind9
#
# ISC BIND 9 from Alpine packages. Digests pinned (index); re-verify in CI on bump.
FROM alpine@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507

RUN apk add --no-cache bind \
    && mkdir -p /etc/bind/zones \
    && chown root:named /etc/bind/zones

COPY named.conf /etc/bind/named.conf
COPY zones/ /etc/bind/zones/
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh \
    && chmod 644 /etc/bind/zones/* /etc/bind/named.conf

EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/entrypoint.sh"]
