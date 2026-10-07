# AmberCell DNS hi-cell provider: coredns (default)
# Provider id: coredns — select with AMBER_DNS_PROVIDER=coredns
#
# Multi-stage: official CoreDNS binary into a pinned Alpine runtime so the
# entrypoint can tee logs into the collector FIFO. Digests pinned (index);
# re-verify in CI on bump.
FROM alpine@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507
COPY --from=coredns/coredns@sha256:af8c8d35a5d184b386c4a6d1a012c8b218d40d1376474c7d071bb6c07201f47d /coredns /usr/local/bin/coredns

COPY Corefile /etc/coredns/Corefile
COPY zones/ /etc/coredns/zones/
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/entrypoint.sh"]
