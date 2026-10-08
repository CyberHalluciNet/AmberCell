# AmberCell memcached hi-cell provider: memcached (default)
# Provider id: memcached — select with AMBER_MEMCACHED_PROVIDER=memcached
#
# Amplification note (G13 family): the cell answers udp/11211 reflection
# probes with empty/small NOT_FOUND responses only — no data is ever loaded,
# so the amplification factor stays ~1. tcp+udp both enabled.
FROM memcached@sha256:9e4de012dc607573052061c0bcb38abc775e1dd59b24e7ac38d1892842094aaf

# The official image runs as uid 11211 (memcache); build steps need root.
USER root

COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

# Runtime stays root so the FIFO volume is writable; memcached itself drops
# privileges via `-u memcache` after binding (SETUID is in the cell cap set).

EXPOSE 11211/tcp 11211/udp
ENTRYPOINT ["/entrypoint.sh"]
