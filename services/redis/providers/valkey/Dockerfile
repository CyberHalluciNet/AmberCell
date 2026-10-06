# AmberCell Redis hi-cell — Valkey (BSD, Redis-compatible)
# Provider id: valkey — AMBER_REDIS_PROVIDER=valkey
FROM valkey/valkey:8.0-alpine

COPY valkey.conf /usr/local/etc/valkey/valkey.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 6379/tcp
ENTRYPOINT ["/entrypoint.sh"]
