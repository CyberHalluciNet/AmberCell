# AmberCell Redis hi-cell — default redis-server provider
# Provider id: redis-server — select with AMBER_REDIS_PROVIDER=redis-server
FROM redis:7.4-alpine

COPY redis.conf /usr/local/etc/redis/redis.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 6379/tcp
ENTRYPOINT ["/entrypoint.sh"]
