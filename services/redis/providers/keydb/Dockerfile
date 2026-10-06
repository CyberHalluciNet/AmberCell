# AmberCell Redis hi-cell — KeyDB (BSD)
# Provider id: keydb — AMBER_REDIS_PROVIDER=keydb
FROM eqalpha/keydb:alpine

COPY keydb.conf /etc/keydb/keydb.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 6379/tcp
ENTRYPOINT ["/entrypoint.sh"]
