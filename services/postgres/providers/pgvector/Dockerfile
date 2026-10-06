# AmberCell Postgres hi-cell — pgvector
# Provider id: pgvector — AMBER_POSTGRES_PROVIDER=pgvector
FROM pgvector/pgvector:pg16

COPY postgresql.conf /etc/postgresql/postgresql.conf
COPY init/ /docker-entrypoint-initdb.d/
COPY entrypoint-wrap.sh /entrypoint-wrap.sh
RUN chmod 755 /entrypoint-wrap.sh

ENTRYPOINT ["/entrypoint-wrap.sh"]
EXPOSE 5432/tcp
