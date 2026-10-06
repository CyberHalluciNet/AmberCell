FROM postgres:16-alpine

COPY postgresql.conf /etc/postgresql/postgresql.conf
COPY init/ /docker-entrypoint-initdb.d/
COPY entrypoint-wrap.sh /entrypoint-wrap.sh
RUN chmod 755 /entrypoint-wrap.sh

ENTRYPOINT ["/entrypoint-wrap.sh"]
