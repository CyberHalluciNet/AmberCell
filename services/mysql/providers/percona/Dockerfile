# AmberCell MySQL hi-cell — Percona Server
# Provider id: percona — AMBER_MYSQL_PROVIDER=percona
FROM percona/percona-server:8.0

USER root
COPY my.cnf /etc/my.cnf.d/ambercell.cnf
COPY init/ /docker-entrypoint-initdb.d/
COPY entrypoint-wrap.sh /entrypoint-wrap.sh
RUN chmod 755 /entrypoint-wrap.sh

ENTRYPOINT ["/entrypoint-wrap.sh"]
EXPOSE 3306/tcp
