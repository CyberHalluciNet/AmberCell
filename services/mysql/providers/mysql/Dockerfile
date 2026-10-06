# AmberCell MySQL hi-cell — Oracle MySQL
# Provider id: mysql — AMBER_MYSQL_PROVIDER=mysql
FROM mysql:8.0

COPY my.cnf /etc/mysql/conf.d/ambercell.cnf
COPY init/ /docker-entrypoint-initdb.d/
COPY entrypoint-wrap.sh /entrypoint-wrap.sh
RUN chmod 755 /entrypoint-wrap.sh

ENTRYPOINT ["/entrypoint-wrap.sh"]
EXPOSE 3306/tcp
