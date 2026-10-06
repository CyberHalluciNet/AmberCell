FROM mariadb:11.4

COPY my.cnf /etc/mysql/conf.d/ambercell.cnf
COPY init/ /docker-entrypoint-initdb.d/
COPY entrypoint-wrap.sh /entrypoint-wrap.sh
RUN chmod 755 /entrypoint-wrap.sh

ENTRYPOINT ["/entrypoint-wrap.sh"]
