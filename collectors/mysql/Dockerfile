FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/mysql-collector
COPY collectors/mysql/mysql_collector ./mysql_collector

ENV AMBER_MYSQL_PROVIDER=mariadb
ENV AMBER_MYSQL_CELL_IP=172.30.90.10

ENTRYPOINT ["python3", "-m", "mysql_collector.main"]
