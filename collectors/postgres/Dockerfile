FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/postgres-collector
COPY collectors/postgres/postgres_collector ./postgres_collector

ENV AMBER_POSTGRES_PROVIDER=postgresql
ENV AMBER_POSTGRES_CELL_IP=172.30.100.10

ENTRYPOINT ["python3", "-m", "postgres_collector.main"]
