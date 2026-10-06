FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/redis-collector
COPY collectors/redis/redis_collector ./redis_collector

ENV AMBER_REDIS_PROVIDER=redis-server
ENV AMBER_REDIS_CELL_IP=172.30.60.10

ENTRYPOINT ["python3", "-m", "redis_collector.main"]
