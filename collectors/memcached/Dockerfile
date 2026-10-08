# AmberCell memcached collector — memcached capture JSONL.
FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/memcached-collector
COPY collectors/memcached/memcached_collector ./memcached_collector

ENV AMBER_MEMCACHED_PROVIDER=memcached
ENV AMBER_MEMCACHED_CELL_IP=172.30.250.10

ENTRYPOINT ["python3", "-m", "memcached_collector.main"]
