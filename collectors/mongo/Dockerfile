FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/mongo-collector
COPY collectors/mongo/mongo_collector ./mongo_collector

ENV AMBER_MONGO_PROVIDER=mongodb
ENV AMBER_MONGO_CELL_IP=172.30.120.10

ENTRYPOINT ["python3", "-m", "mongo_collector.main"]
