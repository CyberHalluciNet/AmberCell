FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/elastic-collector
COPY collectors/elastic/elastic_collector ./elastic_collector

ENV AMBER_ELASTIC_PROVIDER=elasticsearch
ENV AMBER_ELASTIC_CELL_IP=172.30.130.10

ENTRYPOINT ["python3", "-m", "elastic_collector.main"]
