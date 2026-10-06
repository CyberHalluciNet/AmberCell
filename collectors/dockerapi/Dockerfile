FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/dockerapi-collector
COPY collectors/dockerapi/dockerapi_collector ./dockerapi_collector

ENV AMBER_DOCKERAPI_PROVIDER=trap
ENV AMBER_DOCKERAPI_CELL_IP=172.30.140.10

ENTRYPOINT ["python3", "-m", "dockerapi_collector.main"]
