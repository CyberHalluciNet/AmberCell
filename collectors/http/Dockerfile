FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/http-collector
COPY collectors/http/http_collector ./http_collector

ENV AMBER_HTTP_PROVIDER=nginx
ENV AMBER_HTTP_CELL_IP=172.30.80.10

ENTRYPOINT ["python3", "-m", "http_collector.main"]
