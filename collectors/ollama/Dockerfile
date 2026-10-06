FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/ollama-collector
COPY collectors/ollama/ollama_collector ./ollama_collector

ENV AMBER_OLLAMA_PROVIDER=mock
ENV AMBER_OLLAMA_CELL_IP=172.30.160.10

ENTRYPOINT ["python3", "-m", "ollama_collector.main"]
