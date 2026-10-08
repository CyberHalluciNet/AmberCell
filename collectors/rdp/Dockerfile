# AmberCell rdp collector — rdp capture JSONL.
FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/rdp-collector
COPY collectors/rdp/rdp_collector ./rdp_collector

ENV AMBER_RDP_PROVIDER=xrdp
ENV AMBER_RDP_CELL_IP=172.30.251.10

ENTRYPOINT ["python3", "-m", "rdp_collector.main"]
