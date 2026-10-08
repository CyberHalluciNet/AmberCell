# AmberCell netbios collector — netbios capture JSONL.
FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/netbios-collector
COPY collectors/netbios/netbios_collector ./netbios_collector

ENV AMBER_NETBIOS_PROVIDER=nmbd
ENV AMBER_NETBIOS_CELL_IP=172.30.253.10

ENTRYPOINT ["python3", "-m", "netbios_collector.main"]
