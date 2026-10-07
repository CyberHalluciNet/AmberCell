# AmberCell DNS collector — udp/tcp 53 query/AXFR/CHAOS JSONL.
FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/dns-collector
COPY collectors/dns/dns_collector ./dns_collector

ENV AMBER_DNS_PROVIDER=coredns
ENV AMBER_DNS_CELL_IP=172.30.170.10

ENTRYPOINT ["python3", "-m", "dns_collector.main"]
