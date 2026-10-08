# AmberCell imap collector — imap capture JSONL.
FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/imap-collector
COPY collectors/imap/imap_collector ./imap_collector

ENV AMBER_IMAP_PROVIDER=dovecot
ENV AMBER_IMAP_CELL_IP=172.30.240.10

ENTRYPOINT ["python3", "-m", "imap_collector.main"]
