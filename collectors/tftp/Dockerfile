# AmberCell tftp collector — UDP/69 TFTP transfer decode.
FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/tftp-collector
COPY collectors/tftp/tftp_collector ./tftp_collector

ENV AMBER_TFTP_PROVIDER=default
ENV AMBER_TFTP_CELL_IP=172.30.180.10

ENTRYPOINT ["python3", "-m", "tftp_collector.main"]
