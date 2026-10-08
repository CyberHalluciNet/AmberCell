# AmberCell ntp collector — UDP/123 NTP packets.
FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/ntp-collector
COPY collectors/ntp/ntp_collector ./ntp_collector

ENV AMBER_NTP_PROVIDER=chrony
ENV AMBER_NTP_CELL_IP=172.30.200.10

ENTRYPOINT ["python3", "-m", "ntp_collector.main"]
