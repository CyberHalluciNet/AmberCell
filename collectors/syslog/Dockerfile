# AmberCell syslog collector — TCP+UDP/514 syslog messages.
FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/syslog-collector
COPY collectors/syslog/syslog_collector ./syslog_collector

ENV AMBER_SYSLOG_PROVIDER=rsyslog
ENV AMBER_SYSLOG_CELL_IP=172.30.210.10

ENTRYPOINT ["python3", "-m", "syslog_collector.main"]
