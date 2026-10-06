FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/telnet-collector

COPY collectors/telnet/telnet_collector ./telnet_collector

ENV AMBER_TELNET_PROVIDER=busybox-telnetd
ENV AMBER_TELNET_CELL_IP=172.30.40.10
ENV AMBER_TELNET_CELL_ID=telnet-cell-01
ENV AMBER_TELNET_COLLECTOR_ID=telnet-collector-a

ENTRYPOINT ["python3", "-m", "telnet_collector.main"]
