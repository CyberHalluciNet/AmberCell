FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/pop3-collector

COPY collectors/pop3/pop3_collector ./pop3_collector

ENV AMBER_POP3_PROVIDER=dovecot
ENV AMBER_POP3_CELL_IP=172.30.20.10
ENV AMBER_POP3_CELL_ID=pop3-cell-01
ENV AMBER_POP3_COLLECTOR_ID=pop3-collector-a
ENV AMBER_POP3_LOG_FIFO=/run/amber/log/pop3.fifo

ENTRYPOINT ["python3", "-m", "pop3_collector.main"]
