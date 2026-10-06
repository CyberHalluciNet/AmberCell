FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/smtp-collector

COPY collectors/smtp/smtp_collector ./smtp_collector

ENV AMBER_SMTP_PROVIDER=postfix
ENV AMBER_SMTP_CELL_IP=172.30.10.10
ENV AMBER_SMTP_CELL_ID=smtp-cell-01
ENV AMBER_SMTP_COLLECTOR_ID=smtp-collector-a
ENV AMBER_SMTP_LOG_FIFO=/run/amber/log/smtp.fifo

ENTRYPOINT ["python3", "-m", "smtp_collector.main"]
