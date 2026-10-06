FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/ssh-collector

COPY collectors/ssh/ssh_collector ./ssh_collector

ENV AMBER_SSH_PROVIDER=openssh
ENV AMBER_SSH_CELL_IP=172.30.50.10
ENV AMBER_SSH_CELL_ID=ssh-cell-01
ENV AMBER_SSH_COLLECTOR_ID=ssh-collector-a

ENTRYPOINT ["python3", "-m", "ssh_collector.main"]
