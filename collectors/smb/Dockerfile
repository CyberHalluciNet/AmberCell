FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/smb-collector
COPY collectors/smb/smb_collector ./smb_collector

ENV AMBER_SMB_PROVIDER=samba
ENV AMBER_SMB_CELL_IP=172.30.110.10

ENTRYPOINT ["python3", "-m", "smb_collector.main"]
