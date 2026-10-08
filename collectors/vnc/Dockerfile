# AmberCell vnc collector — vnc capture JSONL.
FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/vnc-collector
COPY collectors/vnc/vnc_collector ./vnc_collector

ENV AMBER_VNC_PROVIDER=tigervnc
ENV AMBER_VNC_CELL_IP=172.30.252.10

ENTRYPOINT ["python3", "-m", "vnc_collector.main"]
