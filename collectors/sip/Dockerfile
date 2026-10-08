# AmberCell sip collector — TCP+UDP/5060 SIP requests/responses.
FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/sip-collector
COPY collectors/sip/sip_collector ./sip_collector

ENV AMBER_SIP_PROVIDER=kamailio
ENV AMBER_SIP_CELL_IP=172.30.220.10

ENTRYPOINT ["python3", "-m", "sip_collector.main"]
