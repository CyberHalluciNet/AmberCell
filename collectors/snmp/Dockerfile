# AmberCell snmp collector — UDP+TCP/161 SNMP get/set decode.
FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/snmp-collector
COPY collectors/snmp/snmp_collector ./snmp_collector

ENV AMBER_SNMP_PROVIDER=snmpd
ENV AMBER_SNMP_CELL_IP=172.30.190.10

ENTRYPOINT ["python3", "-m", "snmp_collector.main"]
