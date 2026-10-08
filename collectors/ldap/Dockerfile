# AmberCell ldap collector — TCP/389 LDAP ops.
FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/ldap-collector
COPY collectors/ldap/ldap_collector ./ldap_collector

ENV AMBER_LDAP_PROVIDER=openldap
ENV AMBER_LDAP_CELL_IP=172.30.230.10

ENTRYPOINT ["python3", "-m", "ldap_collector.main"]
