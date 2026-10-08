# AmberCell SNMP hi-cell provider: snmpd (net-snmp alpine)
# Provider id: snmpd — select with AMBER_SNMP_PROVIDER=snmpd
FROM alpine@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507

RUN apk add --no-cache net-snmp

COPY snmpd.conf /etc/snmp/snmpd.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh && chmod 644 /etc/snmp/snmpd.conf

EXPOSE 161/udp 161/tcp
ENTRYPOINT ["/entrypoint.sh"]
