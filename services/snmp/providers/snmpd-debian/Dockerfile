# AmberCell SNMP hi-cell provider: snmpd-debian (net-snmp debian)
# Provider id: snmpd-debian — select with AMBER_SNMP_PROVIDER=snmpd-debian
FROM debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

RUN apt-get update -qq && apt-get install -y --no-install-recommends snmpd && rm -rf /var/lib/apt/lists/*

COPY snmpd.conf /etc/snmp/snmpd.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh && chmod 644 /etc/snmp/snmpd.conf

EXPOSE 161/udp 161/tcp
ENTRYPOINT ["/entrypoint.sh"]
