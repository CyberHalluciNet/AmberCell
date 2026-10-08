# AmberCell SIP hi-cell provider: opensips (alternate)
# Provider id: opensips — select with AMBER_SIP_PROVIDER=opensips
FROM opensips/opensips:3.3-lts

COPY opensips.cfg /etc/opensips/opensips.cfg
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 5060/udp 5060/tcp
ENTRYPOINT ["/entrypoint.sh"]
