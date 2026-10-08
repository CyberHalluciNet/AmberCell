# AmberCell TFTP hi-cell provider: dnsmasq (tftp server mode)
# Provider id: dnsmasq — select with AMBER_TFTP_PROVIDER=dnsmasq
FROM alpine@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507

RUN apk add --no-cache dnsmasq \
    && mkdir -p /var/lib/tftpboot/seed \
    && printf 'AmberCell TFTP seed.\n' > /var/lib/tftpboot/seed/README.txt \
    && printf 'stage-9 sample config.\n' > /var/lib/tftpboot/seed/config.txt \
    && chmod -R a+rX /var/lib/tftpboot

COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 69/udp
ENTRYPOINT ["/entrypoint.sh"]
