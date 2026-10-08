# AmberCell TFTP hi-cell provider: tftpd-hpa (default)
# Provider id: tftpd-hpa — select with AMBER_TFTP_PROVIDER=tftpd-hpa
FROM alpine@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507

RUN apk add --no-cache tftp-hpa \
    && mkdir -p /var/lib/tftpboot-seed /srv/tftp \
    && printf 'AmberCell TFTP seed.\n' > /var/lib/tftpboot-seed/README.txt \
    && printf 'stage-9 sample config.\n' > /var/lib/tftpboot-seed/config.txt \
    && chmod -R a+rX /var/lib/tftpboot-seed

COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 69/udp
ENTRYPOINT ["/entrypoint.sh"]
