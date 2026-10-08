# AmberCell TFTP hi-cell provider: atftpd (alternate)
# Provider id: atftpd — select with AMBER_TFTP_PROVIDER=atftpd
FROM debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

RUN apt-get update -qq && apt-get install -y --no-install-recommends atftpd \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/tftpboot-seed \
    && printf 'AmberCell TFTP seed (atftpd).\n' > /var/lib/tftpboot-seed/README.txt

COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 69/udp
ENTRYPOINT ["/entrypoint.sh"]
