# AmberCell SIP hi-cell provider: kamailio (default)
# Provider id: kamailio — select with AMBER_SIP_PROVIDER=kamailio
FROM debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

RUN apt-get update -qq && apt-get install -y --no-install-recommends kamailio \
    && rm -rf /var/lib/apt/lists/*

COPY kamailio.cfg /etc/kamailio/kamailio.cfg
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh && chmod 644 /etc/kamailio/kamailio.cfg

EXPOSE 5060/udp 5060/tcp
ENTRYPOINT ["/entrypoint.sh"]
