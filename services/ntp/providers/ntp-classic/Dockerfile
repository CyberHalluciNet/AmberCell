# AmberCell NTP hi-cell provider: ntp.org classic ntpd (alternate)
# Provider id: ntp-classic — select with AMBER_NTP_PROVIDER=ntp-classic
FROM debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

RUN apt-get update -qq && apt-get install -y --no-install-recommends ntp \
    && rm -rf /var/lib/apt/lists/*

COPY ntp.conf /etc/ntp.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 123/udp
ENTRYPOINT ["/entrypoint.sh"]
