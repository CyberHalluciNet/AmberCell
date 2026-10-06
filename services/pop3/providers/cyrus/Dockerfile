# AmberCell POP3 hi-cell provider: cyrus (alternate)
# Provider id: cyrus — select with AMBER_POP3_PROVIDER=cyrus
FROM debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         cyrus-imapd \
         cyrus-pop3d \
         cyrus-admin \
         sasl2-bin \
         expect \
         python3 \
         ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/cyrus/socket /run/cyrus/proc /run/cyrus/lock \
         /var/lib/cyrus /var/spool/cyrus/mail \
    && chown -R cyrus:mail /run/cyrus /var/lib/cyrus /var/spool/cyrus

COPY imapd.conf /etc/imapd.conf
COPY cyrus.conf /etc/cyrus.conf
COPY seed_lmtp.py /usr/local/bin/seed_lmtp.py
COPY entrypoint.sh /entrypoint.sh
COPY seeds/ /opt/amber-seeds/
RUN chmod 755 /entrypoint.sh /usr/local/bin/seed_lmtp.py

EXPOSE 110/tcp
ENTRYPOINT ["/entrypoint.sh"]
