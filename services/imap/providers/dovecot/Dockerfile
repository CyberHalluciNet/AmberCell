# AmberCell IMAP hi-cell provider: dovecot (default)
# Provider id: dovecot — select with AMBER_IMAP_PROVIDER=dovecot
FROM debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

RUN apt-get update -qq && apt-get install -y --no-install-recommends dovecot-core dovecot-imapd \
    && rm -rf /var/lib/apt/lists/*

COPY dovecot.conf /etc/dovecot/dovecot.conf
COPY users /etc/dovecot/users
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh && chmod 644 /etc/dovecot/users && chmod 640 /etc/dovecot/dovecot.conf && chown root:dovecot /etc/dovecot/users /etc/dovecot/dovecot.conf

EXPOSE 143/tcp
ENTRYPOINT ["/entrypoint.sh"]
