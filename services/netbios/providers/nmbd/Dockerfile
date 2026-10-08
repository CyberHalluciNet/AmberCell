# AmberCell NetBIOS hi-cell provider: samba nmbd (default)
# Provider id: nmbd — select with AMBER_NETBIOS_PROVIDER=nmbd
FROM debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

RUN apt-get update -qq && apt-get install -y --no-install-recommends samba \
    && rm -rf /var/lib/apt/lists/*

COPY smb.conf /etc/samba/smb.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh && chmod 644 /etc/samba/smb.conf

EXPOSE 137/udp
ENTRYPOINT ["/entrypoint.sh"]
