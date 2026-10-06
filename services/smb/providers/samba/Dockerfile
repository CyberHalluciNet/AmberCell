FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends samba \
  && rm -rf /var/lib/apt/lists/*

COPY smb.conf /etc/samba/smb.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh && mkdir -p /shares/public /shares/admin /var/log/samba

EXPOSE 445/tcp
ENTRYPOINT ["/entrypoint.sh"]
