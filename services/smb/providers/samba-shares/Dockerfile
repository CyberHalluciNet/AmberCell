# AmberCell SMB hi-cell — multi-share Samba layout
# Provider id: samba-shares — AMBER_SMB_PROVIDER=samba-shares
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends samba \
  && rm -rf /var/lib/apt/lists/*

COPY smb.conf /etc/samba/smb.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh \
  && mkdir -p /shares/public /shares/finance /shares/hr /shares/admin /shares/backup /var/log/samba

EXPOSE 445/tcp
ENTRYPOINT ["/entrypoint.sh"]
