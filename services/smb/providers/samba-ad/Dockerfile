# AmberCell SMB hi-cell — Samba AD DC lab lure
# Provider id: samba-ad — AMBER_SMB_PROVIDER=samba-ad
# Honest label: real samba-ad-dc provision in-container; not a production AD.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      samba samba-dsdb-modules samba-vfs-modules winbind libnss-winbind \
      openssl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh \
  && mkdir -p /var/lib/samba /var/log/samba /shares/sysvol /shares/netlogon

EXPOSE 445/tcp
ENTRYPOINT ["/entrypoint.sh"]
