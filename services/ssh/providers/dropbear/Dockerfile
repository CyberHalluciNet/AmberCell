# AmberCell SSH hi-cell provider: dropbear
# Provider id: dropbear — AMBER_SSH_PROVIDER=dropbear
FROM alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache dropbear dropbear-dbclient busybox-extras \
    && mkdir -p /etc/dropbear /jail/home /jail/tmp /mnt/uploads /home/admin /home/support /home/lure \
    && dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key \
    && dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key \
    && adduser -D -h /home/admin -s /usr/local/bin/amber-shell.sh admin \
    && adduser -D -h /home/support -s /usr/local/bin/amber-shell.sh support \
    && adduser -D -h /home/lure -s /usr/local/bin/amber-shell.sh lure \
    && echo 'admin:admin123' | chpasswd \
    && echo 'support:support' | chpasswd \
    && echo 'lure:lure' | chpasswd \
    && chown -R admin:admin /home/admin /mnt/uploads \
    && chmod 755 /mnt/uploads

COPY amber-shell.sh /usr/local/bin/amber-shell.sh
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /usr/local/bin/amber-shell.sh /entrypoint.sh

EXPOSE 22/tcp
ENTRYPOINT ["/entrypoint.sh"]
