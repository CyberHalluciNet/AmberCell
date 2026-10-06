# AmberCell SSH hi-cell provider: openssh (default)
# Provider id: openssh — select with AMBER_SSH_PROVIDER=openssh
FROM alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache openssh openssh-sftp-server busybox-extras \
    && mkdir -p /var/empty/sshd /run/sshd /jail/home /jail/tmp /mnt/uploads \
    && ssh-keygen -A \
    && adduser -D -h /home/admin -s /usr/local/bin/amber-shell.sh admin \
    && adduser -D -h /home/support -s /usr/local/bin/amber-shell.sh support \
    && adduser -D -h /home/lure -s /usr/local/bin/amber-shell.sh lure \
    && echo 'admin:admin123' | chpasswd \
    && echo 'support:support' | chpasswd \
    && echo 'lure:lure' | chpasswd \
    && chown -R admin:admin /home/admin /mnt/uploads \
    && chmod 755 /mnt/uploads

COPY sshd_config /etc/ssh/sshd_config
COPY amber-shell.sh /usr/local/bin/amber-shell.sh
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /usr/local/bin/amber-shell.sh /entrypoint.sh

EXPOSE 22/tcp
ENTRYPOINT ["/entrypoint.sh"]
