# AmberCell SSH hi-cell provider: tinyssh (pubkey-only)
# Provider id: tinyssh — AMBER_SSH_PROVIDER=tinyssh
FROM alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache tinyssh busybox-extras openssh-keygen \
    && mkdir -p /etc/tinyssh/sshkeydir /mnt/uploads /home/admin/.ssh /home/support/.ssh /home/lure/.ssh \
    && tinysshd-makekey /etc/tinyssh/sshkeydir \
    && adduser -D -h /home/admin -s /usr/local/bin/amber-shell.sh admin \
    && adduser -D -h /home/support -s /usr/local/bin/amber-shell.sh support \
    && adduser -D -h /home/lure -s /usr/local/bin/amber-shell.sh lure \
    && ssh-keygen -t ed25519 -N '' -f /tmp/lure_ed25519 \
    && cat /tmp/lure_ed25519.pub >/home/admin/.ssh/authorized_keys \
    && cat /tmp/lure_ed25519.pub >/home/support/.ssh/authorized_keys \
    && cat /tmp/lure_ed25519.pub >/home/lure/.ssh/authorized_keys \
    && cp /tmp/lure_ed25519 /mnt/uploads/lab_lure_ed25519 \
    && cp /tmp/lure_ed25519.pub /mnt/uploads/lab_lure_ed25519.pub \
    && chown -R admin:admin /home/admin /mnt/uploads \
    && chown -R support:support /home/support \
    && chown -R lure:lure /home/lure \
    && chmod 700 /home/admin/.ssh /home/support/.ssh /home/lure/.ssh \
    && chmod 600 /home/*/.ssh/authorized_keys \
    && rm -f /tmp/lure_ed25519 /tmp/lure_ed25519.pub

COPY amber-shell.sh /usr/local/bin/amber-shell.sh
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /usr/local/bin/amber-shell.sh /entrypoint.sh

EXPOSE 22/tcp
ENTRYPOINT ["/entrypoint.sh"]
