# AmberCell SMTP hi-cell provider: exim (alternate)
# Provider id: exim — select with AMBER_SMTP_PROVIDER=exim
FROM alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache exim \
    && mkdir -p /etc/exim /var/spool/exim /var/mail \
    && for u in hr finance admin support; do \
         adduser -D -h "/home/$u" -s /sbin/nologin "$u"; \
         touch "/var/mail/$u"; \
         chown "$u:mail" "/var/mail/$u"; \
       done

COPY exim.conf /etc/exim/exim.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 25/tcp
ENTRYPOINT ["/entrypoint.sh"]
