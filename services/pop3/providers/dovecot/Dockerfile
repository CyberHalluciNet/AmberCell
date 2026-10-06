# AmberCell POP3 hi-cell provider: dovecot (default)
FROM alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache dovecot dovecot-pop3d \
    && for pair in exec:exec123 finance:finance123 hr:hr123 it:it123 canary:canary123; do \
         u="${pair%%:*}"; p="${pair#*:}"; \
         adduser -D -G mail -h "/home/$u" -s /sbin/nologin "$u"; \
         echo "$u:$p" | chpasswd; \
         mkdir -p "/home/$u/mail"; \
         chown -R "$u:mail" "/home/$u"; \
       done

COPY dovecot.conf /etc/dovecot/dovecot.conf
COPY users /etc/dovecot/users
COPY entrypoint.sh /entrypoint.sh
COPY seeds/ /opt/amber-seeds/

RUN chmod 755 /entrypoint.sh

EXPOSE 110/tcp
ENTRYPOINT ["/entrypoint.sh"]
