# AmberCell POP3 hi-cell provider: courier (alternate)
# Provider id: courier — select with AMBER_POP3_PROVIDER=courier
FROM debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         courier-pop \
         courier-authdaemon \
         courier-authlib-userdb \
    && rm -rf /var/lib/apt/lists/* \
    && for pair in exec:exec123 finance:finance123 hr:hr123 it:it123 canary:canary123; do \
         u="${pair%%:*}"; p="${pair#*:}"; \
         useradd -m -s /usr/sbin/nologin "$u"; \
         echo "$u:$p" | chpasswd; \
         maildirmake "/home/$u/Maildir"; \
         chown -R "$u:$u" "/home/$u"; \
       done \
    && sed -i 's/^authmodulelist=.*/authmodulelist="authpam"/' /etc/courier/authdaemonrc \
    && mkdir -p /run/courier/authdaemon

COPY entrypoint.sh /entrypoint.sh
COPY seeds/ /opt/amber-seeds/
RUN chmod 755 /entrypoint.sh

EXPOSE 110/tcp
ENTRYPOINT ["/entrypoint.sh"]
