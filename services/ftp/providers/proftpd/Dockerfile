# AmberCell FTP hi-cell provider: proftpd (alternate)
# Provider id: proftpd — select with AMBER_FTP_PROVIDER=proftpd
#
# Pinned by digest (same Alpine index as vsftpd). Re-verify in CI on bump.
FROM alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache proftpd shadow \
    && usermod -d /var/ftp ftp \
    && adduser -D -h /home/ftpuser -s /sbin/nologin ftpuser \
    && echo 'ftpuser:ftpuser' | chpasswd \
    && adduser -D -h /home/upload -s /sbin/nologin upload \
    && echo 'upload:upload' | chpasswd \
    && mkdir -p /var/ftp/pub/docs /var/ftp/pub/samples /var/ftp/incoming \
        /home/ftpuser/ftp/files /home/upload/ftp/files \
    && printf '%s\n' 'AmberCell FTP seed tree (anonymous /var/ftp/pub).' > /var/ftp/pub/README.txt \
    && printf '%s\n' 'Stage-1 sample document.' > /var/ftp/pub/docs/about.txt \
    && printf 'name,role\nftp,seed\n' > /var/ftp/pub/samples/data.csv \
    && printf '%s\n' 'Writable upload landing zone (anonymous + local).' > /var/ftp/incoming/README.upload \
    && printf '%s\n' 'ftpuser home listing smoke.' > /home/ftpuser/ftp/files/README.txt \
    && printf '%s\n' 'upload weak account home.' > /home/upload/ftp/files/welcome.txt \
    && chown root:root /var/ftp /var/ftp/pub /var/ftp/pub/docs /var/ftp/pub/samples \
    && chmod 555 /var/ftp /var/ftp/pub /var/ftp/pub/docs /var/ftp/pub/samples \
    && chown ftp:ftp /var/ftp/pub/README.txt /var/ftp/pub/docs/about.txt /var/ftp/pub/samples/data.csv \
    && chmod 444 /var/ftp/pub/README.txt /var/ftp/pub/docs/about.txt /var/ftp/pub/samples/data.csv \
    && chown ftp:ftp /var/ftp/incoming \
    && chmod 1733 /var/ftp/incoming \
    && chown root:root /home/ftpuser /home/upload \
    && chmod 555 /home/ftpuser /home/upload \
    && chown -R ftpuser:ftpuser /home/ftpuser/ftp \
    && chown -R upload:upload /home/upload/ftp

COPY proftpd.conf.template /etc/proftpd/proftpd.conf.template
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

# Compose cap_drop ALL and cap_add the minimal set for bind/chroot/setuid
# (NET_BIND_SERVICE, CHOWN, SETUID, SETGID, SYS_CHROOT, DAC_OVERRIDE, FOWNER).
# No privileged mode and no docker.sock.
EXPOSE 21/tcp 30000-30049/tcp

ENTRYPOINT ["/entrypoint.sh"]
