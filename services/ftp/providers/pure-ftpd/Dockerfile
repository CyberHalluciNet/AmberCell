# AmberCell FTP hi-cell provider: pure-ftpd (alternate)
# Provider id: pure-ftpd — select with AMBER_FTP_PROVIDER=pure-ftpd
#
# Pinned by digest (same Alpine index as vsftpd). Re-verify in CI on bump.
# Pure-FTPd has no PassiveOnly flag; we rebuild 1.0.51 with Active Mode patched off
# so PASV bind stays on INADDR_ANY (a control-channel proxy would force 127.0.0.1).
FROM alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

COPY disable-active-mode.patch /tmp/disable-active-mode.patch
COPY pure-ftpd.flags.template /etc/pure-ftpd.flags.template
COPY entrypoint.sh /entrypoint.sh

RUN apk add --no-cache shadow openssl \
    && apk add --no-cache --virtual .build-deps \
        build-base curl openssl-dev \
    && cd /tmp \
    && PURE_FTPD_COMMIT=c1efeb7be8ca3ef6b7660edbeb2d263de30e9a9e \
    && PURE_FTPD_SHA256=e68a2a5bd0989eecdd6792351972d5bf9f5d7883393e25ebd7aa68d3a80acba0 \
    && curl -fsSL -o pure-ftpd.tar.gz \
         "https://github.com/jedisct1/pure-ftpd/archive/${PURE_FTPD_COMMIT}.tar.gz" \
    && echo "${PURE_FTPD_SHA256}  pure-ftpd.tar.gz" | sha256sum -c - \
    && tar -xzf pure-ftpd.tar.gz \
    && cd "pure-ftpd-${PURE_FTPD_COMMIT}" \
    && patch -p1 < /tmp/disable-active-mode.patch \
    && ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --without-pam \
        --with-puredb \
        --with-shadow \
        --without-inetd \
        --without-capabilities \
    && make -j"$(nproc)" \
    && make install-strip \
    && cd / \
    && rm -rf "/tmp/pure-ftpd-${PURE_FTPD_COMMIT}" /tmp/pure-ftpd.tar.gz /tmp/disable-active-mode.patch \
    && apk del .build-deps \
    && (getent passwd ftp >/dev/null || adduser -D -u 21 -h /var/ftp -s /sbin/nologin ftp) \
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
    && chown -R upload:upload /home/upload/ftp \
    && chmod 755 /entrypoint.sh

# Compose cap_drop ALL and cap_add the minimal set for bind/chroot/setuid
# (NET_BIND_SERVICE, CHOWN, SETUID, SETGID, SYS_CHROOT, DAC_OVERRIDE, FOWNER).
# No privileged mode and no docker.sock.
EXPOSE 21/tcp 30000-30049/tcp

ENTRYPOINT ["/entrypoint.sh"]
