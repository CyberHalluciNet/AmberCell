# AmberCell Telnet hi-cell provider: busybox-telnetd (default)
# Provider id: busybox-telnetd — select with AMBER_TELNET_PROVIDER=busybox-telnetd
#
# Uses Alpine busybox-extras telnetd (/usr/sbin/telnetd → busybox-extras).
# Pinned by digest (same Alpine index as vsftpd). Re-verify in CI on bump.
FROM alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache busybox-extras \
    && mkdir -p /jail/bin /jail/etc /jail/tmp /jail/home /jail/var \
    && cp /bin/busybox /jail/bin/busybox \
    && ln -sf busybox /jail/bin/sh \
    && printf '%s\n' \
        'AmberCell telnet lab jail (disposable).' \
        'bin  etc  home  tmp  var' > /jail/README.txt \
    && printf '%s\n' \
        '# Minimal fake root for telnet sessions (Stage-1 scaffold).' \
        'export PS1="ambercell# "' \
        'export PATH=/bin:/usr/bin' \
        'cd / || true' \
        'echo "Type exit to close the session."' \
        'exec /bin/sh -i' > /jail/.profile

COPY amber-login.sh /usr/sbin/amber-login
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /usr/sbin/amber-login /entrypoint.sh

EXPOSE 23/tcp

ENTRYPOINT ["/entrypoint.sh"]
