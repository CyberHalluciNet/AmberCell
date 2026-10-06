# AmberCell Telnet hi-cell provider: inetutils-telnetd (alternate)
# Provider id: inetutils-telnetd — select with AMBER_TELNET_PROVIDER=inetutils-telnetd
#
# GNU inetutils telnetd (Debian) behind ucspi-tcp tcpserver for IPv4-only listen.
# Base pinned by multi-arch index digest.
FROM debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         inetutils-telnetd \
         ucspi-tcp \
         busybox \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /jail/bin /jail/etc /jail/tmp /jail/home /jail/var \
    && cp /bin/busybox /jail/bin/busybox \
    && ln -sf busybox /jail/bin/sh \
    && printf '%s\n' \
        'AmberCell telnet lab jail (disposable).' \
        'bin  etc  home  tmp  var' > /jail/README.txt \
    && printf '%s\n' \
        '# Minimal fake root for telnet sessions.' \
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
