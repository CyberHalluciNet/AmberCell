# AmberCell Telnet hi-cell provider: netkit-telnetd (alternate)
# Provider id: netkit-telnetd — select with AMBER_TELNET_PROVIDER=netkit-telnetd
#
# Classic netkit-telnetd 0.17 built from Debian orig tarball (pinned checksum).
# Runtime: Debian bookworm-slim + ucspi-tcp tcpserver (IPv4-only).
FROM debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS build

ENV DEBIAN_FRONTEND=noninteractive
# netkit-telnet_0.17.orig.tar.gz (Debian snapshot / pool)
ARG NETKIT_URL=https://snapshot.debian.org/archive/debian/20210511T024316Z/pool/main/n/netkit-telnet/netkit-telnet_0.17.orig.tar.gz
ARG NETKIT_SHA256=9c80d5c7838361a328fb6b60016d503def9ce53ad3c589f3b08ff71a2bb88e00

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         build-essential \
         ca-certificates \
         curl \
         libncurses-dev \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL "$NETKIT_URL" -o /tmp/netkit.tgz \
    && echo "$NETKIT_SHA256  /tmp/netkit.tgz" | sha256sum -c - \
    && mkdir -p /src \
    && tar -xzf /tmp/netkit.tgz -C /src \
    && cd /src/netkit-telnet-0.17 \
    && ./configure \
    && make -C telnetd \
    && install -m 755 telnetd/telnetd /usr/local/sbin/netkit-telnetd

FROM debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         ucspi-tcp \
         busybox \
         libncurses6 \
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

COPY --from=build /usr/local/sbin/netkit-telnetd /usr/sbin/netkit-telnetd
COPY amber-login.sh /usr/sbin/amber-login
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /usr/sbin/netkit-telnetd /usr/sbin/amber-login /entrypoint.sh

EXPOSE 23/tcp
ENTRYPOINT ["/entrypoint.sh"]
