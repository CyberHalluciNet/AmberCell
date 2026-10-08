# AmberCell VNC hi-cell provider: TigerVNC Xvnc (default)
# Provider id: tigervnc — select with AMBER_VNC_PROVIDER=tigervnc
#
# Debian bookworm ships no vncpasswd, so the persona is an OPEN VNC
# (SecurityTypes None) — a real, common misconfiguration exposure pattern.
# RFB handshake/banner capture is the evidence value.
FROM debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

RUN apt-get update -qq && apt-get install -y --no-install-recommends tigervnc-standalone-server tigervnc-common \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 5900/tcp
ENTRYPOINT ["/entrypoint.sh"]
