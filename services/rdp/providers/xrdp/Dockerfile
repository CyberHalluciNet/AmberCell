# AmberCell RDP hi-cell provider: xrdp (default)
# Provider id: xrdp — select with AMBER_RDP_PROVIDER=xrdp
#
# Evidence scope: RDP negotiation, TLS, and probe patterns. Credentials ride
# inside TLS/NLA by design (no MITM on the attacker path) — credential capture
# is NOT claimed for this cell; scan/CVE-probe detection is.
FROM debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

RUN apt-get update -qq && apt-get install -y --no-install-recommends xrdp xorgxrdp \
    && rm -rf /var/lib/apt/lists/* \
    && xrdp-keygen xrdp auto 2048 /etc/xrdp/rsakeys.ini \
    && mkdir -p /var/run/xrdp

COPY xrdp.ini /etc/xrdp/xrdp.ini
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh && chmod 644 /etc/xrdp/xrdp.ini

EXPOSE 3389/tcp
ENTRYPOINT ["/entrypoint.sh"]
