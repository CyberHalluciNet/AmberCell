# AmberCell LDAP hi-cell provider: OpenLDAP slapd (default)
# Provider id: openldap — select with AMBER_LDAP_PROVIDER=openldap
FROM debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

RUN apt-get update -qq && apt-get install -y --no-install-recommends slapd ldap-utils \
    && rm -rf /var/lib/apt/lists/*

COPY slapd.conf /etc/ldap/slapd.conf
COPY seed/ /etc/ldap/seed/
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh && chmod 644 /etc/ldap/slapd.conf /etc/ldap/seed/*

EXPOSE 389/tcp
ENTRYPOINT ["/entrypoint.sh"]
