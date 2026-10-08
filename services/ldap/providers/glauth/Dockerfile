# AmberCell LDAP hi-cell provider: GLAuth (alternate)
# Provider id: glauth — select with AMBER_LDAP_PROVIDER=glauth
FROM glauth/glauth:v2.2.0

COPY config.toml /app/config/config.toml

EXPOSE 389/tcp
CMD ["/bin/glauth", "-c", "/app/config/config.toml"]
