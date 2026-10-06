# AmberCell Mongo hi-cell — FerretDB (Apache-2.0 MongoDB wire protocol)
# Provider id: ferretdb — AMBER_MONGO_PROVIDER=ferretdb
FROM ghcr.io/ferretdb/ferretdb:1.24.0

USER root
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
ENV FERRETDB_HANDLER=sqlite
ENV FERRETDB_SQLITE_URL=file:/state/
EXPOSE 27017/tcp
ENTRYPOINT ["/entrypoint.sh"]
