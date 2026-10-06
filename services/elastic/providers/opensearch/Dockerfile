# AmberCell Elastic hi-cell — OpenSearch (Apache-2.0)
# Provider id: opensearch — AMBER_ELASTIC_PROVIDER=opensearch
FROM opensearchproject/opensearch:2.17.1

USER root
COPY entrypoint-wrap.sh /entrypoint-wrap.sh
RUN chmod 755 /entrypoint-wrap.sh
USER opensearch

ENV discovery.type=single-node
ENV DISABLE_SECURITY_PLUGIN=true
ENV OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m
ENV plugins.security.disabled=true

ENTRYPOINT ["/entrypoint-wrap.sh"]
EXPOSE 9200/tcp
