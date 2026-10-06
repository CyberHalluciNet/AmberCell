FROM docker.elastic.co/elasticsearch/elasticsearch:8.15.3

COPY entrypoint-wrap.sh /entrypoint-wrap.sh
USER root
RUN chmod 755 /entrypoint-wrap.sh
USER elasticsearch

ENTRYPOINT ["/entrypoint-wrap.sh"]
