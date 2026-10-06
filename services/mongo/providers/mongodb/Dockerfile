FROM mongo:7.0

COPY init/ /docker-entrypoint-initdb.d/
COPY entrypoint-wrap.sh /entrypoint-wrap.sh
RUN chmod 755 /entrypoint-wrap.sh

ENTRYPOINT ["/entrypoint-wrap.sh"]
