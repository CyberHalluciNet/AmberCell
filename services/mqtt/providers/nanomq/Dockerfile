# AmberCell MQTT hi-cell — NanoMQ
# Provider id: nanomq — AMBER_MQTT_PROVIDER=nanomq
FROM emqx/nanomq:0.21.8-slim

COPY entrypoint.sh /entrypoint.sh
USER root
RUN chmod 755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
EXPOSE 1883/tcp
