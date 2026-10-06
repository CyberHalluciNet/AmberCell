# AmberCell MQTT hi-cell — EMQX (Apache-2.0 open source)
# Provider id: emqx — AMBER_MQTT_PROVIDER=emqx
FROM emqx/emqx:5.8.3

COPY entrypoint.sh /entrypoint.sh
USER root
RUN chmod 755 /entrypoint.sh
ENV EMQX_ALLOW_ANONYMOUS=true
ENV EMQX_DASHBOARD__DEFAULT_USERNAME=admin
ENV EMQX_DASHBOARD__DEFAULT_PASSWORD=ambercell
ENTRYPOINT ["/entrypoint.sh"]
EXPOSE 1883/tcp
