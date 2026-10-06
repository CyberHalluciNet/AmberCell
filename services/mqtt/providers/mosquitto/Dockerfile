# AmberCell MQTT hi-cell — Mosquitto anonymous (default)
# Provider id: mosquitto — select with AMBER_MQTT_PROVIDER=mosquitto
FROM eclipse-mosquitto:2.0.20

COPY mosquitto.conf /mosquitto/config/mosquitto.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 1883/tcp
ENTRYPOINT ["/entrypoint.sh"]
