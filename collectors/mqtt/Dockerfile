FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/mqtt-collector
COPY collectors/mqtt/mqtt_collector ./mqtt_collector

ENV AMBER_MQTT_PROVIDER=mosquitto
ENV AMBER_MQTT_CELL_IP=172.30.70.10

ENTRYPOINT ["python3", "-m", "mqtt_collector.main"]
