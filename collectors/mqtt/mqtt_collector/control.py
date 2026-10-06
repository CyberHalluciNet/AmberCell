"""Mosquitto log + MQTT keyword parse."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_CONN = re.compile(
    r"New (?:connection from|client connected from)\s+(?P<ip>[\d.]+):(?P<port>\d+)(?:\s+as\s+(?P<client>\S+))?",
    re.I,
)
_PUB = re.compile(r"PUBLISH\s+(?:received|dropped)?.*?['\"]?(?P<topic>telemetry/[^'\"\\s]+|sensors/[^'\"\\s]+|[^'\"\\s]+)", re.I)
_SUB = re.compile(r"Received SUBSCRIBE from (?P<client>\S+).*?(?P<topic>telemetry/#|sensors/#|\S+)", re.I)


@dataclass
class MqttSession:
    session_id: str
    client_id: str | None = None
    src_ip: str = "0.0.0.0"
    src_port: int = 0
    topics: list[str] = field(default_factory=list)


@dataclass
class ParsedEvent:
    name: str
    session: MqttSession
    details: dict


class MqttControlParser:
    def __init__(self) -> None:
        self._session = MqttSession(session_id="mqtt-default")

    def bind(self, session: MqttSession) -> None:
        self._session = session

    def handle_line(self, line: str) -> list[ParsedEvent]:
        out: list[ParsedEvent] = []
        text = line.strip()
        if not text:
            return out

        cm = _CONN.search(text)
        if cm:
            self._session.src_ip = cm.group("ip")
            self._session.src_port = int(cm.group("port"))
            if cm.group("client"):
                self._session.client_id = cm.group("client")
            out.append(
                ParsedEvent(
                    "mqtt.connect",
                    self._session,
                    {
                        "client_id": self._session.client_id,
                        "src_ip": self._session.src_ip,
                        "src_port": self._session.src_port,
                    },
                )
            )

        sm = _SUB.search(text)
        if sm:
            topic = sm.group("topic")
            self._session.topics.append(topic)
            out.append(
                ParsedEvent(
                    "mqtt.subscribe",
                    self._session,
                    {"client_id": sm.group("client"), "topic": topic},
                )
            )

        pm = _PUB.search(text)
        if pm:
            topic = pm.group("topic")
            out.append(
                ParsedEvent(
                    "mqtt.publish",
                    self._session,
                    {"topic": topic, "line": text[:240]},
                )
            )
        return out
