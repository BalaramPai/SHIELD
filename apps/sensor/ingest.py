# File: apps/sensor/ingest.py
# Purpose: Sends structured network events from the sensor to Logstash.

import json
import socket
from dataclasses import asdict

from apps.sensor.config import LOGSTASH_HOST, LOGSTASH_PORT
from packages.schemas.events import NetworkEvent


def send_event(event: NetworkEvent) -> None:
    payload = json.dumps(
        {
            **asdict(event),
            "timestamp": event.timestamp.isoformat(),
        }
    ) + "\n"

    with socket.create_connection(
        (LOGSTASH_HOST, LOGSTASH_PORT),
        timeout=5,
    ) as connection:
        connection.sendall(payload.encode("utf-8"))