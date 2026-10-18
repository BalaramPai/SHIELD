# File: packages/schemas/events.py
# Purpose: Defines the shared structure for raw network events produced by the sensor.

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class NetworkEvent:
    event_id: str
    timestamp: datetime
    sensor_id: str
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    protocol_num: int
    packet_size: int
    flags: str